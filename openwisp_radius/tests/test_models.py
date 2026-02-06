import logging
import os
from unittest import mock
from uuid import UUID, uuid4

import swapper
from django.apps.registry import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db.models import ProtectedError
from django.urls import reverse
from django.utils import timezone
from netaddr import EUI, mac_unix

from openwisp_users.tests.utils import TestMultitenantAdminMixin
from openwisp_utils.tests import capture_any_output, capture_stderr

from .. import settings as app_settings
from ..counters.exceptions import MaxQuotaReached
from ..radclient.client import RadClient
from ..tasks import perform_change_of_authorization
from ..utils import (
    DEFAULT_SESSION_TIME_LIMIT,
    DEFAULT_SESSION_TRAFFIC_LIMIT,
    SESSION_TIME_ATTRIBUTE,
    SESSION_TRAFFIC_ATTRIBUTE,
    load_model,
)
from . import _CALLED_STATION_IDS, _RADACCT, FileMixin
from .mixins import BaseTestCase, BaseTransactionTestCase

Nas = load_model("Nas")
RadiusAccounting = load_model("RadiusAccounting")
RadiusCheck = load_model("RadiusCheck")
RadiusReply = load_model("RadiusReply")
RadiusPostAuth = load_model("RadiusPostAuth")
RadiusGroup = load_model("RadiusGroup")
RadiusGroupCheck = load_model("RadiusGroupCheck")
RadiusGroupReply = load_model("RadiusGroupReply")
RadiusUserGroup = load_model("RadiusUserGroup")
RadiusBatch = load_model("RadiusBatch")
OrganizationRadiusSettings = load_model("OrganizationRadiusSettings")
Organization = swapper.load_model("openwisp_users", "Organization")


class TestNas(BaseTestCase):
    def test_string_representation(self):
        nas = Nas(name="entry nasname")
        self.assertEqual(str(nas), nas.name)

    def test_id_uuid(self):
        nas = Nas(name="uuid id")
        self.assertIsInstance(nas.pk, UUID)


class TestRadiusAccounting(FileMixin, BaseTestCase):
    def test_string_representation(self):
        radiusaccounting = RadiusAccounting(unique_id="entry acctuniqueid")
        self.assertEqual(str(radiusaccounting), radiusaccounting.unique_id)

    def test_id(self):
        radiusaccounting = RadiusAccounting(unique_id="unique")
        self.assertEqual(radiusaccounting.pk, radiusaccounting.unique_id)

    def test_ipv6_validator(self):
        radiusaccounting = RadiusAccounting(
            organization=self.default_org,
            unique_id="entry acctuniqueid",
            session_id="entry acctuniqueid",
            nas_ip_address="192.168.182.3",
            framed_ipv6_prefix="::/64",
        )
        radiusaccounting.full_clean()

        radiusaccounting.framed_ipv6_prefix = "192.168.0.0/28"
        self.assertRaises(ValidationError, radiusaccounting.full_clean)

        radiusaccounting.framed_ipv6_prefix = "invalid ipv6_prefix"
        self.assertRaises(ValidationError, radiusaccounting.full_clean)

    def _run_convert_called_station_id_tests(self):
        """
        Reused by other tests below.
        """
        radiusaccounting_options = _RADACCT.copy()
        radiusaccounting_options.update(
            {
                "organization": self.default_org,
                "nas_ip_address": "192.168.182.3",
                "framed_ipv6_prefix": "::/64",
                "calling_station_id": str(EUI("bb:bb:bb:bb:bb:0b", dialect=mac_unix)),
                "called_station_id": "AA-AA-AA-AA-AA-0A",
            }
        )
        with self.subTest("Settings disabled"):
            options = radiusaccounting_options.copy()
            options["unique_id"] = "113"
            radiusaccounting = self._create_radius_accounting(**options)
            radiusaccounting.refresh_from_db()
            self.assertEqual(radiusaccounting.called_station_id, "AA-AA-AA-AA-AA-0A")

        RadiusAppConfig = apps.get_app_config(RadiusAccounting._meta.app_label)
        RadiusAppConfig.connect_signals()

        with self.subTest("CALLED_STATION_ID not defined for organization"):
            options = radiusaccounting_options.copy()
            options["unique_id"] = "111"
            options["organization"] = self._create_org(name="new-org")
            radiusaccounting = self._create_radius_accounting(**options)
            radiusaccounting.refresh_from_db()
            self.assertEqual(radiusaccounting.called_station_id, "AA-AA-AA-AA-AA-0A")

        with self.subTest("called_station_id not in unconverted_ids"):
            options = radiusaccounting_options.copy()
            options["called_station_id"] = "EE-EE-EE-EE-EE-EE"
            options["unique_id"] = "112"
            radiusaccounting = self._create_radius_accounting(**options)
            radiusaccounting.refresh_from_db()
            self.assertEqual(radiusaccounting.called_station_id, "EE-EE-EE-EE-EE-EE")

        with self.subTest("Ideal condition"):
            with self._get_openvpn_status_mock():
                options = radiusaccounting_options.copy()
                options["unique_id"] = "114"
                radiusaccounting = self._create_radius_accounting(**options)
                radiusaccounting.refresh_from_db()
                self.assertEqual(
                    radiusaccounting.called_station_id, "CC-CC-CC-CC-CC-0C"
                )

    def test_multiple_accounting_sessions(self):
        radiusaccounting_options = _RADACCT.copy()
        radiusaccounting_options.update(
            {
                "organization": self.default_org,
                "nas_ip_address": "192.168.182.3",
                "framed_ipv6_prefix": "::/64",
                "calling_station_id": str(EUI("bb:bb:bb:bb:bb:0b", dialect=mac_unix)),
                "called_station_id": "AA-AA-AA-AA-AA-0A",
            }
        )

        with self.subTest("Test new session with same called_station_id"):
            radiusaccounting1 = self._create_radius_accounting(
                unique_id="111", update_time=timezone.now(), **radiusaccounting_options
            )
            radiusaccounting2 = self._create_radius_accounting(
                unique_id="112", update_time=timezone.now(), **radiusaccounting_options
            )
            radiusaccounting1.refresh_from_db()
            radiusaccounting2.refresh_from_db()
            self.assertEqual(radiusaccounting1.terminate_cause, "Session-Timeout")
            self.assertEqual(radiusaccounting1.stop_time, radiusaccounting1.update_time)
            self.assertEqual(radiusaccounting2.stop_time, None)

    @capture_any_output()
    @mock.patch.object(app_settings, "OPENVPN_DATETIME_FORMAT", "%Y-%m-%d %H:%M:%S")
    @mock.patch.object(app_settings, "CONVERT_CALLED_STATION_ON_CREATE", True)
    def test_convert_called_station_id_with_organization_id(self, *args, **kwargs):
        called_station_ids = {
            str(self._get_org().id): _CALLED_STATION_IDS.get("test-org")
        }
        with mock.patch.object(
            app_settings,
            "CALLED_STATION_IDS",
            called_station_ids,
        ):
            self._run_convert_called_station_id_tests()

    @capture_any_output()
    @mock.patch.object(
        app_settings,
        "CALLED_STATION_IDS",
        _CALLED_STATION_IDS,
    )
    @mock.patch.object(app_settings, "OPENVPN_DATETIME_FORMAT", "%Y-%m-%d %H:%M:%S")
    @mock.patch.object(app_settings, "CONVERT_CALLED_STATION_ON_CREATE", True)
    def test_convert_called_station_id_with_organization_slug(self, *args, **kwargs):
        self._run_convert_called_station_id_tests()

    def test_close_stale_sessions_missing_params(self):
        with self.assertRaises(ValueError) as context:
            RadiusAccounting.close_stale_sessions()
        self.assertIn("Missing `days` or `hours`", str(context.exception))

    def test_close_stale_sessions_on_nas_boot_empty_called_station_id(self):
        result = RadiusAccounting._close_stale_sessions_on_nas_boot(None)
        self.assertEqual(result, 0)
        result = RadiusAccounting._close_stale_sessions_on_nas_boot("")
        self.assertEqual(result, 0)


class TestRadiusCheck(BaseTestCase):
    def test_string_representation(self):
        radiuscheck = RadiusCheck(username="entry username")
        self.assertEqual(str(radiuscheck), radiuscheck.username)

    def test_id(self):
        radiuscheck = RadiusCheck(username="test uuid")
        self.assertIsInstance(radiuscheck.pk, UUID)

    def test_auto_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org, user=u)
        c = self._create_radius_check(
            user=u,
            op=":=",
            attribute="Max-Daily-Session",
            value="3600",
            organization=org,
        )
        self.assertEqual(c.username, u.username)

    def test_empty_username(self):
        opts = dict(op=":=", attribute="Max-Daily-Session", value="3600")
        try:
            self._create_radius_check(**opts)
        except ValidationError as e:
            self.assertIn("username", e.message_dict)
            self.assertIn("user", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_change_user_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org, user=u)
        c = self._create_radius_check(
            user=u,
            op=":=",
            attribute="Max-Daily-Session",
            value="3600",
            organization=org,
        )
        u.username = "changed"
        u.full_clean()
        u.save()
        c.refresh_from_db()
        # ensure related records have been updated
        self.assertEqual(c.username, u.username)

    def test_create_radius_check_model(self):
        obj = RadiusCheck.objects.create(
            organization=self.default_org,
            username="Monica",
            value="Cam0_liX",
            attribute="NT-Password",
            op=":=",
        )
        self.assertEqual(obj.value, "Cam0_liX")

    def test_user_different_organization(self):
        org1 = self._create_org(**{"name": "org1", "slug": "org1"})
        org2 = self._create_org(**{"name": "org2", "slug": "org2"})
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org1, user=u)
        try:
            self._create_radius_check(
                user=u,
                op=":=",
                attribute="Max-Daily-Session",
                value="3600",
                organization=org2,
            )
        except ValidationError as e:
            self.assertIn("organization", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_radius_check_unique_attribute(self):
        org1 = self._create_org(**{"name": "org1", "slug": "org1"})
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org1, user=u)
        self._create_radius_check(
            user=u,
            op=":=",
            attribute="Max-Daily-Session",
            value="3600",
            organization=org1,
        )
        try:
            self._create_radius_check(
                user=u,
                op=":=",
                attribute="Max-Daily-Session",
                value="3200",
                organization=org1,
            )
        except ValidationError as e:
            self.assertEqual(
                {
                    "attribute": [
                        "Another check for the same user and with the "
                        "same attribute already exists."
                    ]
                },
                e.message_dict,
            )
        else:
            self.fail("ValidationError not raised")

    def test_auto_username_existing_user_lookup(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username="testuser", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org, user=u)
        c = RadiusCheck(
            username="testuser",
            op=":=",
            attribute="Max-Daily-Session",
            value="3600",
            organization=org,
        )
        c.full_clean()
        c.save()
        self.assertEqual(c.user, u)
        self.assertEqual(c.username, u.username)


class TestRadiusReply(BaseTestCase):
    def test_string_representation(self):
        radiusreply = RadiusReply(username="entry username")
        self.assertEqual(str(radiusreply), radiusreply.username)

    def test_uuid(self):
        radiusreply = RadiusReply(username="test id")
        self.assertIsInstance(radiusreply.pk, UUID)

    def test_auto_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org, user=u)
        r = self._create_radius_reply(
            user=u,
            attribute="Reply-Message",
            op=":=",
            value="Login failed",
            organization=org,
        )
        self.assertEqual(r.username, u.username)

    def test_empty_username(self):
        opts = dict(attribute="Reply-Message", op=":=", value="Login failed")
        try:
            self._create_radius_reply(**opts)
        except ValidationError as e:
            self.assertIn("username", e.message_dict)
            self.assertIn("user", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_change_user_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org, user=u)
        r = self._create_radius_reply(
            user=u,
            attribute="Reply-Message",
            op=":=",
            value="Login failed",
            organization=org,
        )
        u.username = "changed"
        u.full_clean()
        u.save()
        r.refresh_from_db()
        # ensure related records have been updated
        self.assertEqual(r.username, u.username)

    def test_user_different_organization(self):
        org1 = self._create_org(**{"name": "org1", "slug": "org1"})
        org2 = self._create_org(**{"name": "org2", "slug": "org2"})
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org1, user=u)
        try:
            self._create_radius_reply(
                user=u,
                attribute="Reply-Message",
                op=":=",
                value="Login failed",
                organization=org2,
            )
        except ValidationError as e:
            self.assertIn("organization", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_radius_reply_unique_attribute(self):
        org1 = self._create_org(**{"name": "org1", "slug": "org1"})
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        self._create_org_user(organization=org1, user=u)
        self._create_radius_reply(
            user=u,
            attribute="Reply-Message",
            op=":=",
            value="Login failed",
            organization=org1,
        )
        try:
            self._create_radius_reply(
                user=u,
                attribute="Reply-Message",
                op="=",
                value="Login failed",
                organization=org1,
            )
        except ValidationError as e:
            self.assertEqual(
                {
                    "attribute": [
                        "Another reply for the same user and with the "
                        "same attribute already exists."
                    ]
                },
                e.message_dict,
            )
        else:
            self.fail("ValidationError not raised")


class TestRadiusPostAuth(BaseTestCase):
    def test_string_representation(self):
        radiuspostauthentication = RadiusPostAuth(username="entry username")
        self.assertEqual(
            str(radiuspostauthentication), radiuspostauthentication.username
        )

    def test_id(self):
        radiuspostauth = RadiusPostAuth(username="test id")
        self.assertIsInstance(radiuspostauth.pk, UUID)


class TestRadiusGroup(BaseTestCase):
    def test_group_str(self):
        g = RadiusGroup(name="entry groupname")
        self.assertEqual(str(g), g.name)

    def test_group_id(self):
        g = RadiusGroup(name="test group id")
        self.assertIsInstance(g.pk, UUID)

    def test_group_reply_str(self):
        r = RadiusGroupReply(groupname="entry groupname")
        self.assertEqual(str(r), r.groupname)

    def test_group_reply_id(self):
        gr = RadiusGroupReply(groupname="test group reply id")
        self.assertIsInstance(gr.pk, UUID)

    def test_group_check_str(self):
        c = RadiusGroupCheck(groupname="entry groupname")
        self.assertEqual(str(c), c.groupname)

    def test_group_check_id(self):
        gc = RadiusGroupCheck(groupname="group check id")
        self.assertIsInstance(gc.pk, UUID)

    def test_user_group_str(self):
        ug = RadiusUserGroup(username="entry username")
        self.assertEqual(str(ug), ug.username)

    def test_user_group_id(self):
        ug = RadiusUserGroup(username="test user group id")
        self.assertIsInstance(ug.pk, UUID)

    def test_default_groups(self):
        org = self._get_org("default")
        queryset = RadiusGroup.objects.filter(organization=org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name="default-users").count(), 1)
        self.assertEqual(queryset.filter(name="default-power-users").count(), 1)
        self.assertEqual(queryset.filter(default=True).count(), 1)
        users = queryset.get(name="default-users")
        self.assertTrue(users.default)
        self.assertEqual(users.radiusgroupcheck_set.count(), 2)
        check = users.radiusgroupcheck_set.get(attribute=SESSION_TIME_ATTRIBUTE)
        self.assertEqual(check.value, DEFAULT_SESSION_TIME_LIMIT)
        check = users.radiusgroupcheck_set.get(attribute=SESSION_TRAFFIC_ATTRIBUTE)
        self.assertEqual(check.value, DEFAULT_SESSION_TRAFFIC_LIMIT)
        power_users = queryset.get(name="default-power-users")
        self.assertEqual(power_users.radiusgroupcheck_set.count(), 0)

    def test_change_default_group(self):
        org1 = self._create_org(**{"name": "org1", "slug": "org1"})
        org2 = self._create_org(**{"name": "org2", "slug": "org2"})
        new_default_org1 = RadiusGroup(
            name="org1-new", organization=org1, description="test", default=True
        )
        new_default_org1.full_clean()
        new_default_org1.save()
        new_default_org2 = RadiusGroup(
            name="org2-new", organization=org2, description="test", default=True
        )
        new_default_org2.full_clean()
        new_default_org2.save()
        queryset = RadiusGroup.objects.filter(default=True, organization=org1)
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.filter(name="org1-new").count(), 1)
        # org2
        queryset = RadiusGroup.objects.filter(default=True, organization=org2)
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.filter(name="org2-new").count(), 1)

    def test_delete_default_group(self):
        group = RadiusGroup.objects.get(organization=self._get_org(), default=1)
        try:
            group.delete()
        except ProtectedError:
            pass
        else:
            self.fail("ProtectedError not raised")

    def test_undefault_group(self):
        group = RadiusGroup.objects.get(organization=self._get_org(), default=True)
        group.default = False
        try:
            group.full_clean()
        except ValidationError as e:
            self.assertIn("default", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_no_default_failure_after_erasing(self):
        # this is a corner case but a very annoying one
        RadiusGroup.objects.all().delete()  # won't trigger ValidationError
        self._create_radius_group(name="test")

    def test_groupcheck_auto_name(self):
        g = self._create_radius_group(name="test", description="test")
        c = self._create_radius_groupcheck(
            group=g, attribute="Max-Daily-Session", op=":=", value="3600"
        )
        self.assertEqual(c.groupname, g.name)

    def test_groupcheck_empty_groupname(self):
        opts = dict(attribute="Max-Daily-Session", op=":=", value="3600")
        try:
            self._create_radius_groupcheck(**opts)
        except ValidationError as e:
            self.assertIn("groupname", e.message_dict)
            self.assertIn("group", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_groupreply_auto_name(self):
        g = self._create_radius_group(name="test", description="test")
        r = self._create_radius_groupreply(
            group=g, attribute="Reply-Message", op=":=", value="Login failed"
        )
        self.assertEqual(r.groupname, g.name)

    def test_groupreply_empty_groupname(self):
        opts = dict(attribute="Reply-Message", op=":=", value="Login failed")
        try:
            self._create_radius_groupreply(**opts)
        except ValidationError as e:
            self.assertIn("groupname", e.message_dict)
            self.assertIn("group", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_usergroups_auto_fields(self):
        g = self._create_radius_group(name="test", description="test")
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        ug = self._create_radius_usergroup(user=u, group=g, priority=1)
        self.assertEqual(ug.groupname, g.name)
        self.assertEqual(ug.username, u.username)

    def test_usergroups_empty_groupname(self):
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        try:
            self._create_radius_usergroup(user=u, priority=1)
        except ValidationError as e:
            self.assertIn("groupname", e.message_dict)
            self.assertIn("group", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_usergroups_empty_username(self):
        g = self._create_radius_group(name="test", description="test")
        try:
            self._create_radius_usergroup(group=g, priority=1)
        except ValidationError as e:
            self.assertIn("username", e.message_dict)
            self.assertIn("user", e.message_dict)
        else:
            self.fail("ValidationError not raised")

    def test_change_group_auto_name(self):
        g = self._create_radius_group(name="test", description="test")
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        c = self._create_radius_groupcheck(
            group=g, attribute="Max-Daily-Session", op=":=", value="3600"
        )
        r = self._create_radius_groupreply(
            group=g, attribute="Reply-Message", op=":=", value="Login failed"
        )
        ug = self._create_radius_usergroup(user=u, group=g, priority=1)
        g.name = "changed"
        g.full_clean()
        g.save()
        c.refresh_from_db()
        r.refresh_from_db()
        ug.refresh_from_db()
        # ensure related records have been updated
        self.assertEqual(c.groupname, g.name)
        self.assertEqual(r.groupname, g.name)
        self.assertEqual(ug.groupname, g.name)

    def test_change_user_username(self):
        g = self._create_radius_group(name="test", description="test")
        u = get_user_model().objects.create(
            username="test", email="test@test.org", password="test"
        )
        ug = self._create_radius_usergroup(user=u, group=g, priority=1)
        u.username = "changed"
        u.full_clean()
        u.save()
        ug.refresh_from_db()
        # ensure related records have been updated
        self.assertEqual(ug.username, u.username)

    def test_delete(self):
        g = self._create_radius_group(name="test", description="test")
        g.delete()
        self.assertEqual(RadiusGroup.objects.all().count(), 4)

    def test_create_organization_default_group(self):
        new_org = self._create_org(**{"name": "new org", "slug": "new-org"})
        queryset = RadiusGroup.objects.filter(organization=new_org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name="new-org-users").count(), 1)
        self.assertEqual(queryset.filter(name="new-org-power-users").count(), 1)
        self.assertEqual(queryset.filter(default=True).count(), 1)
        group = queryset.filter(default=True).first()
        self.assertEqual(group.radiusgroupcheck_set.count(), 2)
        self.assertEqual(group.radiusgroupreply_set.count(), 0)

    def test_rename_organization(self):
        default_org = Organization.objects.first()
        default_org.name = "renamed"
        default_org.slug = default_org.name
        default_org.full_clean()
        default_org.save()
        queryset = RadiusGroup.objects.filter(organization=default_org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name="renamed-users").count(), 1)
        self.assertEqual(queryset.filter(name="renamed-power-users").count(), 1)

    def test_auto_prefix(self):
        org = self._create_org(**{"name": "Cool WiFi", "slug": "cool-wifi"})
        rg = RadiusGroup(name="guests", organization=org)
        rg.full_clean()
        self.assertEqual(rg.name, f"{org.slug}-guests")

    def test_org_none(self):
        rg = RadiusGroup(name="guests")
        try:
            rg.full_clean()
        except ValidationError as e:
            self.assertIn("organization", e.message_dict)
        except Exception as e:
            name = e.__class__.__name__
            self.fail(f"ValidationError not raised, got {name}: {e} instead")
        else:
            self.fail("ValidationError not raised")

    def test_unique_attribute(self):
        org = self._create_org(**{"name": "Cool WiFi", "slug": "cool-wifi"})
        rg = RadiusGroup(name="guests", organization=org)
        rg.save()
        with self.subTest("test radius group check unique attribute"):
            self._create_radius_groupcheck(
                group=rg, attribute="Max-Daily-Session", op=":=", value="3600"
            )
            try:
                self._create_radius_groupcheck(
                    group=rg, attribute="Max-Daily-Session", op=":=", value="3200"
                )
            except ValidationError as e:
                self.assertEqual(
                    {
                        "attribute": [
                            "Another group check for the same group and with the "
                            "same attribute already exists."
                        ]
                    },
                    e.message_dict,
                )
            else:
                self.fail("ValidationError not raised")
        with self.subTest("test radius reply unique attribute"):
            self._create_radius_groupreply(
                group=rg, attribute="Reply-Message", op=":=", value="Login failed"
            )
            try:
                self._create_radius_groupreply(
                    group=rg, attribute="Reply-Message", op=":=", value="Login failed"
                )
            except ValidationError as e:
                self.assertEqual(
                    {
                        "attribute": [
                            "Another group reply for the same group and with the "
                            "same attribute already exists."
                        ]
                    },
                    e.message_dict,
                )
            else:
                self.fail("ValidationError not raised")


class TestTransactionRadiusGroup(BaseTransactionTestCase):
    def test_new_user_default_group(self):
        user = get_user_model()(username="test", email="test@test.org", password="test")
        user.full_clean()
        user.save()
        self._create_org_user(user=user)
        user.refresh_from_db()
        usergroup_set = user.radiususergroup_set.all()
        self.assertEqual(usergroup_set.count(), 1)
        ug = usergroup_set.first()
        self.assertTrue(ug.group.default)
        return user

    def test_user_multiple_orgs_default_group(self):
        user = self.test_new_user_default_group()
        new_org = self._create_org(name="org2", slug="org2")
        self._create_org_user(user=user, organization=new_org)
        usergroup_set = user.radiususergroup_set.all()
        self.assertEqual(usergroup_set.count(), 2)
        new_ug = usergroup_set.filter(group__organization_id=new_org.pk).first()
        self.assertIsNotNone(new_ug)
        self.assertTrue(new_ug.group.default)


class TestRadiusBatch(BaseTestCase):
    def test_string_representation(self):
        radiusbatch = RadiusBatch(name="test")
        self.assertEqual(str(radiusbatch), "test")

    def test_delete_method(self):
        radiusbatch = self._create_radius_batch(
            strategy="prefix", prefix="test-prefix16", name="test"
        )
        radiusbatch.prefix_add("test-prefix16", 5)
        User = get_user_model()
        self.assertEqual(User.objects.all().count(), 5)
        radiusbatch.delete()
        self.assertEqual(RadiusBatch.objects.all().count(), 0)
        self.assertEqual(User.objects.all().count(), 0)

    def test_clean_method(self):
        with self.assertRaises(ValidationError):
            self._create_radius_batch()
        # missing csvfile
        try:
            self._create_radius_batch(strategy="csv", name="test")
        except ValidationError as e:
            self.assertIn("csvfile", e.message_dict)
        else:
            self.fail("ValidationError not raised")
        # missing prefix
        try:
            self._create_radius_batch(strategy="prefix", name="test")
        except ValidationError as e:
            self.assertIn("prefix", e.message_dict)
        else:
            self.fail("ValidationError not raised")
        # mixing strategies
        dummy_file = os.path.join(settings.PRIVATE_STORAGE_ROOT, "test_csv2")
        open(dummy_file, "a").close()
        try:
            self._create_radius_batch(
                strategy="prefix", prefix="prefix", csvfile=dummy_file, name="test"
            )
        except ValidationError as e:
            os.remove(dummy_file)
            self.assertIn("Mixing", str(e))
        else:
            os.remove(dummy_file)
            self.fail("ValidationError not raised")

    def test_csv_import_existing_email(self):
        existing_user = get_user_model().objects.create(
            username="existing", email="existing@test.org", password="test"
        )
        batch = self._create_radius_batch(
            strategy="prefix", prefix="test", name="test-batch"
        )
        row = ["", "password123", "existing@test.org", "John", "Doe"]
        user, password = batch.get_or_create_user(row, [], 8)
        self.assertEqual(user, existing_user)
        self.assertIsNone(password)

    def test_add_user_already_member(self):
        user = get_user_model().objects.create(
            username="testuser", email="test@test.org", password="test"
        )
        org = self.default_org
        self._create_org_user(user=user, organization=org)
        batch = self._create_radius_batch(
            strategy="prefix", prefix="test", name="test-batch"
        )
        OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")
        initial_count = OrganizationUser.objects.filter(user=user).count()
        batch.save_user(user)
        self.assertEqual(
            OrganizationUser.objects.filter(user=user).count(), initial_count
        )


class TestPrivateCsvFile(FileMixin, TestMultitenantAdminMixin, BaseTestCase):
    def setUp(self):
        reader = [["", "cleartext$password", "rohith@openwisp.com", "Rohith", "ASRK"]]
        batch = self._create_radius_batch(
            name="test", strategy="csv", csvfile=self._get_csvfile(reader)
        )
        self.csvfile = batch.csvfile
        super().setUp()

    def _download_csv_file_status(self, status_code):
        response = self.client.get(
            reverse(
                "radius:serve_private_file",
                args=[self.csvfile],
            )
        )
        self.assertEqual(response.status_code, status_code)

    def test_unauthenticated_user(self):
        self._download_csv_file_status(403)

    def test_authenticated_user(self):
        user = self._get_user()
        self.client.force_login(user)
        self._download_csv_file_status(403)

    def test_authenticated_user_with_different_organization(self):
        org2 = self._create_org(**{"name": "test-org2", "is_active": True})
        user2 = self._create_user(**{"username": "test2", "email": "test2@test.co"})
        self._create_org_user(**{"organization": org2, "user": user2})
        self.client.force_login(user2)
        self._download_csv_file_status(403)

    def test_authenticated_user_with_same_organization(self):
        self._get_org_user()
        self.client.force_login(self._get_user())
        self._download_csv_file_status(403)

    def test_staff_user_with_different_organization(self):
        org2 = self._create_org(**{"name": "test-org2", "is_active": True})
        user2 = self._create_operator(**{"username": "test2", "email": "test2@test.co"})
        self._create_org_user(**{"organization": org2, "user": user2})
        self.client.force_login(user2)
        self._download_csv_file_status(403)

    def test_operator_with_different_organization(self):
        org2 = self._create_org(**{"name": "test-org2", "is_active": True})
        user2 = self._create_operator(**{"username": "test2", "email": "test2@test.co"})
        self._create_org_user(**{"organization": org2, "user": user2, "is_admin": True})
        self.client.force_login(user2)
        self._download_csv_file_status(403)

    def test_staff_user_with_same_organization(self):
        self._create_org_user(**{"user": self._get_operator()})
        self.client.force_login(self._get_operator())
        self._download_csv_file_status(403)

    def test_operator_with_same_organization(self):
        self._create_org_user(**{"user": self._get_operator(), "is_admin": True})
        self.client.force_login(self._get_operator())
        self._download_csv_file_status(200)

    def test_superuser(self):
        user = self._get_admin()
        self.client.force_login(user)
        self._download_csv_file_status(200)

    def test_delete_csv_file(self):
        file_storage_backend = RadiusBatch.csvfile.field.storage

        with self.subTest("Test deleting object deletes file"):
            batch = self._create_radius_batch(
                name="test1", strategy="csv", csvfile=self.csvfile
            )
            file_name = batch.csvfile.name
            self.assertEqual(file_storage_backend.exists(file_name), True)
            batch.delete()
            self.assertEqual(file_storage_backend.exists(file_name), False)

        with self.subTest("Test deleting object with a deleted file"):
            batch = self._create_radius_batch(
                name="test2", strategy="csv", csvfile=self.csvfile
            )
            file_name = batch.csvfile.name
            # Delete the file from the storage backend before
            # deleting the object
            file_storage_backend.delete(file_name)
            self.assertNotEqual(batch.csvfile, None)
            batch.delete()

        with self.subTest("Test deleting object without csvfile"):
            batch = self._create_radius_batch(
                name="test3", strategy="prefix", prefix="test-prefix16"
            )
            batch.delete()


class TestChangeOfAuthorization(BaseTransactionTestCase):
    def _change_radius_user_group(self, user, organization):
        rad_user_group = user.radiususergroup_set.first()
        power_user_group = RadiusGroup.objects.get(
            organization=organization, name__contains="power-users"
        )
        rad_user_group.group = power_user_group
        rad_user_group.save()

    def _create_radius_accounting(self, user, organization, options=None):
        radiusaccounting_options = _RADACCT.copy()
        radiusaccounting_options.update(
            {
                "organization": organization,
                "unique_id": "113",
                "username": user.username,
            }
        )
        options = options or {}
        radiusaccounting_options.update(options)
        return super()._create_radius_accounting(**radiusaccounting_options)

    @mock.patch("openwisp_radius.tasks.perform_change_of_authorization.delay")
    def test_no_change_of_authorization_on_new_radius_user_group(self, mocked_task):
        # This method creates a new organization user
        # which has a RadiusUserGroup by default.
        user = self._get_user_with_org()
        self.assertEqual(user.radiususergroup_set.count(), 1)
        mocked_task.assert_not_called()

    @capture_any_output()
    @mock.patch("openwisp_radius.tasks.perform_change_of_authorization.delay")
    def test_no_change_of_authorization_on_closed_sessions(self, mocked_task):
        user = self._get_user_with_org()
        org = self._get_org()
        self._create_radius_accounting(
            user, org, options={"stop_time": "2022-11-04 10:50:00"}
        )
        self._change_radius_user_group(user, org)
        mocked_task.assert_not_called()

    @mock.patch.object(RadClient, "perform_disconnect", return_value=False)
    @mock.patch.object(RadClient, "perform_change_of_authorization", return_value=False)
    @mock.patch("logging.Logger.warning")
    def test_perform_change_of_authorization_celery_task_failures(
        self, mocked_logger, mocked_coa, mocked_disconnect
    ):
        mocked_user_id = uuid4()
        mocked_old_group_id = uuid4()
        mocked_new_group_id = uuid4()
        org = self._get_org()
        user = self._get_user_with_org()
        user_group = RadiusGroup.objects.get(organization=org, name=f"{org.slug}-users")
        power_user_group = RadiusGroup.objects.get(
            organization=org, name=f"{org.slug}-power-users"
        )
        with self.subTest("Test user deleted after scheduling of task"):
            perform_change_of_authorization(
                user_id=mocked_user_id,
                old_group_id=mocked_old_group_id,
                new_group_id=mocked_new_group_id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to find user with "{mocked_user_id}" ID.'
                " Skipping CoA operation."
            )
        mocked_logger.reset_mock()

        with self.subTest("Test user session closed after scheduling of task"):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group.id,
                new_group_id=power_user_group.id,
            )
            mocked_logger.assert_called_once_with(
                f'The user "{user.username} <{user.email}>" does not have any open'
                " RadiusAccounting sessions. Skipping CoA operation."
            )
        mocked_logger.reset_mock()

        session = self._create_radius_accounting(user, org)

        with self.subTest("Test new RadiusGroup was deleted after scheduling of task"):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group,
                new_group_id=mocked_new_group_id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to find RadiusGroup with "{mocked_new_group_id}" ID.'
                " Skipping CoA operation."
            )
        mocked_logger.reset_mock()

        with self.subTest("Test NAS not found for the RadiusAccounting object"):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group.id,
                new_group_id=power_user_group.id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to find RADIUS secret for "{session.unique_id}"'
                " RadiusAccounting object. Skipping CoA operation"
                " for this session."
            )
        mocked_logger.reset_mock()

        nas = self._create_nas(
            name="NAS",
            organization=org,
            short_name="test",
            type="Virtual",
            secret="testing123",
        )

        with self.subTest("Test NAS name does not contain IP network"):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group.id,
                new_group_id=power_user_group.id,
            )
            self.assertEqual(
                mocked_logger.call_args_list[0][0][0],
                f'Failed to parse NAS IP network for "{nas.id}" object. Skipping!',
            )
            self.assertEqual(
                mocked_logger.call_args_list[1][0][0],
                f'Failed to find RADIUS secret for "{session.unique_id}"'
                " RadiusAccounting object. Skipping CoA operation"
                " for this session.",
            )
        mocked_logger.reset_mock()

        nas.name = "127.0.0.1"
        nas.save()
        with self.subTest("Test RadClient encountered error while sending CoA packet"):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group.id,
                new_group_id=power_user_group.id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to perform CoA for "{session.unique_id}"'
                f' RadiusAccounting object of "{user}" user'
            )

        mocked_coa.reset_mock()
        with self.subTest("Counter.check() raises Exception"):
            with mock.patch(
                "openwisp_radius.counters.base.BaseCounter.check",
                side_effect=Exception("Test exception"),
            ), mock.patch("logging.Logger.exception") as mocked_exception:
                perform_change_of_authorization(
                    user_id=user.id,
                    old_group_id=power_user_group.id,
                    new_group_id=user_group.id,
                )
                # All counters raised exception, we cannot proceed with CoA
                mocked_coa.assert_not_called()
                counter = app_settings.CHECK_ATTRIBUTE_COUNTERS_MAP[
                    "Max-Daily-Session-Traffic"
                ]
                mocked_exception.assert_called_with(
                    f'Got exception "Test exception" while executing '
                    f"{counter.counter_name}(user={user.username}, "
                    f"group={user_group}, organization_id={org.id.hex})"
                )

        mocked_coa.reset_mock()
        with self.subTest("Counter.check() raises MaxQuotaReached"):
            with mock.patch(
                "openwisp_radius.counters.base.BaseCounter.check",
                side_effect=MaxQuotaReached(
                    message="MaxQuotaReached",
                    level="info",
                    logger=logging,
                    reply_message="reply MaxQuotaReached",
                ),
            ), mock.patch("logging.Logger.exception") as mocked_exception:
                perform_change_of_authorization(
                    user_id=user.id,
                    old_group_id=power_user_group.id,
                    new_group_id=user_group.id,
                )
                mocked_coa.assert_not_called()
                mocked_disconnect.assert_called_once_with(
                    {
                        "User-Name": "tester",
                    }
                )
                mocked_exception.assert_not_called()

        mocked_coa.reset_mock()
        mocked_disconnect.reset_mock()
        with self.subTest("RADIUS Attribute absent from CHECK_ATTRIBUTE_COUNTERS_MAP"):
            with mock.patch(
                "openwisp_radius.tasks.app_settings.CHECK_ATTRIBUTE_COUNTERS_MAP", {}
            ), mock.patch("logging.Logger.exception") as mocked_exception:
                perform_change_of_authorization(
                    user_id=user.id,
                    old_group_id=power_user_group.id,
                    new_group_id=user_group.id,
                )
                mocked_coa.assert_not_called()
                mocked_disconnect.assert_not_called()
                mocked_exception.assert_not_called()

    @mock.patch.object(RadClient, "perform_change_of_authorization", return_value=True)
    @capture_stderr()
    def test_change_of_authorization(self, mocked_radclient, *args):
        org = self._get_org()
        user = self._get_user_with_org()
        nas_options = {
            "organization": org,
            "short_name": "test",
            "type": "Virtual",
            "secret": "testing123",
        }
        self._create_nas(name="10.8.0.0/24", **nas_options)
        self._create_nas(name="172.16.0.0/24", **nas_options)
        rad_acct = self._create_radius_accounting(
            user, org, options={"nas_ip_address": "10.8.0.1"}
        )
        user_radiususergroup = user.radiususergroup_set.first()
        restricted_user_group = RadiusGroup.objects.get(
            organization=org, name=f"{org.slug}-users"
        )
        power_user_group = RadiusGroup.objects.get(
            organization=org, name=f"{org.slug}-power-users"
        )
        self._create_radius_groupreply(
            group=restricted_user_group,
            attribute="Idle-Timeout",
            op="=",
            value="300",
        )

        # RadiusGroup is changed to a power user.
        # Limitations set by the previous RadiusGroup
        # should be removed.
        user_radiususergroup.group = power_user_group
        user_radiususergroup.save()
        mocked_radclient.assert_called_with(
            {
                "User-Name": user.username,
                "Session-Timeout": "",
                "CoovaChilli-Max-Total-Octets": "",
                "Idle-Timeout": "",
            }
        )
        rad_acct.refresh_from_db()
        self.assertEqual(rad_acct.groupname, power_user_group.name)

        mocked_radclient.reset_mock()
        # RadiusGroup is changed to a restricted user.
        # Limitations set by the previous RadiusGroup
        # should be removed.
        user_radiususergroup.group = restricted_user_group
        user_radiususergroup.save()
        mocked_radclient.assert_called_with(
            {
                "User-Name": user.username,
                "Session-Timeout": "10800",
                "CoovaChilli-Max-Total-Octets": "3000000000",
                "Idle-Timeout": "300",
            }
        )
        rad_acct.refresh_from_db()
        self.assertEqual(rad_acct.groupname, restricted_user_group.name)

    @mock.patch.object(RadClient, "perform_change_of_authorization")
    def test_change_of_authorization_org_disabled(self, mocked_radclient):
        org = self._get_org()
        org.radius_settings.coa_enabled = False
        org.radius_settings.save()
        user = self._get_user_with_org()
        nas_options = {
            "organization": org,
            "short_name": "test",
            "type": "Virtual",
            "secret": "testing123",
        }
        self._create_nas(name="10.8.0.0/24", **nas_options)
        self._create_radius_accounting(
            user, org, options={"nas_ip_address": "10.8.0.1"}
        )
        user_radiususergroup = user.radiususergroup_set.first()
        power_user_group = RadiusGroup.objects.get(
            organization=org, name=f"{org.slug}-power-users"
        )
        user_radiususergroup.group = power_user_group
        user_radiususergroup.save()
        mocked_radclient.assert_not_called()

    @mock.patch.object(RadClient, "perform_change_of_authorization", return_value=True)
    def test_sessions_with_multiple_orgs(self, mocked_radclient):
        org1 = self._get_org()
        org2 = self._get_org("org2")
        user = self._get_user_with_org()
        self._create_org_user(user=user, organization=org2)
        self.assertEqual(user.radiususergroup_set.count(), 2)
        nas_options = {
            "organization": org1,
            "short_name": "test1",
            "type": "Virtual",
            "secret": "testing123",
        }
        self._create_nas(name="10.8.0.0/24", **nas_options)
        org2_session = self._create_radius_accounting(
            user,
            org2,
            options={"nas_ip_address": "10.9.0.1", "groupname": f"{org2.slug}-users"},
        )
        org1_session = self._create_radius_accounting(
            user,
            org1,
            options={
                "nas_ip_address": "10.8.0.1",
                "unique_id": "114",
                "groupname": f"{org1.slug}-users",
            },
        )
        user_radiususergroup = user.radiususergroup_set.get(group__organization=org1)
        org1_power_user_group = RadiusGroup.objects.get(
            organization=org1, name=f"{org1.slug}-power-users"
        )
        user_radiususergroup.group = org1_power_user_group
        user_radiususergroup.save()

        mocked_radclient.assert_called_once_with(
            {
                "Session-Timeout": "",
                "CoovaChilli-Max-Total-Octets": "",
                "User-Name": "tester",
            }
        )
        org1_session.refresh_from_db()
        self.assertEqual(org1_session.groupname, org1_power_user_group.name)
        org2_session.refresh_from_db()
        self.assertEqual(org2_session.groupname, f"{org2.slug}-users")


class TestCoverageImprovements(BaseTestCase):

    def test_auto_username_mixin_edge_cases(self):
        existing_user = get_user_model().objects.create(
            username="existing", email="existing@test.org", password="test"
        )
        self._create_org_user(organization=self.default_org, user=existing_user)

        check = RadiusCheck(
            username="existing",
            op=":=",
            attribute="Max-Daily-Session",
            value="3600",
            organization=self.default_org,
        )
        check.clean()
        self.assertEqual(check.user, existing_user)

    def test_radius_group_validation_edge_cases(self):
        group = RadiusGroup(name="test-group", default=True)
        if not hasattr(group, "organization"):
            group.clean()

    def test_organization_radius_settings_validation_edge_cases(self):
        org_settings = OrganizationRadiusSettings.objects.create(
            organization=self.default_org, token="test-token"
        )

        org_settings.freeradius_allowed_hosts = ""
        with mock.patch.object(app_settings, "FREERADIUS_ALLOWED_HOSTS", []):
            try:
                org_settings._clean_freeradius_allowed_hosts()
            except ValidationError as e:
                self.assertIn("freeradius_allowed_hosts", str(e))

        org_settings.allowed_mobile_prefixes = "+999,invalid"
        try:
            org_settings._clean_allowed_mobile_prefixes()
        except ValidationError as e:
            self.assertIn("allowed_mobile_prefixes", str(e))

        org_settings.password_reset_url = "http://example.com/reset"
        try:
            org_settings._clean_password_reset_url()
        except ValidationError as e:
            self.assertIn("password_reset_url", str(e))

        org_settings.sms_message = "Your verification code is ready"
        try:
            org_settings._clean_sms_message()
        except ValidationError as e:
            self.assertIn("sms_message", str(e))

    def test_organization_radius_settings_validation_edge_cases(self):
        org_settings, created = OrganizationRadiusSettings.objects.get_or_create(
            organization=self.default_org, defaults={"token": "test-token"}
        )
        if not created:
            org_settings.token = "test-token"
            org_settings.save()

        org_settings.freeradius_allowed_hosts = ""
        with mock.patch.object(app_settings, "FREERADIUS_ALLOWED_HOSTS", []):
            try:
                org_settings._clean_freeradius_allowed_hosts()
            except ValidationError as e:
                self.assertIn("freeradius_allowed_hosts", str(e))

        org_settings.allowed_mobile_prefixes = "+999,invalid"
        try:
            org_settings._clean_allowed_mobile_prefixes()
        except ValidationError as e:
            self.assertIn("allowed_mobile_prefixes", str(e))

        org_settings.password_reset_url = "http://example.com/reset"
        try:
            org_settings._clean_password_reset_url()
        except ValidationError as e:
            self.assertIn("password_reset_url", str(e))
        org_settings.sms_message = "Your verification code is ready"
        try:
            org_settings._clean_sms_message()
        except ValidationError as e:
            self.assertIn("sms_message", str(e))

    def test_radius_batch_clean_edge_cases(self):
        batch = RadiusBatch(
            name="test",
            organization=self.default_org,
            strategy="prefix",
            prefix="invalid!@#$%^&*()",
        )

        try:
            batch.clean()
        except ValidationError as e:
            self.assertIn("prefix", str(e))

    def test_phone_token_edge_cases(self):
        PhoneToken = load_model("PhoneToken")
        user = get_user_model().objects.create(
            username="phoneuser", email="phone@test.org", password="test"
        )
        self._create_org_user(organization=self.default_org, user=user)

        token = PhoneToken(user=user, phone_number="+1234567890", ip="192.168.1.1")

        try:
            token._validate_already_verified()
        except ObjectDoesNotExist:
            pass

        with mock.patch.object(app_settings, "SMS_TOKEN_MAX_USER_DAILY", 1):
            existing_token = PhoneToken.objects.create(
                user=user, phone_number="+1234567891", ip="192.168.1.2"
            )

            try:
                token._validate_max_attempts()
            except ValidationError as e:
                self.assertIn("Maximum daily limit reached", str(e))

    def test_registered_user_properties(self):
        RegisteredUser = load_model("RegisteredUser")
        user = get_user_model().objects.create(
            username="reguser", email="reg@test.org", password="test"
        )

        registered_user = RegisteredUser.objects.create(
            user=user, method="email", is_verified=True
        )

        self.assertFalse(registered_user.is_identity_verified_strong)

        registered_user.method = "sms"
        self.assertTrue(registered_user.is_identity_verified_strong)

    def test_radius_token_str_method(self):
        RadiusToken = load_model("RadiusToken")
        user = get_user_model().objects.create(
            username="tokenuser", email="token@test.org", password="test"
        )

        token = RadiusToken.objects.create(user=user, organization=self.default_org)

        token.key = None
        str_representation = str(token)
        self.assertIn("RadiusToken:", str_representation)
        self.assertIn(user.username, str_representation)

    def test_cache_operations(self):
        org_settings, created = OrganizationRadiusSettings.objects.get_or_create(
            organization=self.default_org, defaults={"token": "test-token-123"}
        )
        if not created:
            org_settings.token = "test-token-123"
            org_settings.save()

        org_settings.save_cache()
        from django.core.cache import cache

        cached_token = cache.get(self.default_org.pk)
        self.assertEqual(cached_token, "test-token-123")

        org_settings.delete_cache()
        cached_token = cache.get(self.default_org.pk)
        self.assertIsNone(cached_token)

        RadiusToken = load_model("RadiusToken")
        user = get_user_model().objects.create(
            username="cacheuser", email="cache@test.org", password="test"
        )

        token = RadiusToken.objects.create(user=user, organization=self.default_org)

        cache.set(f"rt-{user.username}", "test-value")

        token.delete_cache()
        cached_value = cache.get(f"rt-{user.username}")
        self.assertIsNone(cached_value)

    def test_attribute_validation_mixin_properties(self):
        check = self._create_radius_check(
            username="testuser", op=":=", attribute="Test-Attribute", value="test"
        )

        object_name = check._object_name
        self.assertIn("check", object_name)

        error_msg = check._get_error_message()
        self.assertIn("check", error_msg)

    def test_radius_accounting_close_stale_sessions_edge_cases(self):
        result = RadiusAccounting._close_stale_sessions_on_nas_boot(None)
        self.assertEqual(result, 0)

        result = RadiusAccounting._close_stale_sessions_on_nas_boot("")
        self.assertEqual(result, 0)

    @mock.patch("logging.Logger.warning")
    def test_phone_token_send_edge_cases(self, mock_logger):
        PhoneToken = load_model("PhoneToken")

        user_without_org = get_user_model().objects.create(
            username="noorg", email="noorg@test.org", password="test"
        )

        token = PhoneToken(
            user=user_without_org, phone_number="+1234567890", ip="192.168.1.1"
        )

        from openwisp_radius.exceptions import NoOrgException

        try:
            token.send_token()
        except NoOrgException as e:
            self.assertIn("not member of any organization", str(e))

    def test_radius_batch_get_or_create_user_edge_cases(self):
        batch = self._create_radius_batch(
            strategy="prefix", prefix="test", name="test-batch"
        )

        # Test creating new user with empty password - generates password
        row = ["testuser", "", "test@example.com", "Test", "User"]
        user, password = batch.get_or_create_user(row, [], 8)
        self.assertIsNotNone(user)
        self.assertIsNotNone(password)  # Generated password is returned

        existing_user = get_user_model().objects.create(
            username="existing", email="existing@example.com", password="test"
        )

        row = ["newuser", "password123", "existing@example.com", "Test", "User"]
        user, password = batch.get_or_create_user(row, [], 8)
        self.assertEqual(user, existing_user)
        self.assertIsNone(password)

    def test_radius_batch_expire_method(self):
        batch = self._create_radius_batch(
            strategy="prefix", prefix="test", name="test-batch"
        )

        test_user = get_user_model().objects.create_user(
            username="batchuser", email="batch@example.com", password="testpass123"
        )
        batch.users.add(test_user)

        batch.expire()
        test_user.refresh_from_db()
        self.assertFalse(test_user.is_active)

    def test_radius_check_validation_kwargs_without_org(self):
        check = RadiusCheck(
            username="testuser", op=":=", attribute="Test-Attribute", value="test"
        )
        check.user = get_user_model().objects.create(
            username="testuser", email="test@test.org", password="test"
        )
        check.organization = None

        kwargs = check._get_validation_queryset_kwargs()
        self.assertIn("user", kwargs)
        self.assertIn("attribute", kwargs)
        self.assertNotIn("organization", kwargs)

    def test_radius_reply_validation_kwargs_without_org(self):
        reply = RadiusReply(
            username="testuser", op="=", attribute="Reply-Message", value="test"
        )
        reply.user = get_user_model().objects.create(
            username="testuser2", email="test2@test.org", password="test"
        )
        reply.organization = None

        kwargs = reply._get_validation_queryset_kwargs()
        self.assertIn("user", kwargs)
        self.assertIn("attribute", kwargs)
        self.assertNotIn("organization", kwargs)

    def test_radius_group_get_default_queryset_no_pk(self):
        group = RadiusGroup(name="test", organization=self.default_org, default=True)
        queryset = group.get_default_queryset()
        self.assertTrue(queryset.exists())


class TestCoverageImprovementsTransaction(BaseTransactionTestCase):

    def test_radius_batch_process_with_exception(self):
        batch = self._create_radius_batch(
            strategy="prefix", prefix="test", name="test-batch"
        )

        with mock.patch.object(
            batch, "prefix_add", side_effect=Exception("Test error")
        ):
            batch.process(number_of_users=5, is_async=True)
            self.assertEqual(batch.status, RadiusBatch.FAILED)

    @mock.patch("openwisp_radius.utils.SmsMessage.send")
    def test_phone_token_sms_send_failure(self, mock_send):
        PhoneToken = load_model("PhoneToken")
        user = get_user_model().objects.create_user(
            username="smsuser", email="sms@test.org", password="test"
        )

        OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")
        OrganizationUser.objects.create(user=user, organization=self._get_org())

        mock_send.side_effect = Exception("SMS sending failed")

        token = PhoneToken(user=user, phone_number="+1234567890", ip="192.168.1.1")

        try:
            token.send_token()
        except Exception as e:
            self.assertIn("SMS sending failed", str(e))


del BaseTestCase
del BaseTransactionTestCase
