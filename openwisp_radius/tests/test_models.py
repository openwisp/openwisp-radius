import os
from unittest import mock
from uuid import UUID, uuid4

import swapper
from django.apps.registry import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.urls import reverse
from django.utils import timezone
from netaddr import EUI, mac_unix

from openwisp_users.tests.utils import TestMultitenantAdminMixin
from openwisp_utils.tests import capture_any_output, capture_stderr

from .. import settings as app_settings
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

Nas = load_model('Nas')
RadiusAccounting = load_model('RadiusAccounting')
RadiusCheck = load_model('RadiusCheck')
RadiusReply = load_model('RadiusReply')
RadiusPostAuth = load_model('RadiusPostAuth')
RadiusGroup = load_model('RadiusGroup')
RadiusGroupCheck = load_model('RadiusGroupCheck')
RadiusGroupReply = load_model('RadiusGroupReply')
RadiusUserGroup = load_model('RadiusUserGroup')
RadiusBatch = load_model('RadiusBatch')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
Organization = swapper.load_model('openwisp_users', 'Organization')


class TestNas(BaseTestCase):
    def test_string_representation(self):
        nas = Nas(name='entry nasname')
        self.assertEqual(str(nas), nas.name)

    def test_id_uuid(self):
        nas = Nas(name='uuid id')
        self.assertIsInstance(nas.pk, UUID)


class TestRadiusAccounting(FileMixin, BaseTestCase):
    def test_string_representation(self):
        radiusaccounting = RadiusAccounting(unique_id='entry acctuniqueid')
        self.assertEqual(str(radiusaccounting), radiusaccounting.unique_id)

    def test_id(self):
        radiusaccounting = RadiusAccounting(unique_id='unique')
        self.assertEqual(radiusaccounting.pk, radiusaccounting.unique_id)

    def test_ipv6_validator(self):
        radiusaccounting = RadiusAccounting(
            organization=self.default_org,
            unique_id='entry acctuniqueid',
            session_id='entry acctuniqueid',
            nas_ip_address='192.168.182.3',
            framed_ipv6_prefix='::/64',
        )
        radiusaccounting.full_clean()

        radiusaccounting.framed_ipv6_prefix = '192.168.0.0/28'
        self.assertRaises(ValidationError, radiusaccounting.full_clean)

        radiusaccounting.framed_ipv6_prefix = 'invalid ipv6_prefix'
        self.assertRaises(ValidationError, radiusaccounting.full_clean)

    def _run_convert_called_station_id_tests(self):
        """
        Reused by other tests below.
        """
        radiusaccounting_options = _RADACCT.copy()
        radiusaccounting_options.update(
            {
                'organization': self.default_org,
                'nas_ip_address': '192.168.182.3',
                'framed_ipv6_prefix': '::/64',
                'calling_station_id': str(EUI('bb:bb:bb:bb:bb:0b', dialect=mac_unix)),
                'called_station_id': 'AA-AA-AA-AA-AA-0A',
            }
        )
        with self.subTest('Settings disabled'):
            options = radiusaccounting_options.copy()
            options['unique_id'] = '113'
            radiusaccounting = self._create_radius_accounting(**options)
            radiusaccounting.refresh_from_db()
            self.assertEqual(radiusaccounting.called_station_id, 'AA-AA-AA-AA-AA-0A')

        RadiusAppConfig = apps.get_app_config(RadiusAccounting._meta.app_label)
        RadiusAppConfig.connect_signals()

        with self.subTest('CALLED_STATION_ID not defined for organization'):
            options = radiusaccounting_options.copy()
            options['unique_id'] = '111'
            options['organization'] = self._create_org(name='new-org')
            radiusaccounting = self._create_radius_accounting(**options)
            radiusaccounting.refresh_from_db()
            self.assertEqual(radiusaccounting.called_station_id, 'AA-AA-AA-AA-AA-0A')

        with self.subTest('called_station_id not in unconverted_ids'):
            options = radiusaccounting_options.copy()
            options['called_station_id'] = 'EE-EE-EE-EE-EE-EE'
            options['unique_id'] = '112'
            radiusaccounting = self._create_radius_accounting(**options)
            radiusaccounting.refresh_from_db()
            self.assertEqual(radiusaccounting.called_station_id, 'EE-EE-EE-EE-EE-EE')

        with self.subTest('Ideal condition'):
            with self._get_openvpn_status_mock():
                options = radiusaccounting_options.copy()
                options['unique_id'] = '114'
                radiusaccounting = self._create_radius_accounting(**options)
                radiusaccounting.refresh_from_db()
                self.assertEqual(
                    radiusaccounting.called_station_id, 'CC-CC-CC-CC-CC-0C'
                )

    def test_multiple_accounting_sessions(self):
        radiusaccounting_options = _RADACCT.copy()
        radiusaccounting_options.update(
            {
                'organization': self.default_org,
                'nas_ip_address': '192.168.182.3',
                'framed_ipv6_prefix': '::/64',
                'calling_station_id': str(EUI('bb:bb:bb:bb:bb:0b', dialect=mac_unix)),
                'called_station_id': 'AA-AA-AA-AA-AA-0A',
            }
        )

        with self.subTest('Test new session with same called_station_id'):
            radiusaccounting1 = self._create_radius_accounting(
                unique_id='111', update_time=timezone.now(), **radiusaccounting_options
            )
            radiusaccounting2 = self._create_radius_accounting(
                unique_id='112', update_time=timezone.now(), **radiusaccounting_options
            )
            radiusaccounting1.refresh_from_db()
            radiusaccounting2.refresh_from_db()
            self.assertEqual(radiusaccounting1.terminate_cause, 'Session-Timeout')
            self.assertEqual(radiusaccounting1.stop_time, radiusaccounting1.update_time)
            self.assertEqual(radiusaccounting2.stop_time, None)

    @capture_any_output()
    @mock.patch.object(app_settings, 'OPENVPN_DATETIME_FORMAT', u'%Y-%m-%d %H:%M:%S')
    @mock.patch.object(app_settings, 'CONVERT_CALLED_STATION_ON_CREATE', True)
    def test_convert_called_station_id_with_organization_id(self, *args, **kwargs):
        called_station_ids = {
            str(self._get_org().id): _CALLED_STATION_IDS.get('test-org')
        }
        with mock.patch.object(
            app_settings,
            'CALLED_STATION_IDS',
            called_station_ids,
        ):
            self._run_convert_called_station_id_tests()

    @capture_any_output()
    @mock.patch.object(
        app_settings,
        'CALLED_STATION_IDS',
        _CALLED_STATION_IDS,
    )
    @mock.patch.object(app_settings, 'OPENVPN_DATETIME_FORMAT', u'%Y-%m-%d %H:%M:%S')
    @mock.patch.object(app_settings, 'CONVERT_CALLED_STATION_ON_CREATE', True)
    def test_convert_called_station_id_with_organization_slug(self, *args, **kwargs):
        self._run_convert_called_station_id_tests()


class TestRadiusCheck(BaseTestCase):
    def test_string_representation(self):
        radiuscheck = RadiusCheck(username='entry username')
        self.assertEqual(str(radiuscheck), radiuscheck.username)

    def test_id(self):
        radiuscheck = RadiusCheck(username='test uuid')
        self.assertIsInstance(radiuscheck.pk, UUID)

    def test_auto_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org, user=u)
        c = self._create_radius_check(
            user=u,
            op=':=',
            attribute='Max-Daily-Session',
            value='3600',
            organization=org,
        )
        self.assertEqual(c.username, u.username)

    def test_empty_username(self):
        opts = dict(op=':=', attribute='Max-Daily-Session', value='3600')
        try:
            self._create_radius_check(**opts)
        except ValidationError as e:
            self.assertIn('username', e.message_dict)
            self.assertIn('user', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_change_user_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org, user=u)
        c = self._create_radius_check(
            user=u,
            op=':=',
            attribute='Max-Daily-Session',
            value='3600',
            organization=org,
        )
        u.username = 'changed'
        u.full_clean()
        u.save()
        c.refresh_from_db()
        # ensure related records have been updated
        self.assertEqual(c.username, u.username)

    def test_create_radius_check_model(self):
        obj = RadiusCheck.objects.create(
            organization=self.default_org,
            username='Monica',
            value='Cam0_liX',
            attribute='NT-Password',
            op=':=',
        )
        self.assertEqual(obj.value, 'Cam0_liX')

    def test_user_different_organization(self):
        org1 = self._create_org(**{'name': 'org1', 'slug': 'org1'})
        org2 = self._create_org(**{'name': 'org2', 'slug': 'org2'})
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org1, user=u)
        try:
            self._create_radius_check(
                user=u,
                op=':=',
                attribute='Max-Daily-Session',
                value='3600',
                organization=org2,
            )
        except ValidationError as e:
            self.assertIn('organization', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_radius_check_unique_attribute(self):
        org1 = self._create_org(**{'name': 'org1', 'slug': 'org1'})
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org1, user=u)
        self._create_radius_check(
            user=u,
            op=':=',
            attribute='Max-Daily-Session',
            value='3600',
            organization=org1,
        )
        try:
            self._create_radius_check(
                user=u,
                op=':=',
                attribute='Max-Daily-Session',
                value='3200',
                organization=org1,
            )
        except ValidationError as e:
            self.assertEqual(
                {
                    'attribute': [
                        'Another check for the same user and with the '
                        'same attribute already exists.'
                    ]
                },
                e.message_dict,
            )
        else:
            self.fail('ValidationError not raised')


class TestRadiusReply(BaseTestCase):
    def test_string_representation(self):
        radiusreply = RadiusReply(username='entry username')
        self.assertEqual(str(radiusreply), radiusreply.username)

    def test_uuid(self):
        radiusreply = RadiusReply(username='test id')
        self.assertIsInstance(radiusreply.pk, UUID)

    def test_auto_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org, user=u)
        r = self._create_radius_reply(
            user=u,
            attribute='Reply-Message',
            op=':=',
            value='Login failed',
            organization=org,
        )
        self.assertEqual(r.username, u.username)

    def test_empty_username(self):
        opts = dict(attribute='Reply-Message', op=':=', value='Login failed')
        try:
            self._create_radius_reply(**opts)
        except ValidationError as e:
            self.assertIn('username', e.message_dict)
            self.assertIn('user', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_change_user_username(self):
        org = self.default_org
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org, user=u)
        r = self._create_radius_reply(
            user=u,
            attribute='Reply-Message',
            op=':=',
            value='Login failed',
            organization=org,
        )
        u.username = 'changed'
        u.full_clean()
        u.save()
        r.refresh_from_db()
        # ensure related records have been updated
        self.assertEqual(r.username, u.username)

    def test_user_different_organization(self):
        org1 = self._create_org(**{'name': 'org1', 'slug': 'org1'})
        org2 = self._create_org(**{'name': 'org2', 'slug': 'org2'})
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org1, user=u)
        try:
            self._create_radius_reply(
                user=u,
                attribute='Reply-Message',
                op=':=',
                value='Login failed',
                organization=org2,
            )
        except ValidationError as e:
            self.assertIn('organization', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_radius_reply_unique_attribute(self):
        org1 = self._create_org(**{'name': 'org1', 'slug': 'org1'})
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        self._create_org_user(organization=org1, user=u)
        self._create_radius_reply(
            user=u,
            attribute='Reply-Message',
            op=':=',
            value='Login failed',
            organization=org1,
        )
        try:
            self._create_radius_reply(
                user=u,
                attribute='Reply-Message',
                op='=',
                value='Login failed',
                organization=org1,
            )
        except ValidationError as e:
            self.assertEqual(
                {
                    'attribute': [
                        'Another reply for the same user and with the '
                        'same attribute already exists.'
                    ]
                },
                e.message_dict,
            )
        else:
            self.fail('ValidationError not raised')


class TestRadiusPostAuth(BaseTestCase):
    def test_string_representation(self):
        radiuspostauthentication = RadiusPostAuth(username='entry username')
        self.assertEqual(
            str(radiuspostauthentication), radiuspostauthentication.username
        )

    def test_id(self):
        radiuspostauth = RadiusPostAuth(username='test id')
        self.assertIsInstance(radiuspostauth.pk, UUID)


class TestRadiusGroup(BaseTestCase):
    def test_group_str(self):
        g = RadiusGroup(name='entry groupname')
        self.assertEqual(str(g), g.name)

    def test_group_id(self):
        g = RadiusGroup(name='test group id')
        self.assertIsInstance(g.pk, UUID)

    def test_group_reply_str(self):
        r = RadiusGroupReply(groupname='entry groupname')
        self.assertEqual(str(r), r.groupname)

    def test_group_reply_id(self):
        gr = RadiusGroupReply(groupname='test group reply id')
        self.assertIsInstance(gr.pk, UUID)

    def test_group_check_str(self):
        c = RadiusGroupCheck(groupname='entry groupname')
        self.assertEqual(str(c), c.groupname)

    def test_group_check_id(self):
        gc = RadiusGroupCheck(groupname='group check id')
        self.assertIsInstance(gc.pk, UUID)

    def test_user_group_str(self):
        ug = RadiusUserGroup(username='entry username')
        self.assertEqual(str(ug), ug.username)

    def test_user_group_id(self):
        ug = RadiusUserGroup(username='test user group id')
        self.assertIsInstance(ug.pk, UUID)

    def test_default_groups(self):
        org = self._get_org('default')
        queryset = RadiusGroup.objects.filter(organization=org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name='default-users').count(), 1)
        self.assertEqual(queryset.filter(name='default-power-users').count(), 1)
        self.assertEqual(queryset.filter(default=True).count(), 1)
        users = queryset.get(name='default-users')
        self.assertTrue(users.default)
        self.assertEqual(users.radiusgroupcheck_set.count(), 2)
        check = users.radiusgroupcheck_set.get(attribute=SESSION_TIME_ATTRIBUTE)
        self.assertEqual(check.value, DEFAULT_SESSION_TIME_LIMIT)
        check = users.radiusgroupcheck_set.get(attribute=SESSION_TRAFFIC_ATTRIBUTE)
        self.assertEqual(check.value, DEFAULT_SESSION_TRAFFIC_LIMIT)
        power_users = queryset.get(name='default-power-users')
        self.assertEqual(power_users.radiusgroupcheck_set.count(), 0)

    def test_change_default_group(self):
        org1 = self._create_org(**{'name': 'org1', 'slug': 'org1'})
        org2 = self._create_org(**{'name': 'org2', 'slug': 'org2'})
        new_default_org1 = RadiusGroup(
            name='org1-new', organization=org1, description='test', default=True
        )
        new_default_org1.full_clean()
        new_default_org1.save()
        new_default_org2 = RadiusGroup(
            name='org2-new', organization=org2, description='test', default=True
        )
        new_default_org2.full_clean()
        new_default_org2.save()
        queryset = RadiusGroup.objects.filter(default=True, organization=org1)
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.filter(name='org1-new').count(), 1)
        # org2
        queryset = RadiusGroup.objects.filter(default=True, organization=org2)
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.filter(name='org2-new').count(), 1)

    def test_delete_default_group(self):
        group = RadiusGroup.objects.get(organization=self._get_org(), default=1)
        try:
            group.delete()
        except ProtectedError:
            pass
        else:
            self.fail('ProtectedError not raised')

    def test_undefault_group(self):
        group = RadiusGroup.objects.get(organization=self._get_org(), default=True)
        group.default = False
        try:
            group.full_clean()
        except ValidationError as e:
            self.assertIn('default', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_no_default_failure_after_erasing(self):
        # this is a corner case but a very annoying one
        RadiusGroup.objects.all().delete()  # won't trigger ValidationError
        self._create_radius_group(name='test')

    def test_groupcheck_auto_name(self):
        g = self._create_radius_group(name='test', description='test')
        c = self._create_radius_groupcheck(
            group=g, attribute='Max-Daily-Session', op=':=', value='3600'
        )
        self.assertEqual(c.groupname, g.name)

    def test_groupcheck_empty_groupname(self):
        opts = dict(attribute='Max-Daily-Session', op=':=', value='3600')
        try:
            self._create_radius_groupcheck(**opts)
        except ValidationError as e:
            self.assertIn('groupname', e.message_dict)
            self.assertIn('group', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_groupreply_auto_name(self):
        g = self._create_radius_group(name='test', description='test')
        r = self._create_radius_groupreply(
            group=g, attribute='Reply-Message', op=':=', value='Login failed'
        )
        self.assertEqual(r.groupname, g.name)

    def test_groupreply_empty_groupname(self):
        opts = dict(attribute='Reply-Message', op=':=', value='Login failed')
        try:
            self._create_radius_groupreply(**opts)
        except ValidationError as e:
            self.assertIn('groupname', e.message_dict)
            self.assertIn('group', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_usergroups_auto_fields(self):
        g = self._create_radius_group(name='test', description='test')
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        ug = self._create_radius_usergroup(user=u, group=g, priority=1)
        self.assertEqual(ug.groupname, g.name)
        self.assertEqual(ug.username, u.username)

    def test_usergroups_empty_groupname(self):
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        try:
            self._create_radius_usergroup(user=u, priority=1)
        except ValidationError as e:
            self.assertIn('groupname', e.message_dict)
            self.assertIn('group', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_usergroups_empty_username(self):
        g = self._create_radius_group(name='test', description='test')
        try:
            self._create_radius_usergroup(group=g, priority=1)
        except ValidationError as e:
            self.assertIn('username', e.message_dict)
            self.assertIn('user', e.message_dict)
        else:
            self.fail('ValidationError not raised')

    def test_change_group_auto_name(self):
        g = self._create_radius_group(name='test', description='test')
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        c = self._create_radius_groupcheck(
            group=g, attribute='Max-Daily-Session', op=':=', value='3600'
        )
        r = self._create_radius_groupreply(
            group=g, attribute='Reply-Message', op=':=', value='Login failed'
        )
        ug = self._create_radius_usergroup(user=u, group=g, priority=1)
        g.name = 'changed'
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
        g = self._create_radius_group(name='test', description='test')
        u = get_user_model().objects.create(
            username='test', email='test@test.org', password='test'
        )
        ug = self._create_radius_usergroup(user=u, group=g, priority=1)
        u.username = 'changed'
        u.full_clean()
        u.save()
        ug.refresh_from_db()
        # ensure related records have been updated
        self.assertEqual(ug.username, u.username)

    def test_delete(self):
        g = self._create_radius_group(name='test', description='test')
        g.delete()
        self.assertEqual(RadiusGroup.objects.all().count(), 4)

    def test_create_organization_default_group(self):
        new_org = self._create_org(**{'name': 'new org', 'slug': 'new-org'})
        queryset = RadiusGroup.objects.filter(organization=new_org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name='new-org-users').count(), 1)
        self.assertEqual(queryset.filter(name='new-org-power-users').count(), 1)
        self.assertEqual(queryset.filter(default=True).count(), 1)
        group = queryset.filter(default=True).first()
        self.assertEqual(group.radiusgroupcheck_set.count(), 2)
        self.assertEqual(group.radiusgroupreply_set.count(), 0)

    def test_rename_organization(self):
        default_org = Organization.objects.first()
        default_org.name = 'renamed'
        default_org.slug = default_org.name
        default_org.full_clean()
        default_org.save()
        queryset = RadiusGroup.objects.filter(organization=default_org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name='renamed-users').count(), 1)
        self.assertEqual(queryset.filter(name='renamed-power-users').count(), 1)

    def test_auto_prefix(self):
        org = self._create_org(**{'name': 'Cool WiFi', 'slug': 'cool-wifi'})
        rg = RadiusGroup(name='guests', organization=org)
        rg.full_clean()
        self.assertEqual(rg.name, f'{org.slug}-guests')

    def test_org_none(self):
        rg = RadiusGroup(name='guests')
        try:
            rg.full_clean()
        except ValidationError as e:
            self.assertIn('organization', e.message_dict)
        except Exception as e:
            name = e.__class__.__name__
            self.fail(f'ValidationError not raised, got {name}: {e} instead')
        else:
            self.fail('ValidationError not raised')

    def test_unique_attribute(self):
        org = self._create_org(**{'name': 'Cool WiFi', 'slug': 'cool-wifi'})
        rg = RadiusGroup(name='guests', organization=org)
        rg.save()
        with self.subTest('test radius group check unique attribute'):
            self._create_radius_groupcheck(
                group=rg, attribute='Max-Daily-Session', op=':=', value='3600'
            )
            try:
                self._create_radius_groupcheck(
                    group=rg, attribute='Max-Daily-Session', op=':=', value='3200'
                )
            except ValidationError as e:
                self.assertEqual(
                    {
                        'attribute': [
                            'Another group check for the same group and with the '
                            'same attribute already exists.'
                        ]
                    },
                    e.message_dict,
                )
            else:
                self.fail('ValidationError not raised')
        with self.subTest('test radius reply unique attribute'):
            self._create_radius_groupreply(
                group=rg, attribute='Reply-Message', op=':=', value='Login failed'
            )
            try:
                self._create_radius_groupreply(
                    group=rg, attribute='Reply-Message', op=':=', value='Login failed'
                )
            except ValidationError as e:
                self.assertEqual(
                    {
                        'attribute': [
                            'Another group reply for the same group and with the '
                            'same attribute already exists.'
                        ]
                    },
                    e.message_dict,
                )
            else:
                self.fail('ValidationError not raised')


class TestTransactionRadiusGroup(BaseTransactionTestCase):
    def test_new_user_default_group(self):
        user = get_user_model()(username='test', email='test@test.org', password='test')
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
        new_org = self._create_org(name='org2', slug='org2')
        self._create_org_user(user=user, organization=new_org)
        usergroup_set = user.radiususergroup_set.all()
        self.assertEqual(usergroup_set.count(), 2)
        new_ug = usergroup_set.filter(group__organization_id=new_org.pk).first()
        self.assertIsNotNone(new_ug)
        self.assertTrue(new_ug.group.default)


class TestRadiusBatch(BaseTestCase):
    def test_string_representation(self):
        radiusbatch = RadiusBatch(name='test')
        self.assertEqual(str(radiusbatch), 'test')

    def test_delete_method(self):
        radiusbatch = self._create_radius_batch(
            strategy='prefix', prefix='test-prefix16', name='test'
        )
        radiusbatch.prefix_add('test-prefix16', 5)
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
            self._create_radius_batch(strategy='csv', name='test')
        except ValidationError as e:
            self.assertIn('csvfile', e.message_dict)
        else:
            self.fail('ValidationError not raised')
        # missing prefix
        try:
            self._create_radius_batch(strategy='prefix', name='test')
        except ValidationError as e:
            self.assertIn('prefix', e.message_dict)
        else:
            self.fail('ValidationError not raised')
        # mixing strategies
        dummy_file = os.path.join(settings.PRIVATE_STORAGE_ROOT, 'test_csv2')
        open(dummy_file, 'a').close()
        try:
            self._create_radius_batch(
                strategy='prefix', prefix='prefix', csvfile=dummy_file, name='test'
            )
        except ValidationError as e:
            os.remove(dummy_file)
            self.assertIn('Mixing', str(e))
        else:
            os.remove(dummy_file)
            self.fail('ValidationError not raised')


class TestPrivateCsvFile(FileMixin, TestMultitenantAdminMixin, BaseTestCase):
    def setUp(self):
        reader = [['', 'cleartext$password', 'rohith@openwisp.com', 'Rohith', 'ASRK']]
        batch = self._create_radius_batch(
            name='test', strategy='csv', csvfile=self._get_csvfile(reader)
        )
        self.csvfile = batch.csvfile
        super().setUp()

    def _download_csv_file_status(self, status_code):
        response = self.client.get(
            reverse(
                'radius:serve_private_file',
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
        org2 = self._create_org(**{'name': 'test-org2', 'is_active': True})
        user2 = self._create_user(**{'username': 'test2', 'email': 'test2@test.co'})
        self._create_org_user(**{'organization': org2, 'user': user2})
        self.client.force_login(user2)
        self._download_csv_file_status(403)

    def test_authenticated_user_with_same_organization(self):
        self._get_org_user()
        self.client.force_login(self._get_user())
        self._download_csv_file_status(403)

    def test_staff_user_with_different_organization(self):
        org2 = self._create_org(**{'name': 'test-org2', 'is_active': True})
        user2 = self._create_operator(**{'username': 'test2', 'email': 'test2@test.co'})
        self._create_org_user(**{'organization': org2, 'user': user2})
        self.client.force_login(user2)
        self._download_csv_file_status(403)

    def test_operator_with_different_organization(self):
        org2 = self._create_org(**{'name': 'test-org2', 'is_active': True})
        user2 = self._create_operator(**{'username': 'test2', 'email': 'test2@test.co'})
        self._create_org_user(**{'organization': org2, 'user': user2, 'is_admin': True})
        self.client.force_login(user2)
        self._download_csv_file_status(403)

    def test_staff_user_with_same_organization(self):
        self._create_org_user(**{'user': self._get_operator()})
        self.client.force_login(self._get_operator())
        self._download_csv_file_status(403)

    def test_operator_with_same_organization(self):
        self._create_org_user(**{'user': self._get_operator(), 'is_admin': True})
        self.client.force_login(self._get_operator())
        self._download_csv_file_status(200)

    def test_superuser(self):
        user = self._get_admin()
        self.client.force_login(user)
        self._download_csv_file_status(200)

    def test_delete_csv_file(self):
        file_storage_backend = RadiusBatch.csvfile.field.storage

        with self.subTest('Test deleting object deletes file'):
            batch = self._create_radius_batch(
                name='test1', strategy='csv', csvfile=self.csvfile
            )
            file_name = batch.csvfile.name
            self.assertEqual(file_storage_backend.exists(file_name), True)
            batch.delete()
            self.assertEqual(file_storage_backend.exists(file_name), False)

        with self.subTest('Test deleting object with a deleted file'):
            batch = self._create_radius_batch(
                name='test2', strategy='csv', csvfile=self.csvfile
            )
            file_name = batch.csvfile.name
            # Delete the file from the storage backend before
            # deleting the object
            file_storage_backend.delete(file_name)
            self.assertNotEqual(batch.csvfile, None)
            batch.delete()

        with self.subTest('Test deleting object without csvfile'):
            batch = self._create_radius_batch(
                name='test3', strategy='prefix', prefix='test-prefix16'
            )
            batch.delete()


class TestChangeOfAuthorization(BaseTransactionTestCase):
    def _change_radius_user_group(self, user, organization):
        rad_user_group = user.radiususergroup_set.first()
        power_user_group = RadiusGroup.objects.get(
            organization=organization, name__contains='power-users'
        )
        rad_user_group.group = power_user_group
        rad_user_group.save()

    def _create_radius_accounting(self, user, organization, options=None):
        radiusaccounting_options = _RADACCT.copy()
        radiusaccounting_options.update(
            {
                'organization': organization,
                'unique_id': '113',
                'username': user.username,
            }
        )
        options = options or {}
        radiusaccounting_options.update(options)
        return super()._create_radius_accounting(**radiusaccounting_options)

    @mock.patch('openwisp_radius.tasks.perform_change_of_authorization.delay')
    def test_no_change_of_authorization_on_new_radius_user_group(self, mocked_task):
        # This method creates a new organization user
        # which has a RadiusUserGroup by default.
        user = self._get_user_with_org()
        self.assertEqual(user.radiususergroup_set.count(), 1)
        mocked_task.assert_not_called()

    @capture_any_output()
    @mock.patch('openwisp_radius.tasks.perform_change_of_authorization.delay')
    def test_no_change_of_authorization_on_closed_sessions(self, mocked_task):
        user = self._get_user_with_org()
        org = self._get_org()
        self._create_radius_accounting(
            user, org, options={'stop_time': '2022-11-04 10:50:00'}
        )
        self._change_radius_user_group(user, org)
        mocked_task.assert_not_called()

    @mock.patch.object(RadClient, 'perform_change_of_authorization', return_value=False)
    @mock.patch('logging.Logger.warning')
    def test_perform_change_of_authorization_celery_task_failures(
        self, mocked_logger, *args
    ):
        mocked_user_id = uuid4()
        mocked_old_group_id = uuid4()
        mocked_new_group_id = uuid4()
        org = self._get_org()
        user = self._get_user_with_org()
        user_group = RadiusGroup.objects.get(organization=org, name=f'{org.slug}-users')
        power_user_group = RadiusGroup.objects.get(
            organization=org, name=f'{org.slug}-power-users'
        )
        with self.subTest('Test user deleted after scheduling of task'):
            perform_change_of_authorization(
                user_id=mocked_user_id,
                old_group_id=mocked_old_group_id,
                new_group_id=mocked_new_group_id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to find user with "{mocked_user_id}" ID.'
                ' Skipping CoA operation.'
            )
        mocked_logger.reset_mock()

        with self.subTest('Test user session closed after scheduling of task'):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=mocked_old_group_id,
                new_group_id=mocked_new_group_id,
            )
            mocked_logger.assert_called_once_with(
                f'The user with "{user.id}" ID does not have any open'
                ' RadiusAccounting sessions. Skipping CoA operation.'
            )
        mocked_logger.reset_mock()

        session = self._create_radius_accounting(user, org)

        with self.subTest('Test new RadiusGroup was deleted after scheduling of task'):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group,
                new_group_id=mocked_new_group_id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to find RadiusGroup with "{mocked_new_group_id}".'
                ' Skipping CoA operation.'
            )
        mocked_logger.reset_mock()

        with self.subTest('Test NAS not found for the RadiusAccounting object'):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group.id,
                new_group_id=power_user_group.id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to find RADIUS secret for "{session.unique_id}"'
                ' RadiusAccounting object. Skipping CoA operation'
                ' for this session.'
            )
        mocked_logger.reset_mock()

        nas = self._create_nas(
            name='NAS',
            organization=org,
            short_name='test',
            type='Virtual',
            secret='testing123',
        )

        with self.subTest('Test NAS name does not contain IP network'):
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
                ' RadiusAccounting object. Skipping CoA operation'
                ' for this session.',
            )
        mocked_logger.reset_mock()

        nas.name = '127.0.0.1'
        nas.save()
        with self.subTest('Test RadClient encountered error while sending CoA packet'):
            perform_change_of_authorization(
                user_id=user.id,
                old_group_id=user_group.id,
                new_group_id=power_user_group.id,
            )
            mocked_logger.assert_called_once_with(
                f'Failed to perform CoA for "{session.unique_id}"'
                f' RadiusAccounting object of "{user}" user'
            )

    @mock.patch.object(RadClient, 'perform_change_of_authorization', return_value=True)
    @capture_stderr()
    def test_change_of_authorization(self, mocked_radclient, *args):
        org = self._get_org()
        user = self._get_user_with_org()
        nas_options = {
            'organization': org,
            'short_name': 'test',
            'type': 'Virtual',
            'secret': 'testing123',
        }
        self._create_nas(name='10.8.0.0/24', **nas_options)
        self._create_nas(name='172.16.0.0/24', **nas_options)
        rad_acct = self._create_radius_accounting(
            user, org, options={'nas_ip_address': '10.8.0.1'}
        )
        user_radiususergroup = user.radiususergroup_set.first()
        restricted_user_group = RadiusGroup.objects.get(
            organization=org, name=f'{org.slug}-users'
        )
        power_user_group = RadiusGroup.objects.get(
            organization=org, name=f'{org.slug}-power-users'
        )

        # RadiusGroup is changed to a power user.
        # Limitations set by the previous RadiusGroup
        # should be removed.
        user_radiususergroup.group = power_user_group
        user_radiususergroup.save()
        mocked_radclient.assert_called_with(
            {
                'User-Name': user.username,
                'Session-Timeout': '',
                'CoovaChilli-Max-Total-Octets': '',
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
                'User-Name': user.username,
                'Session-Timeout': '10800',
                'CoovaChilli-Max-Total-Octets': '3000000000',
            }
        )
        rad_acct.refresh_from_db()
        self.assertEqual(rad_acct.groupname, restricted_user_group.name)

    @mock.patch.object(RadClient, 'perform_change_of_authorization')
    def test_change_of_authorization_org_disabled(self, mocked_radclient):
        org = self._get_org()
        org.radius_settings.coa_enabled = False
        org.radius_settings.save()
        user = self._get_user_with_org()
        nas_options = {
            'organization': org,
            'short_name': 'test',
            'type': 'Virtual',
            'secret': 'testing123',
        }
        self._create_nas(name='10.8.0.0/24', **nas_options)
        self._create_radius_accounting(
            user, org, options={'nas_ip_address': '10.8.0.1'}
        )
        user_radiususergroup = user.radiususergroup_set.first()
        power_user_group = RadiusGroup.objects.get(
            organization=org, name=f'{org.slug}-power-users'
        )
        user_radiususergroup.group = power_user_group
        user_radiususergroup.save()
        mocked_radclient.assert_not_called()


del BaseTestCase
del BaseTransactionTestCase
