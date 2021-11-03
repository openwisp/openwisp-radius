import os
from unittest import mock
from uuid import UUID

import swapper
from django.apps.registry import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.urls import reverse
from netaddr import EUI, mac_unix

from openwisp_users.tests.utils import TestMultitenantAdminMixin
from openwisp_utils.tests import capture_any_output

from .. import settings as app_settings
from ..utils import (
    DEFAULT_SESSION_TIME_LIMIT,
    DEFAULT_SESSION_TRAFFIC_LIMIT,
    SESSION_TIME_ATTRIBUTE,
    SESSION_TRAFFIC_ATTRIBUTE,
    load_model,
)
from . import _RADACCT, FileMixin
from .mixins import BaseTestCase

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

    @capture_any_output()
    @mock.patch.object(
        app_settings,
        'CALLED_STATION_IDS',
        {
            'test-org': {
                'openvpn_config': [
                    {'host': '127.0.0.1', 'port': 7505, 'password': 'somepassword'}
                ],
                'unconverted_ids': ['AA-AA-AA-AA-AA-0A'],
            }
        },
    )
    @mock.patch.object(app_settings, 'OPENVPN_DATETIME_FORMAT', u'%Y-%m-%d %H:%M:%S')
    @mock.patch.object(app_settings, 'CONVERT_CALLED_STATION_ON_CREATE', True)
    def test_convert_called_station_id(self):
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

        with self.subTest('CALLED_STATAION_ID not defined for organization'):
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

    def test_auto_value(self):
        obj = self._create_radius_check(
            username='Monica', value='Cam0_liX', attribute='NT-Password', op=':='
        )
        self.assertEqual(obj.value, '891fc570507eef023cbfec043dd5f2b1')

    def test_create_radius_check_model(self):
        obj = RadiusCheck.objects.create(
            organization=self.default_org,
            username='Monica',
            new_value='Cam0_liX',
            attribute='NT-Password',
            op=':=',
        )
        self.assertEqual(obj.value, '891fc570507eef023cbfec043dd5f2b1')

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


class TestRadiusPostAuth(BaseTestCase):
    def test_string_representation(self):
        radiuspostauthentication = RadiusPostAuth(username='entry username')
        self.assertEqual(
            str(radiuspostauthentication), radiuspostauthentication.username
        )

    def test_id(self):
        radiuspostauth = RadiusPostAuth(username='test id')
        self.assertIsInstance(radiuspostauth.pk, UUID)


class TestOrganizationRadiusSettings(BaseTestCase):

    optional_settings_params = {
        'first_name': 'disabled',
        'last_name': 'allowed',
        'birth_date': 'disabled',
        'location': 'mandatory',
    }

    @mock.patch.object(
        app_settings,
        'OPTIONAL_REGISTRATION_FIELDS',
        optional_settings_params,
    )
    def test_org_settings_same_globally(self):
        org = self._get_org()
        org.radius_settings.first_name = 'disabled'
        org.radius_settings.last_name = 'allowed'
        org.radius_settings.location = 'mandatory'
        org.radius_settings.birth_date = 'disabled'
        org.radius_settings.full_clean()
        org.radius_settings.save()

        self.assertIsNone(org.radius_settings.first_name)
        self.assertIsNone(org.radius_settings.last_name)
        self.assertIsNone(org.radius_settings.location)
        self.assertIsNone(org.radius_settings.birth_date)

    def test_get_registration_enabled(self):
        rad_setting = self._get_org().radius_settings

        with self.subTest('Test registration enabled set to True'):
            rad_setting.registration_enabled = True
            self.assertEqual(rad_setting.get_registration_enabled(), True)

        with self.subTest('Test registration enabled set to False'):
            rad_setting.registration_enabled = False
            self.assertEqual(rad_setting.get_registration_enabled(), False)

        with self.subTest('Test registration enabled set to None'):
            rad_setting.registration_enabled = None
            self.assertEqual(
                rad_setting.get_registration_enabled(),
                app_settings.REGISTRATION_API_ENABLED,
            )


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
