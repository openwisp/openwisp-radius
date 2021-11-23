from unittest import mock

import swapper
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

from openwisp_users.tests.utils import TestMultitenantAdminMixin
from openwisp_utils.tests import capture_any_output

from .. import settings as app_settings
from ..base.models import _GET_IP_LIST_HELP_TEXT
from ..registration import register_registration_method, unregister_registration_method
from ..utils import load_model
from . import CallCommandMixin, FileMixin, PostParamsMixin
from .mixins import BaseTestCase

User = get_user_model()
Nas = load_model('Nas')
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
RadiusCheck = load_model('RadiusCheck')
RadiusToken = load_model('RadiusToken')
RadiusGroup = load_model('RadiusGroup')
RadiusReply = load_model('RadiusReply')
RegisteredUser = load_model('RegisteredUser')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
Organization = swapper.load_model('openwisp_users', 'Organization')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')

_RADCHECK_ENTRY = {
    'username': 'Monica',
    'value': 'Cam0_liX',
    'attribute': 'NT-Password',
}
_RADCHECK_ENTRY_PW_UPDATE = {
    'username': 'Monica',
    'new_value': 'Cam0_liX',
    'attribute': 'NT-Password',
}


class TestAdmin(
    BaseTestCase,
    FileMixin,
    CallCommandMixin,
    PostParamsMixin,
    TestMultitenantAdminMixin,
):

    app_label = 'openwisp_radius'
    app_label_users = 'openwisp_users'

    operator_permission_filters = [
        {'codename__endswith': 'nas'},
        {'codename__endswith': 'accounting'},
        {'codename__endswith': 'batch'},
        {'codename__endswith': 'check'},
        {'codename__endswith': 'reply'},
        {'codename__endswith': 'group'},
        {'codename__endswith': 'user'},
    ]

    _RADCHECK_ENTRY = {
        'username': 'Monica',
        'value': 'Cam0_liX',
        'attribute': 'NT-Password',
        'op': ':=',
    }

    @property
    def _RADCHECK_ENTRY_PW_UPDATE(self):
        return {
            'username': 'Monica',
            'new_value': 'Cam0_liX',
            'attribute': 'NT-Password',
            'op': ':=',
            'organization': str(self.default_org.pk),
        }

    def setUp(self):
        super().setUp()
        self._superuser_login()

    def test_nas_change(self):
        options = dict(
            name='fiore',
            short_name='ff',
            type='cisco',
            secret='d',
            ports='22',
            community='vmv',
            description='ciao',
            server='jsjs',
        )
        obj = self._create_nas(**options)
        response = self.client.get(
            reverse(f'admin:{self.app_label}_nas_change', args=[obj.pk])
        )
        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiusreply_change(self):
        options = dict(
            username='bob', attribute='Cleartext-Password', op=':=', value='passbob'
        )
        obj = self._create_radius_reply(**options)
        response = self.client.get(
            reverse(f'admin:{self.app_label}_radiusreply_change', args=[obj.pk])
        )

        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiusgroupreply_change(self):
        options = dict(
            groupname='students', attribute='Cleartext-Password', op=':=', value='PPP'
        )
        obj = self._create_radius_groupreply(**options)
        response = self.client.get(
            reverse(
                f'admin:{self.app_label}_radiusgroupreply_change',
                args=[obj.pk],
            )
        )

        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiusgroupcheck_change(self):
        options = dict(
            groupname='students', attribute='Cleartext-Password', op=':=', value='PPP'
        )
        obj = self._create_radius_groupcheck(**options)
        response = self.client.get(
            reverse(
                f'admin:{self.app_label}_radiusgroupcheck_change',
                args=[obj.pk],
            )
        )
        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiususergroup_change(self):
        options = dict(username='bob', groupname='students', priority='1')
        obj = self._create_radius_usergroup(**options)
        response = self.client.get(
            reverse(f'admin:{self.app_label}_radiususergroup_change', args=[obj.pk])
        )
        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    @capture_any_output()
    def test_radiusaccounting_change(self):
        options = dict(
            unique_id='2',
            username='bob',
            nas_ip_address='127.0.0.1',
            start_time='2017-06-10 10:50:00',
            stop_time='2017-06-10 11:50:00',
            session_time='5',
            authentication='RADIUS',
            connection_info_start='f',
            connection_info_stop='hgh',
            input_octets='1',
            output_octets='4',
            update_time='2017-03-10 11:50:00',
            session_id='1',
        )
        obj = self._create_radius_accounting(**options)
        response = self.client.get(
            reverse(
                f'admin:{self.app_label}_radiusaccounting_change',
                args=[obj.pk],
            )
        )
        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiusaccounting_changelist_readonly(self):
        self.assertFalse(app_settings.EDITABLE_ACCOUNTING)
        url = reverse(f'admin:{self.app_label}_radiusaccounting_changelist')
        response = self.client.get(url)
        self.assertNotContains(response, 'Add accounting')

    def test_postauth_change(self):
        options = dict(
            username='gino', password='ciao', reply='ghdhd', date='2017-09-02'
        )
        obj = self._create_radius_postauth(**options)
        url = reverse(f'admin:{self.app_label}_radiuspostauth_change', args=[obj.pk])
        response = self.client.get(url)
        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiuscheck_change(self):
        obj = self._create_radius_check(**self._RADCHECK_ENTRY)
        _RADCHECK = self._RADCHECK_ENTRY.copy()
        _RADCHECK['attribute'] = 'Cleartext-Password'
        self._create_radius_check(**_RADCHECK)
        _RADCHECK['attribute'] = 'LM-Password'
        self._create_radius_check(**_RADCHECK)
        _RADCHECK['attribute'] = 'NT-Password'
        self._create_radius_check(**_RADCHECK)
        _RADCHECK['attribute'] = 'MD5-Password'
        self._create_radius_check(**_RADCHECK)
        _RADCHECK['attribute'] = 'SMD5-Password'
        self._create_radius_check(**_RADCHECK)
        _RADCHECK['attribute'] = 'SHA-Password'
        self._create_radius_check(**_RADCHECK)
        _RADCHECK['attribute'] = 'SSHA-Password'
        self._create_radius_check(**_RADCHECK)
        _RADCHECK['attribute'] = 'Crypt-Password'
        self._create_radius_check(**_RADCHECK)
        data = self._RADCHECK_ENTRY_PW_UPDATE.copy()
        data['mode'] = 'custom'
        url = reverse(f'admin:{self.app_label}_radiuscheck_change', args=[obj.pk])
        response = self.client.post(url, data, follow=True)
        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiusbatch_change(self):
        obj = self._create_radius_batch(
            name='test',
            strategy='prefix',
            prefix='test-prefix4',
            expiration_date='1998-01-28',
        )
        url = reverse(f'admin:{self.app_label}_radiusbatch_change', args=[obj.pk])
        response = self.client.get(url)
        self.assertContains(response, 'ok')
        self.assertNotContains(response, 'errors')

    def test_radiusbatch_change_contains_pdf_download(self):
        obj = self._create_radius_batch(
            name='test-prefix17',
            strategy='prefix',
            prefix='test-prefix17',
            expiration_date='1998-01-28',
        )
        url = reverse(f'admin:{self.app_label}_radiusbatch_change', args=[obj.pk])
        response = self.client.get(url)
        pdf_url = reverse(
            'radius:download_rad_batch_pdf',
            args=[obj.organization.slug, obj.pk],
        )
        self.assertContains(response, pdf_url)

    def test_radiusbatch_change_not_contains_pdf_download(self):
        self.assertEqual(RadiusBatch.objects.count(), 0)
        add_url = reverse(f'admin:{self.app_label}_radiusbatch_add')
        data = self._get_csv_post_data()
        response = self.client.post(add_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(RadiusBatch.objects.count(), 1)
        obj = RadiusBatch.objects.first()
        url = reverse(f'admin:{self.app_label}_radiusbatch_change', args=[obj.pk])
        response = self.client.get(url)
        pdf_url = reverse(
            'radius:download_rad_batch_pdf',
            args=[obj.organization.pk, obj.pk],
        )
        self.assertNotContains(response, pdf_url)

    def test_radiuscheck_create_weak_passwd(self):
        _RADCHECK = self._RADCHECK_ENTRY_PW_UPDATE.copy()
        _RADCHECK['new_value'] = ''
        resp = self.client.post(
            reverse(f'admin:{self.app_label}_radiuscheck_add'),
            _RADCHECK,
            follow=True,
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'errors')

    def test_radiuscheck_create_disabled_hash(self):
        data = self._RADCHECK_ENTRY_PW_UPDATE.copy()
        data['attribute'] = 'Cleartext-Password'
        data['mode'] = 'custom'
        url = reverse(f'admin:{self.app_label}_radiuscheck_add')
        response = self.client.post(url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'errors')

    def test_radiuscheck_admin_save_model(self):
        obj = self._create_radius_check(**self._RADCHECK_ENTRY)
        change_url = reverse(
            f'admin:{self.app_label}_radiuscheck_change', args=[obj.pk]
        )
        # test admin save_model method
        data = self._RADCHECK_ENTRY_PW_UPDATE.copy()
        data['op'] = ':='
        data['mode'] = 'custom'
        response = self.client.post(change_url, data, follow=True)
        self.assertNotContains(response, 'errors')
        obj.refresh_from_db()
        self.assertNotEqual(obj.value, self._RADCHECK_ENTRY['value'])
        self.assertNotEqual(obj.value, data['new_value'])  # hashed
        # test also invalid password
        data['new_value'] = 'cionfrazZ'
        response = self.client.post(change_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'errors')
        self.assertContains(response, 'The secret must contain')

    def test_radiuscheck_enable_disable_action(self):
        self._create_radius_check(**self._RADCHECK_ENTRY)
        checks = RadiusCheck.objects.all().values_list('pk', flat=True)
        change_url = reverse(f'admin:{self.app_label}_radiuscheck_changelist')
        data = {'action': 'enable_action', '_selected_action': checks}
        self.client.post(change_url, data, follow=True)
        data = {'action': 'disable_action', '_selected_action': checks}
        self.client.post(change_url, data, follow=True)
        self.assertEqual(RadiusCheck.objects.filter(is_active=True).count(), 0)

    def test_radiuscheck_filter_duplicates_username(self):
        self._create_radius_check(**self._RADCHECK_ENTRY)
        self._create_radius_check(**self._RADCHECK_ENTRY)
        url = (
            reverse(f'admin:{self.app_label}_radiuscheck_changelist')
            + '?duplicates=username'
        )
        resp = self.client.get(url, follow=True)
        self.assertEqual(resp.status_code, 200)

    def test_radiuscheck_filter_duplicates_value(self):
        self._create_radius_check(**self._RADCHECK_ENTRY)
        self._create_radius_check(**self._RADCHECK_ENTRY)
        url = (
            reverse(f'admin:{self.app_label}_radiuscheck_changelist')
            + '?duplicates=value'
        )
        resp = self.client.get(url, follow=True)
        self.assertEqual(resp.status_code, 200)

    def test_radiuscheck_filter_expired(self):
        url = (
            reverse(f'admin:{self.app_label}_radiuscheck_changelist')
            + '?expired=expired'
        )
        resp = self.client.get(url, follow=True)
        self.assertEqual(resp.status_code, 200)

    def test_radiuscheck_filter_not_expired(self):
        url = (
            reverse(f'admin:{self.app_label}_radiuscheck_changelist')
            + '?expired=not_expired'
        )
        resp = self.client.get(url, follow=True)
        self.assertEqual(resp.status_code, 200)

    def test_nas_admin_save_model(self):
        options = {
            'name': 'test-NAS',
            'short_name': 'test',
            'type': 'Virtual',
            'ports': '12',
            'secret': 'testing123',
            'server': '',
            'community': '',
            'description': 'test',
        }
        nas = self._create_nas(**options)
        change_url = reverse(f'admin:{self.app_label}_nas_change', args=[nas.pk])
        options['custom_type'] = ''
        options['type'] = 'Other'
        options['organization'] = str(self.default_org.pk)
        options = self._get_post_defaults(options)
        response = self.client.post(change_url, options, follow=True)
        self.assertNotContains(response, 'error')
        nas.refresh_from_db()
        self.assertEqual(nas.type, 'Other')

    def test_radius_batch_save_model(self):
        self.assertEqual(RadiusBatch.objects.count(), 0)
        add_url = reverse(f'admin:{self.app_label}_radiusbatch_add')
        data = self._get_csv_post_data()
        response = self.client.post(add_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(RadiusBatch.objects.count(), 1)
        batch = RadiusBatch.objects.first()
        self.assertEqual(batch.users.count(), 3)
        change_url = reverse(
            f'admin:{self.app_label}_radiusbatch_change', args=[batch.pk]
        )
        response = self.client.post(change_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(batch.users.count(), 3)
        data = self._get_prefix_post_data()
        response = self.client.post(add_url, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(RadiusBatch.objects.count(), 2)
        data['number_of_users'] = -5
        response = self.client.post(add_url, data, follow=True)
        error_message = 'Ensure this value is greater than or equal to 1'
        self.assertTrue(error_message in str(response.content))

    def test_radiusbatch_no_of_users(self):
        r = self._create_radius_batch(
            name='test', strategy='prefix', prefix='test-prefix5'
        )
        path = reverse(f'admin:{self.app_label}_radiusbatch_change', args=[r.pk])
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'field-number_of_users')

    @capture_any_output()
    def test_radiusbatch_delete_methods(self):
        n = User.objects.count()
        options = dict(
            organization=self.default_org.slug, n=10, prefix='test-prefix6', name='test'
        )
        self._call_command('prefix_add_users', **options)
        self.assertEqual(User.objects.count() - n, 10)
        r = RadiusBatch.objects.first()
        delete_path = reverse(f'admin:{self.app_label}_radiusbatch_delete', args=[r.pk])
        response = self.client.post(delete_path, {'post': 'yes'}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.count() - n, 0)
        options['name'] = 'test1'
        self._call_command('prefix_add_users', **options)
        options['name'] = 'test2'
        self._call_command('prefix_add_users', **options)
        self.assertEqual(User.objects.count() - n, 20)
        changelist_path = reverse(f'admin:{self.app_label}_radiusbatch_changelist')
        p_keys = [x.pk for x in RadiusBatch.objects.all()]
        data = {'action': 'delete_selected_batches', '_selected_action': p_keys}
        response = self.client.post(changelist_path, data, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.count() - n, 0)

    def test_radius_batch_csv_help_text(self):
        add_url = reverse(f'admin:{self.app_label}_radiusbatch_add')
        response = self.client.get(add_url)
        docs_link = (
            'https://openwisp-radius.readthedocs.io/en/latest'
            '/user/importing_users.html'
        )
        self.assertContains(response, docs_link)

    def test_radiususergroup_inline_user(self):
        app_label = User._meta.app_label
        add_url = reverse(f'admin:{app_label}_user_add')
        response = self.client.get(add_url)
        label_id = 'radiususergroup_set-group'
        self.assertNotContains(response, label_id)
        user = User.objects.first()
        change_url = reverse(f'admin:{app_label}_user_change', args=[user.pk])
        response = self.client.get(change_url)
        self.assertContains(response, label_id)

    def _get_csv_post_data(self):
        path = self._get_path('static/test_batch.csv')
        csvfile = open(path, 'rt')
        data = {
            'expiration_date': '2019-03-20',
            'strategy': 'csv',
            'csvfile': csvfile,
            'name': 'test1',
            'organization': self.default_org.pk,
        }
        return data

    def _get_prefix_post_data(self):
        data = {
            'expiration_date': '2019-03-20',
            'strategy': 'prefix',
            'prefix': 'test-prefix12',
            'number_of_users': 10,
            'name': 'test2',
            'organization': self.default_org.pk,
        }
        return data

    def test_radius_group_delete_default_by_superuser(self):
        org = self._get_org()
        rg = RadiusGroup.objects
        default = rg.get(organization=org, default=True)
        url_name = f'admin:{self.app_label}_radiusgroup_delete'
        delete_url = reverse(url_name, args=[default.pk])
        response = self.client.get(delete_url)
        self.assertEqual(rg.filter(organization=org, default=True).count(), 1)
        self.assertEqual(response.status_code, 200)

    def test_radius_group_delete_default_by_non_superuser(self):
        org = self._get_org()
        user = self._get_admin()
        OrganizationUser.objects.create(organization=org, user=user, is_admin=True)
        user.is_superuser = False
        user.save()
        for permission in Permission.objects.all():
            user.user_permissions.add(permission)
        rg = RadiusGroup.objects
        default = rg.get(organization=org, default=True)
        url_name = f'admin:{self.app_label}_radiusgroup_delete'
        delete_url = reverse(url_name, args=[default.pk])
        response = self.client.get(delete_url)
        self.assertEqual(rg.filter(organization=org, default=True).count(), 1)
        self.assertEqual(response.status_code, 403)

    def test_radius_group_delete_selected_default(self):
        url = reverse(f'admin:{self.app_label}_radiusgroup_changelist')
        org = self._get_org()
        rg = RadiusGroup.objects
        default = rg.get(organization=org, default=True)
        response = self.client.post(
            url,
            {
                'action': 'delete_selected_groups',
                '_selected_action': str(default.pk),
                'select_across': '0',
                'index': '0',
                'post': 'yes',
            },
            follow=True,
        )
        self.assertEqual(rg.filter(organization=org, default=True).count(), 1)
        self.assertContains(response, 'error')
        self.assertContains(response, 'Cannot proceed with the delete')

    def test_organization_radsettings_freeradius_allowed_hosts(self):
        org = self._get_org()
        url = reverse(
            f'admin:{self.app_label_users}_organization_change',
            args=[org.pk],
        )
        radsetting = OrganizationRadiusSettings.objects.get(organization=org)
        form_data = org.__dict__
        form_data.update(
            {
                "owner-TOTAL_FORMS": "0",
                "owner-INITIAL_FORMS": "0",
                "owner-MIN_NUM_FORMS": "0",
                "owner-MAX_NUM_FORMS": "1",
                'radius_settings-TOTAL_FORMS': '1',
                'radius_settings-INITIAL_FORMS': '1',
                'radius_settings-MIN_NUM_FORMS': '0',
                'radius_settings-MAX_NUM_FORMS': '1',
                'radius_settings-0-token': '12345',
                'radius_settings-0-sms_sender': '',
                'radius_settings-0-sms_meta_data': 'null',
                'radius_settings-0-id': radsetting.pk,
                'radius_settings-0-organization': org.pk,
            }
        )
        with self.subTest('Return FREERADIUS_ALLOWED_HOSTS back'):
            form_data.update(
                {'radius_settings-0-freeradius_allowed_hosts': '127.0.0.1'}
            )
            response = self.client.post(url, form_data)
            self.assertEqual(response.status_code, 302)
            radsetting.refresh_from_db()
            # This should fail when the value of FREERADIUS_ALLOWED_HOSTS is
            # stored in the model as well.
            self.assertEqual(radsetting.freeradius_allowed_hosts, None)
        with self.subTest('Valid IP list'):
            form_data.update(
                {'radius_settings-0-freeradius_allowed_hosts': '127.0.0.45'}
            )
            response = self.client.post(url, form_data)
            self.assertEqual(response.status_code, 302)
            radsetting.refresh_from_db()
            self.assertEqual(radsetting.freeradius_allowed_hosts, '127.0.0.45')
        with self.subTest('Empty IP list with FREERADIUS_ALLOWED_HOSTS'):
            form_data.update({'radius_settings-0-freeradius_allowed_hosts': ''})
            response = self.client.post(url, form_data)
            self.assertEqual(response.status_code, 302)
            radsetting.refresh_from_db()
            self.assertEqual(radsetting.freeradius_allowed_hosts, '')
        with self.subTest('Empty IP list without FREERADIUS_ALLOWED_HOSTS'):
            with mock.patch('openwisp_radius.settings.FREERADIUS_ALLOWED_HOSTS', []):
                response = self.client.post(url, form_data)
            self.assertContains(
                response,
                _(
                    'Cannot be empty when the settings value for '
                    '`OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS` is not provided.'
                ),
            )
        with self.subTest('Invalid IP list'):
            form_data.update(
                {'radius_settings-0-freeradius_allowed_hosts': '123.246.512.12'}
            )
            response = self.client.post(url, form_data)
            self.assertContains(
                response,
                _(
                    'Invalid input. Please enter valid ip addresses '
                    'or subnets separated by comma. (no spaces)'
                ),
            )

    def test_radsettings_freeradius_allowed_hosts_help_text(self):
        url = reverse(f'admin:{self.app_label_users}_organization_add')
        response = self.client.get(url)
        self.assertContains(response, _GET_IP_LIST_HELP_TEXT)

    def test_radius_group_delete_selected_non_default(self):
        url = reverse(f'admin:{self.app_label}_radiusgroup_changelist')
        org = self._get_org()
        rg = RadiusGroup.objects
        non_default = rg.get(organization=org, default=False)
        response = self.client.post(
            url,
            {
                'action': 'delete_selected_groups',
                '_selected_action': str(non_default.pk),
                'select_across': '0',
                'index': '0',
                'post': 'yes',
            },
            follow=True,
        )
        self.assertNotContains(response, 'error')
        self.assertEqual(rg.filter(organization=org, default=False).count(), 0)

    def test_batch_user_creation_form(self):
        url = reverse(f'admin:{self.app_label}_radiusbatch_add')
        response = self.client.post(
            url,
            {
                'strategy': 'prefix',
                'prefix': 'test_prefix16',
                'name': 'test_name',
                'csvfile': '',
                'number_of_users': '',
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'errors field-number_of_users')

    def _login(self, username='admin', password='tester'):
        self.client.force_login(User.objects.get(username=username))

    def _get_url(self, url, user=False, group=False, model_name=None):
        response = self.client.get(url)
        autocomplete_url = f'/admin/autocomplete/?app_label={self.app_label}'
        user_url = f'/admin/{self.app_label_users}/user/autocomplete/'
        group_url = f'/admin/{self.app_label}/radiusgroup/autocomplete/'
        if model_name:
            autocomplete_url += f'&model_name={model_name}'
        if user:
            autocomplete_url += '&field_name=user'
        if group:
            autocomplete_url += '&field_name=group'
        if user_url in str(response.content) and user:
            return user_url
        if group_url in str(response.content) and group:
            return group_url
        return autocomplete_url

    def test_radiusbatch_org_user(self):
        self.assertEqual(RadiusBatch.objects.count(), 0)
        add_url = reverse(f'admin:{self.app_label}_radiusbatch_add')
        data = self._get_csv_post_data()
        self.client.post(add_url, data, follow=True)
        self.assertEqual(OrganizationUser.objects.all().count(), 3)
        for u in OrganizationUser.objects.all():
            self.assertEqual(u.organization, RadiusBatch.objects.first().organization)

    def _create_multitenancy_test_env(
        self, usergroup=False, groupcheck=False, groupreply=False
    ):
        org1 = self._create_org(**{'name': 'testorg1', 'slug': 'testorg1'})
        org2 = self._create_org(**{'name': 'testorg2', 'slug': 'testorg2'})
        inactive = self._create_org(
            **{'name': 'inactive org', 'is_active': False, 'slug': 'inactive-org'}
        )
        operator = TestMultitenantAdminMixin()._create_operator()
        self._create_org_user(organization=org1, user=operator, is_admin=True)
        self._create_org_user(organization=inactive, user=operator, is_admin=True)
        user11 = User.objects.create(
            username='user11', password='User_11', email='user11@g.com'
        )
        user22 = User.objects.create(
            username='user22', password='User_22', email='user22@g.com'
        )
        user33 = User.objects.create(
            username='user33', password='User_33', email='user33@g.com'
        )
        self._create_org_user(organization=org1, user=user11, is_admin=True)
        self._create_org_user(organization=org2, user=user22, is_admin=True)
        self._create_org_user(organization=inactive, user=user33, is_admin=True)
        rc1 = RadiusCheck.objects.create(
            username='user1', attribute='NT-Password', value='User_1', organization=org1
        )
        rc2 = RadiusCheck.objects.create(
            username='user2', attribute='NT-Password', value='User_2', organization=org2
        )
        rc3 = RadiusCheck.objects.create(
            username='user3',
            attribute='NT-Password',
            value='User_3',
            organization=inactive,
        )
        rr1 = RadiusReply.objects.create(
            username='user1', attribute='NT-Password', value='User_1', organization=org1
        )
        rr2 = RadiusReply.objects.create(
            username='user2', attribute='NT-Password', value='User_2', organization=org2
        )
        rr3 = RadiusReply.objects.create(
            username='user3',
            attribute='NT-Password',
            value='User_3',
            organization=inactive,
        )
        rg1 = RadiusGroup.objects.create(name='radiusgroup1org', organization=org1)
        rg2 = RadiusGroup.objects.create(name='radiusgroup2org', organization=org2)
        rg3 = RadiusGroup.objects.create(
            name='radiusgroup3-inactive', organization=inactive
        )
        nas1 = Nas.objects.create(
            name='nas1org',
            short_name='nas1org',
            secret='nas1-secret',
            type='Other',
            organization=org1,
        )
        nas2 = Nas.objects.create(
            name='nas2org',
            short_name='nas2org',
            secret='nas2-secret',
            type='Other',
            organization=org2,
        )
        nas3 = Nas.objects.create(
            name='nas3-inactive',
            short_name='nas3org',
            secret='nas3-secret',
            type='Other',
            organization=inactive,
        )
        ra1 = RadiusAccounting.objects.create(
            username='user1',
            nas_ip_address='172.16.64.92',
            unique_id='001',
            session_id='001',
            organization=org1,
        )
        ra2 = RadiusAccounting.objects.create(
            username='user2',
            nas_ip_address='172.16.64.93',
            unique_id='002',
            session_id='002',
            organization=org2,
        )
        ra3 = RadiusAccounting.objects.create(
            username='user3',
            nas_ip_address='172.16.64.95',
            unique_id='003',
            session_id='003',
            organization=inactive,
        )
        rb1 = RadiusBatch.objects.create(
            name='radiusbacth1org',
            organization=org1,
            strategy='prefix',
            prefix='test-prefix1',
        )
        rb2 = RadiusBatch.objects.create(
            name='radiusbacth2org',
            organization=org2,
            strategy='prefix',
            prefix='test-prefix2',
        )
        rb3 = RadiusBatch.objects.create(
            name='radiusbacth3-inactive',
            organization=inactive,
            strategy='prefix',
            prefix='test-prefix3',
        )
        data = dict(
            rb1=rb1,
            rb2=rb2,
            rb3=rb3,
            nas1=nas1,
            nas2=nas2,
            nas3=nas3,
            rg1=rg1,
            rg2=rg2,
            rg3=rg3,
            rr1=rr1,
            rr2=rr2,
            rr3=rr3,
            rc1=rc1,
            rc2=rc2,
            rc3=rc3,
            ra1=ra1,
            ra2=ra2,
            ra3=ra3,
            org1=org1,
            org2=org2,
            inactive=inactive,
            user11=user11,
            user22=user22,
            user33=user33,
            operator=operator,
        )
        if usergroup:
            ug1 = self._create_radius_usergroup(user=user11, group=rg1)
            ug2 = self._create_radius_usergroup(user=user22, group=rg2)
            ug3 = self._create_radius_usergroup(user=user33, group=rg3)
            data.update(dict(ug1=ug1, ug2=ug2, ug3=ug3))
        if groupcheck:
            gc1 = self._create_radius_groupcheck(
                group=rg1, attribute='test-attr1', value='1'
            )
            gc2 = self._create_radius_groupcheck(
                group=rg2, attribute='test-attr2', value='2'
            )
            gc3 = self._create_radius_groupcheck(
                group=rg3, attribute='test-attr3', value='3'
            )
            data.update(dict(gc1=gc1, gc2=gc2, gc3=gc3))
        if groupreply:
            gr1 = self._create_radius_groupreply(
                group=rg1, attribute='test-attr1', value='1'
            )
            gr2 = self._create_radius_groupreply(
                group=rg2, attribute='test-attr2', value='2'
            )
            gr3 = self._create_radius_groupreply(
                group=rg3, attribute='test-attr3', value='3'
            )
            data.update(dict(gr1=gr1, gr2=gr2, gr3=gr3))
        return data

    def test_radiuscheck_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiuscheck_changelist'),
            visible=[data['rc1'].username, data['org1'].name],
            hidden=[data['rc2'].username, data['org2'].name, data['rc3'].username],
        )

    def test_radiuscheck_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiuscheck_add'),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True,
        )

    @capture_any_output()
    def test_radiuscheck_user_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=self._get_url(
                reverse(f'admin:{self.app_label}_radiuscheck_add'),
                user=True,
                model_name='radiuscheck',
            ),
            visible=[data['user11']],
            hidden=[data['user22']],
        )

    def test_radiusreply_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusreply_changelist'),
            visible=[data['rr1'].username, data['org1'].name],
            hidden=[data['rr2'].username, data['org2'], data['rr3'].username],
        )

    def test_radiusreply_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusreply_add'),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True,
        )

    @capture_any_output()
    def test_radiusreply_user_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=self._get_url(
                reverse(f'admin:{self.app_label}_radiusreply_add'),
                user=True,
                model_name='radiusreply',
            ),
            visible=[data['user11']],
            hidden=[data['user22']],
        )

    def test_radiusgroup_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusgroup_changelist'),
            visible=[data['rg1'].name, data['org1'].name],
            hidden=[data['org2'].name, data['rg2'].name, data['rg3'].name],
        )

    def test_radiusgroup_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=(reverse(f'admin:{self.app_label}_radiusgroup_add')),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True,
        )

    def test_nas_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_nas_changelist'),
            visible=[data['nas1'].name, data['org1'].name],
            hidden=[data['nas2'].name, data['org2'].name, data['nas3'].name],
        )

    def test_nas_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_nas_add'),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True,
        )

    def test_radiusaccounting_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusaccounting_changelist'),
            visible=[data['ra1'].username, data['org1'].name],
            hidden=[data['ra2'].username, data['org2'].name, data['ra3'].username],
        )

    def test_radiusbatch_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusbatch_changelist'),
            visible=[data['rb1'].name, data['org1'].name],
            hidden=[data['rb2'].name, data['org2'].name, data['rb3'].name],
        )

    def test_radiusbatch_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusbatch_add'),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True,
        )

    def test_radius_usergroup_queryset(self):
        data = self._create_multitenancy_test_env(usergroup=True)
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiususergroup_changelist'),
            visible=[data['ug1'].group, data['ug1'].user],
            hidden=[data['ug2'].group, data['ug2'].user, data['ug3'].user],
        )

    def test_radius_usergroup_group_fk_queryset(self):
        data = self._create_multitenancy_test_env(usergroup=True)
        self._test_multitenant_admin(
            url=self._get_url(
                reverse(f'admin:{self.app_label}_radiususergroup_add'),
                group=True,
                model_name='radiususergroup',
            ),
            visible=[data['rg1']],
            hidden=[data['rg2']],
        )

    @capture_any_output()
    def test_radius_usergroup_user_fk_queryset(self):
        data = self._create_multitenancy_test_env(usergroup=True)
        self._test_multitenant_admin(
            url=self._get_url(
                reverse(f'admin:{self.app_label}_radiususergroup_add'),
                user=True,
                model_name='radiususergroup',
            ),
            visible=[data['user11']],
            hidden=[data['user22']],
        )

    def test_radius_groupcheck_queryset(self):
        data = self._create_multitenancy_test_env(groupcheck=True)
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusgroupcheck_changelist'),
            visible=[data['gc1'].group, data['gc1'].attribute],
            hidden=[data['gc2'].group, data['gc2'].attribute, data['gc3']],
        )

    def test_radius_groupcheck_group_fk_queryset(self):
        data = self._create_multitenancy_test_env(groupcheck=True)
        self._test_multitenant_admin(
            url=self._get_url(
                reverse(f'admin:{self.app_label}_radiusgroupcheck_add'),
                group=True,
                model_name='radiusgroupcheck',
            ),
            visible=[data['rg1']],
            hidden=[data['rg2']],
        )

    def test_radius_groupreply_queryset(self):
        data = self._create_multitenancy_test_env(groupreply=True)
        self._test_multitenant_admin(
            url=reverse(f'admin:{self.app_label}_radiusgroupreply_changelist'),
            visible=[data['gr1'].group, data['gr1'].attribute],
            hidden=[data['gr2'].group, data['gr2'].attribute, data['gr3']],
        )

    def test_radius_groupreply_group_fk_queryset(self):
        data = self._create_multitenancy_test_env(groupreply=True)
        self._test_multitenant_admin(
            url=self._get_url(
                reverse(f'admin:{self.app_label}_radiusgroupreply_add'),
                group=True,
                model_name='radiusgroupreply',
            ),
            visible=[data['rg1']],
            hidden=[data['rg2']],
        )

    @capture_any_output()
    def test_radiustoken_delete_queryset(self, *args, **kwargs):
        # Create & check radius token works
        self._get_org_user()
        radtoken, _ = RadiusToken.objects.get_or_create(
            user=self._get_user(), organization=self._get_org(), can_auth=True
        )
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'tester', 'password': 'tester'},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(cache.get('rt-tester'), str(self.default_org.pk))
        # Delete radius token
        response = self.client.post(
            reverse('admin:{0}_radiustoken_changelist'.format(self.app_label)),
            {
                'action': 'delete_selected',
                '_selected_action': [radtoken.pk],
                'post': 'yes',
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        # Test delete queryset deleted cache
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'tester', 'password': 'tester'},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(cache.get('rt-tester'), None)

    def test_organization_radsettings_allowed_mobile_prefixes(self):
        org = self._get_org()
        url = reverse(
            f'admin:{self.app_label_users}_organization_change',
            args=[org.pk],
        )
        radsetting = OrganizationRadiusSettings.objects.get(organization=org)
        form_data = org.__dict__
        form_data.update(
            {
                "owner-TOTAL_FORMS": "0",
                "owner-INITIAL_FORMS": "0",
                "owner-MIN_NUM_FORMS": "0",
                "owner-MAX_NUM_FORMS": "1",
                'radius_settings-TOTAL_FORMS': '1',
                'radius_settings-INITIAL_FORMS': '1',
                'radius_settings-MIN_NUM_FORMS': '0',
                'radius_settings-MAX_NUM_FORMS': '1',
                'radius_settings-0-token': '12345',
                'radius_settings-0-sms_sender': '',
                'radius_settings-0-sms_meta_data': 'null',
                'radius_settings-0-id': radsetting.pk,
                'radius_settings-0-organization': org.pk,
            }
        )
        with self.subTest('Valid mobile prefix list'):
            form_data.update({'radius_settings-0-allowed_mobile_prefixes': '+51,+44'})
            response = self.client.post(url, form_data)
            self.assertEqual(response.status_code, 302)
            radsetting.refresh_from_db()
            self.assertEqual(radsetting.allowed_mobile_prefixes, '+51,+44')
        with self.subTest('Invalid list'):
            form_data.update({'radius_settings-0-allowed_mobile_prefixes': '+51, +44'})
            response = self.client.post(url, form_data)
            self.assertContains(
                response,
                _(
                    'Invalid input. Please enter valid mobile '
                    'prefixes separated by comma. (no spaces)'
                ),
            )

        with self.subTest('Invalid list with spaces'):
            form_data.update({'radius_settings-0-allowed_mobile_prefixes': ', , , '})
            response = self.client.post(url, form_data)
            self.assertContains(
                response,
                _(
                    'Invalid input. Please enter valid mobile '
                    'prefixes separated by comma. (no spaces)'
                ),
            )

        with self.subTest('Invalid list with invalid prefix'):
            form_data.update(
                {'radius_settings-0-allowed_mobile_prefixes': '+12345,+777700012'}
            )
            response = self.client.post(url, form_data)
            self.assertContains(
                response,
                _(
                    'Invalid input. Please enter valid mobile '
                    'prefixes separated by comma. (no spaces)'
                ),
            )

    def test_inline_registered_user(self):
        app_label = User._meta.app_label
        user = User.objects.first()
        url = reverse(f'admin:{app_label}_user_change', args=[user.pk])

        with self.subTest('Inline exists'):
            response = self.client.get(url)
            self.assertContains(response, 'id_registered_user-TOTAL_FORMS')

        with self.subTest('Register new choice'):
            register_registration_method('national_id', 'National ID')
            response = self.client.get(url)
            self.assertContains(response, '<option value="national_id">National ID')

        # not strictly an admin test but grouped here for convenience
        with self.subTest('test duplicate register'):
            with self.assertRaises(ImproperlyConfigured):
                register_registration_method('national_id', 'National ID')

        # not strictly an admin test but grouped here for convenience
        with self.subTest('test fail_loud=False'):
            try:
                register_registration_method(
                    'national_id', 'National ID', fail_loud=False
                )
            except ImproperlyConfigured:
                self.fail('Unexpected failure')

        with self.subTest('Unregister existing choice'):
            unregister_registration_method('national_id')
            response = self.client.get(url)
            self.assertNotContains(response, '<option value="national_id">National ID')

        # not strictly an admin test but grouped here for convenience
        with self.assertRaises(ImproperlyConfigured):
            unregister_registration_method('national_id')

        # not strictly an admin test but grouped here for convenience
        with self.subTest('test fail_loud=False'):
            try:
                unregister_registration_method('national_id', fail_loud=False)
            except ImproperlyConfigured:
                self.fail('Unexpected failure')

        # not strictly an admin test but grouped here for convenience
        with self.subTest('test strong_identity=True'):
            register_registration_method('passport', 'Passport', strong_identity=True)
            self.assertNotIn('passport', RegisteredUser._weak_verification_methods)
            unregister_registration_method('passport')

        # not strictly an admin test but grouped here for convenience
        with self.subTest('test strong_identity=False'):
            register_registration_method('github', 'GitHub', strong_identity=False)
            self.assertIn('github', RegisteredUser._weak_verification_methods)

    def test_get_is_verified_user_admin_list(self):
        unknown = User.objects.first()
        self.assertIsNotNone(unknown)
        verified = User(
            username='verified', password='verified', email='verified@test.com'
        )
        verified.full_clean()
        verified.save()
        RegisteredUser.objects.create(
            user=verified, method='mobile_phone', is_verified=True
        )
        unverified = User.objects.create(
            username='unverified', password='unverified', email='unverified@test.com'
        )
        unverified.full_clean()
        unverified.save()
        RegisteredUser.objects.create(
            user=unverified, method='mobile_phone', is_verified=False
        )
        app_label = User._meta.app_label
        url = reverse(f'admin:{app_label}_user_changelist')
        response = self.client.get(url)

        def get_expected_html(value):
            return (
                '<td class="field-get_is_verified"><img src="/static/admin/img/icon-'
                f'{value}.svg" alt="{value}">'
            )

        self.assertContains(response, get_expected_html('yes'))
        self.assertContains(response, get_expected_html('no'))
        self.assertContains(response, get_expected_html('unknown'))

    def test_registered_user_filter(self):
        unknown = User.objects.first()
        self.assertIsNotNone(unknown)
        verified = User(
            username='verified', password='verified', email='verified@test.com'
        )
        verified.full_clean()
        verified.save()
        RegisteredUser.objects.create(
            user=verified, method='mobile_phone', is_verified=True
        )
        unverified = User.objects.create(
            username='unverified', password='unverified', email='unverified@test.com'
        )
        unverified.full_clean()
        unverified.save()
        RegisteredUser.objects.create(
            user=unverified, method='mobile_phone', is_verified=False
        )
        app_label = User._meta.app_label
        url = reverse(f'admin:{app_label}_user_changelist')

        def get_expected_html(value):
            return (
                '<td class="field-get_is_verified"><img src="/static/admin/img/icon-'
                f'{value}.svg" alt="{value}">'
            )

        with self.subTest('Verified users filter'):
            response = self.client.get(url, {'is_verified': 'true'})
            self.assertContains(response, get_expected_html('yes'))
            self.assertNotContains(response, get_expected_html('no'))
            self.assertNotContains(response, get_expected_html('unknown'))

        with self.subTest('Unverified users filter'):
            response = self.client.get(f'{url}?is_verified=false')
            self.assertNotContains(response, get_expected_html('yes'))
            self.assertContains(response, get_expected_html('no'))
            self.assertNotContains(response, get_expected_html('unknown'))

        with self.subTest('Unknown verification users filter'):
            response = self.client.get(f'{url}?is_verified=unknown')
            self.assertNotContains(response, get_expected_html('yes'))
            self.assertNotContains(response, get_expected_html('no'))
            self.assertContains(response, get_expected_html('unknown'))

    def test_admin_menu_groups(self):
        # Test menu group (openwisp-utils menu group) for RadiusAccounting, RadiusBatch,
        # RadiusCheck, RadiusGroup, Nas, RadiusPostAuth, RadiusToken, and RadiusReply
        # models

        self._login()
        models = [
            'radiusaccounting',
            'radiusbatch',
            'radiuscheck',
            'radiusgroup',
            'nas',
            'radiuspostauth',
            'radiustoken',
            'radiusreply',
        ]
        response = self.client.get(reverse('admin:index'))
        for model in models:
            with self.subTest(f'test menu group link for {model} model'):
                url = reverse(f'admin:{self.app_label}_{model}_changelist')
                self.assertContains(response, f'class="mg-link" href="{url}"')
        with self.subTest('test radius group is registered'):
            html = '<div class="mg-dropdown-label">RADIUS </div>'
            self.assertContains(response, html, html=True)
