from unittest import mock

import swapper
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.urls import reverse

from openwisp_utils.tests import capture_any_output

from ... import settings as app_settings
from ...utils import load_model
from ..mixins import ApiTokenMixin, BaseTestCase

User = get_user_model()
PhoneToken = load_model('PhoneToken')
RadiusToken = load_model('RadiusToken')
RadiusAccounting = load_model('RadiusAccounting')
RadiusPostAuth = load_model('RadiusPostAuth')
RadiusBatch = load_model('RadiusBatch')
RadiusUserGroup = load_model('RadiusUserGroup')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
Organization = swapper.load_model('openwisp_users', 'Organization')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')


class TestApiReject(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        app_settings.API_AUTHORIZE_REJECT = True

    @classmethod
    def tearDownClass(cls):
        app_settings.API_AUTHORIZE_REJECT = False

    def test_disabled_user_login(self):
        User.objects.create_user(username='barbar', password='molly', is_active=False)
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'barbar', 'password': 'molly'},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, {'control:Auth-Type': 'Reject'})

    def test_authorize_401(self):
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'baldo', 'password': 'ugo'},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, {'control:Auth-Type': 'Reject'})


class TestAutoGroupname(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app_settings.API_ACCOUNTING_AUTO_GROUP = True

    def test_automatic_groupname_account_enabled(self):
        user = User.objects.create_superuser(
            username='username1', email='admin@admin.com', password='qwertyuiop'
        )
        usergroup1 = self._create_radius_usergroup(
            groupname='group1', priority=2, username='testgroup1'
        )
        usergroup2 = self._create_radius_usergroup(
            groupname='group2', priority=1, username='testgroup2'
        )
        user.radiususergroup_set.set([usergroup1, usergroup2])
        self.client.post(
            f'{reverse("radius:accounting")}{self.token_querystring}',
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': 'username1',
            },
        )
        accounting_created = RadiusAccounting.objects.get(username='username1')
        self.assertEqual(accounting_created.groupname, 'group2')
        user.delete()


class TestAutoGroupnameDisabled(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app_settings.API_ACCOUNTING_AUTO_GROUP = False

    def test_account_creation_api_automatic_groupname_disabled(self):
        user = User.objects.create_superuser(
            username='username1', email='admin@admin.com', password='qwertyuiop'
        )
        usergroup1 = self._create_radius_usergroup(
            groupname='group1', priority=2, username='testgroup1'
        )
        usergroup2 = self._create_radius_usergroup(
            groupname='group2', priority=1, username='testgroup2'
        )
        user.radiususergroup_set.set([usergroup1, usergroup2])
        url = f'{reverse("radius:accounting")}{self.token_querystring}'
        self.client.post(
            url,
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': 'username1',
            },
        )
        accounting_created = RadiusAccounting.objects.get(username='username1')
        self.assertIsNone(accounting_created.groupname)
        user.delete()


class TestClientIpApi(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        self._get_org_user()
        self.params = {'username': 'tester', 'password': 'tester'}
        self.fail_msg = (
            'Request rejected: Client IP address (127.0.0.1) is not in '
            'the list of IP addresses allowed to consume the freeradius API.'
        )
        self.freeradius_hosts_path = 'openwisp_radius.settings.FREERADIUS_ALLOWED_HOSTS'
        self.client.post(
            reverse('radius:user_auth_token', args=[self._get_org().slug]), self.params
        )

    def test_cache(self):
        def authorize_and_asset(numOfQueries, ip_list):
            with self.assertNumQueries(numOfQueries):
                response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})
            self.assertEqual(cache.get(f'ip-{org.pk}'), ip_list)

        cache.clear()
        org = self._get_org()
        self.assertEqual(cache.get(f'ip-{org.pk}'), None)
        with self.subTest('Without Cache'):
            authorize_and_asset(6, [])
        with self.subTest('With Cache'):
            authorize_and_asset(4, [])
        with self.subTest('Organization Settings Updated'):
            radsetting = OrganizationRadiusSettings.objects.get(organization=org)
            radsetting.freeradius_allowed_hosts = '127.0.0.1,192.0.2.0'
            radsetting.save()
            authorize_and_asset(4, ['127.0.0.1', '192.0.2.0'])
        with self.subTest('Cache Deleted'):
            cache.clear()
            authorize_and_asset(6, ['127.0.0.1', '192.0.2.0'])

    def test_ip_from_setting_valid(self):
        response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    @capture_any_output()
    def test_ip_from_setting_invalid(self):
        test_fail_msg = (
            'Request rejected: (localhost) in organization settings or '
            'settings.py is not a valid IP address. Please contact administrator.'
        )
        with mock.patch(self.freeradius_hosts_path, ['localhost']):
            response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], test_fail_msg)

    def test_ip_from_radsetting_valid(self):
        with mock.patch(self.freeradius_hosts_path, []):
            radsetting = OrganizationRadiusSettings.objects.get(
                organization=self._get_org()
            )
        radsetting.freeradius_allowed_hosts = '127.0.0.1'
        radsetting.save()
        response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    @capture_any_output()
    def test_ip_from_radsetting_invalid(self):
        test_fail_msg = (
            'Request rejected: (127.0.0.500) in organization settings or '
            'settings.py is not a valid IP address. Please contact administrator.'
        )
        radsetting = OrganizationRadiusSettings.objects.get(
            organization=self._get_org()
        )
        radsetting.freeradius_allowed_hosts = '127.0.0.500'
        radsetting.save()
        with mock.patch(self.freeradius_hosts_path, []):
            response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], test_fail_msg)

    @capture_any_output()
    def test_ip_from_radsetting_not_exist(self):
        org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        self._create_org_user(**{'organization': org2})
        self.client.post(reverse('radius:user_auth_token', args=[org2.slug]))
        with self.subTest('FREERADIUS_ALLOWED_HOSTS is 127.0.0.1'):
            response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})
        with self.subTest('Empty Settings'), mock.patch(self.freeradius_hosts_path, []):
            response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.data['detail'], self.fail_msg)


class TestOgranizationRadiusSettings(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        cache.clear()
        self.org = self._create_org(**{'name': 'test', 'slug': 'test'})

    def test_string_representation(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(str(rad), rad.organization.name)

    def test_default_token(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(32, len(rad.token))

    def test_bad_token(self):
        try:
            rad = OrganizationRadiusSettings(
                token='bad.t.o.k.e.n', organization=self.org
            )
            rad.full_clean()
        except ValidationError as e:
            self.assertEqual(
                e.message_dict['token'][0],
                'This value must not contain spaces, dots or slashes.',
            )

    def test_cache(self):
        rad = OrganizationRadiusSettings.objects.create(
            token='12345', organization=self.org
        )
        self._get_org_user()
        token_querystring = f'?token={rad.token}&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        # Clear cache before sending request
        cache.clear()
        self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        with self.subTest('Cache & token match'):
            self.assertEqual(rad.token, cache.get(rad.organization.pk))
        with self.subTest('Force changed corrupt cache returns 403'):
            cache.set(rad.organization.pk, 'wrong-value')
            response = self.client.post(
                post_url, {'username': 'tester', 'password': 'tester'}
            )
            self.assertEqual(response.status_code, 403)
        with self.subTest('Updated cache with radius setting token'):
            rad.token = '1234567'
            rad.save()
            self.assertEqual(rad.token, cache.get(rad.organization.pk))
        with self.subTest('Cache Miss: radius settings deleted'):
            rad.delete()
            self.assertEqual(None, cache.get(rad.organization.pk))

    def test_no_org_radius_setting(self):
        self._get_org_user()
        token_querystring = f'?token=12345&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        r = self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data, {'detail': 'Token authentication failed'})

    def test_uuid_in_cache(self):
        rad = OrganizationRadiusSettings.objects.create(
            token='12345', organization=self.org
        )
        cache.set('uuid', str(self.org.pk), 30)
        self._get_org_user()
        token_querystring = f'?token={rad.token}&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        r = self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 200)

    def test_default_organisation_radius_settings(self):
        org = self._get_org()
        self.assertTrue(hasattr(org, 'radius_settings'))
        self.assertIsInstance(org.radius_settings, OrganizationRadiusSettings)

    def test_sms_phone_required(self):
        radius_settings = OrganizationRadiusSettings(
            organization=self.org, sms_verification=True, sms_sender=''
        )
        try:
            radius_settings.full_clean()
        except ValidationError as e:
            self.assertIn('sms_sender', e.message_dict)
        else:
            self.fail('ValidationError not raised')
