from unittest import mock

import swapper
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.timezone import localtime
from freezegun import freeze_time
from rest_framework.authtoken.models import Token

from openwisp_radius.api import views as api_views
from openwisp_utils.tests import capture_any_output

from ... import settings as app_settings
from ...utils import load_model
from .. import _TEST_DATE
from ..mixins import ApiTokenMixin, BaseTestCase

RadiusToken = load_model('RadiusToken')
RegisteredUser = load_model('RegisteredUser')
PhoneToken = load_model('PhoneToken')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
User = get_user_model()


class TestApiUserToken(ApiTokenMixin, BaseTestCase):
    def _get_url(self):
        return reverse('radius:user_auth_token', args=[self.default_org.slug])

    def _post_credentials(self):
        with self.assertNumQueries(21):
            return self.client.post(
                self._get_url(), {'username': 'tester', 'password': 'tester'}
            )

    def _user_auth_token_helper(self, username):
        response = self._post_credentials()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['key'], Token.objects.first().key)
        self.assertEqual(
            response.data['radius_user_token'],
            RadiusToken.objects.first().key,
        )
        self.assertTrue(response.data['is_active'])
        self.assertIn('is_verified', response.data)
        self.assertIn('method', response.data)
        self.assertIn('radius_user_token', response.data)

    def test_user_auth_token_200(self):
        org_user = self._get_org_user()

        with self.subTest('login with username'):
            self._user_auth_token_helper(org_user.user.username)

        with self.subTest('login with email'):
            self._user_auth_token_helper(org_user.user.email)

        with self.subTest('login with phone_number'):
            org_user.user.phone_number = '+23767778243'
            org_user.save()
            self._user_auth_token_helper(org_user.user.phone_number)

    def test_user_language_preference_stored(self):
        test_user = self._get_user()
        self.assertEqual(test_user.language, 'en-gb')
        self.client.post(
            self._get_url(),
            {'username': 'tester', 'password': 'tester'},
            HTTP_ACCEPT_LANGUAGE='it',
        )
        test_user.refresh_from_db()
        self.assertEqual(test_user.language, 'it')

    def test_user_auth_token_with_second_organization(self):
        api_views.renew_required = False
        self._get_org_user()
        self.org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        self._create_org_user(**{'organization': self.org2})
        for org_slug in [self.default_org.slug, self.org2.slug]:
            with self.subTest(org_slug):
                # Get token for organizations
                response = self.client.post(
                    reverse('radius:user_auth_token', args=[org_slug]),
                    {'username': 'tester', 'password': 'tester'},
                )
                self.assertEqual(response.status_code, 200)
                # Check authorization accepts for both organizations
                response = self.client.post(
                    reverse('radius:authorize'),
                    {'username': 'tester', 'password': 'tester'},
                )
                self.assertEqual(response.status_code, 200)
        api_views.renew_required = True

    def test_user_auth_token_400_credentials(self):
        url = self._get_url()
        r = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 400)
        self.assertIn(
            'credentials entered are not valid', r.json()['non_field_errors'][0]
        )

    @capture_any_output()
    def test_user_auth_token_different_organization(self):
        self._get_org_user()
        org2 = self._create_org(name='org2')
        OrganizationRadiusSettings.objects.create(organization=org2)
        url = reverse('radius:user_auth_token', args=[org2.slug])

        with self.subTest('OrganziationUser present'):
            response = self.client.post(
                url, {'username': 'tester', 'password': 'tester'}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data['key'], Token.objects.first().key)
            self.assertEqual(
                response.data['radius_user_token'],
                RadiusToken.objects.first().key,
            )
            self.assertEqual(OrganizationUser.objects.count(), 2)
            org_user = OrganizationUser.objects.first()
            self.assertEqual(org_user.organization, org2)

        with self.subTest('No OrganizationUser present'):
            OrganizationUser.objects.all().delete()
            response = self.client.post(
                url, {'username': 'tester', 'password': 'tester'}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(OrganizationUser.objects.count(), 1)
            org_user = OrganizationUser.objects.first()
            self.assertEqual(org_user.organization, org2)

        with self.subTest('New OrganizationUser validation'):
            with mock.patch.object(User, 'is_member', return_value=False):
                response = self.client.post(
                    url, {'username': 'tester', 'password': 'tester'}
                )
                self.assertEqual(response.status_code, 400)
                expected_response = {
                    'non_field_errors': [
                        'Organization user with this User and '
                        'Organization already exists.'
                    ]
                }
                self.assertEqual(response.data, expected_response)

    @capture_any_output()
    def test_user_auth_token_different_organization_registration_settings(self):
        def _assert_registration_disabled():
            response = self.client.post(
                url, {'username': 'tester', 'password': 'tester'}
            )
            self.assertEqual(response.status_code, 403)
            self.assertEqual(
                response.data['detail'],
                f'{org2} does not allow self registration of new accounts.',
            )
            self.assertEqual(org2_user_query.count(), 0)

        def _assert_registration_enabled():
            response = self.client.post(
                url, {'username': 'tester', 'password': 'tester'}
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(org2_user_query.count(), 1)

        org1_user = self._get_org_user()
        org2 = self._create_org(name='org2')
        org2_user_query = OrganizationUser.objects.filter(
            organization=org2, user=org1_user.user
        )
        rad_setting = OrganizationRadiusSettings.objects.create(
            organization=org2, registration_enabled=None
        )
        url = reverse('radius:user_auth_token', args=[org2.slug])

        with self.subTest('Global disabled and organization None'):
            with mock.patch.object(app_settings, 'REGISTRATION_API_ENABLED', False):
                _assert_registration_disabled()

        with self.subTest('Global enabled and organization None'):
            _assert_registration_enabled()

        org2_user_query.delete()

        with self.subTest('Organization disabled'):
            rad_setting.registration_enabled = False
            rad_setting.save()
            _assert_registration_disabled()

        with self.subTest('Global enabled and organization None'):
            rad_setting.registration_enabled = True
            rad_setting.save()
            _assert_registration_enabled()

    @capture_any_output()
    def test_unverified_registered_user_different_organization(self):
        user_cred = {'username': 'tester', 'password': 'tester'}
        user = self._create_user(**user_cred)
        self._create_org_user(user=user, organization=self.default_org)
        org2 = self._create_org(name='org2')
        rad_settings = OrganizationRadiusSettings.objects.create(
            organization=org2, needs_identity_verification=True
        )
        url = reverse('radius:user_auth_token', args=[org2.slug])

        with self.subTest('Test RegisteredUser object does not exist'):
            response = self.client.post(url, user_cred)
            self.assertEqual(response.status_code, 403)

        registered_user = RegisteredUser.objects.create(user=user, method='')
        with self.subTest('Test unverified user without registration method'):
            response = self.client.post(url, user_cred)
            self.assertEqual(response.status_code, 403)

        with self.subTest('Test verified user without registration method'):
            registered_user.is_verified = True
            registered_user.save()
            response = self.client.post(url, user_cred)
            self.assertEqual(response.status_code, 403)

        with self.subTest('Test verified user with mobile registration method'):
            registered_user.method = 'mobile_phone'
            registered_user.save()
            response = self.client.post(url, user_cred)
            self.assertEqual(response.status_code, 200)
            self.assertIn('key', response.data)

        OrganizationUser.objects.filter(organization=org2, user=user).delete()
        with self.subTest(
            'Test unverified user organization does not need identity verification'
        ):
            registered_user.is_verified = False
            registered_user.save()
            rad_settings.needs_identity_verification = False
            rad_settings.save()

            response = self.client.post(url, user_cred)
            self.assertEqual(response.status_code, 200)
            self.assertIn('key', response.data)

    def test_user_auth_token_404(self):
        url = reverse(
            'radius:user_auth_token', args=['00000000-0000-0000-0000-000000000000']
        )
        r = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 404)

    @freeze_time(_TEST_DATE)
    def test_user_auth_updates_last_login(self):
        admin = self._get_admin()
        login_payload = {'username': 'admin', 'password': 'tester'}
        login_url = reverse('radius:user_auth_token', args=[self.default_org.slug])
        self.assertEqual(admin.last_login, None)
        response = self.client.post(login_url, data=login_payload)
        self.assertEqual(response.status_code, 200)
        admin.refresh_from_db()
        self.assertIsNotNone(admin.last_login)
        self.assertEqual(localtime(admin.last_login).isoformat(), _TEST_DATE)

    def test_user_auth_token_inactive_user(self):
        url = self._get_url()
        organization_user = self._get_org_user()
        organization_user.user.is_active = False
        organization_user.user.save()
        response = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.data['is_active'])


class TestApiValidateToken(ApiTokenMixin, BaseTestCase):
    def _get_url(self):
        return reverse('radius:validate_auth_token', args=[self.default_org.slug])

    def _test_validate_auth_token_helper(self, user):
        url = self._get_url()
        token = Token.objects.create(user=user)
        # empty payload
        response = self.client.post(url)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['response_code'], 'BLANK_OR_INVALID_TOKEN')
        # invalid token
        payload = dict(token='some-random-string')
        response = self.client.post(url, payload)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['response_code'], 'BLANK_OR_INVALID_TOKEN')
        # valid token
        payload = dict(token=token.key)
        with self.assertNumQueries(16):
            response = self.client.post(url, payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data['response_code'], 'AUTH_TOKEN_VALIDATION_SUCCESSFUL'
        )
        self.assertEqual(response.data['auth_token'], token.key)
        self.assertEqual(
            response.data['radius_user_token'],
            RadiusToken.objects.first().key,
        )
        user = token.user
        self.assertEqual(user, RadiusToken.objects.first().user)
        self.assertEqual(
            response.data['username'],
            user.username,
        )
        self.assertEqual(
            response.data['is_active'],
            user.is_active,
        )
        if user.is_active:
            phone_number = user.phone_number
        else:
            phone_number = PhoneToken.objects.filter(user=user).first().phone_number

        if phone_number:
            phone_number = str(phone_number)

        self.assertEqual(
            response.data['phone_number'],
            phone_number,
        )
        self.assertEqual(
            response.data['email'],
            user.email,
        )
        self.assertIn('is_verified', response.data)
        self.assertIn('method', response.data)
        self.assertIn('radius_user_token', response.data)

    def test_validate_auth_token_with_active_user(self):
        user = self._get_user_with_org()
        self._test_validate_auth_token_helper(user)

    def test_user_language_preference_stored(self):
        user = self._get_user()
        token = Token.objects.create(user=user)
        self.assertEqual(user.language, 'en-gb')
        self.client.post(
            self._get_url(),
            dict(token=token.key),
            HTTP_ACCEPT_LANGUAGE='ru',
        )
        user.refresh_from_db()
        self.assertEqual(user.language, 'ru')

    def test_validate_auth_token_phone_number_null(self):
        user = self._get_user_with_org()
        user.phone_number = None
        user.save()
        self._test_validate_auth_token_helper(user)

    @capture_any_output()
    def test_validate_auth_token_with_inactive_user(self):
        user = self._get_user_with_org()
        user.is_active = False
        user.save()
        user.refresh_from_db()
        phone_token = PhoneToken(
            user=user, ip='127.0.0.1', phone_number='+237675578296'
        )
        phone_token.full_clean()
        phone_token.save()
        self._test_validate_auth_token_helper(user)

    @freeze_time(_TEST_DATE)
    def test_user_auth_updates_last_login(self):
        admin = self._get_admin()
        token = Token.objects.create(user=admin)
        payload = dict(token=token.key)
        self.assertEqual(admin.last_login, None)
        response = self.client.post(self._get_url(), payload)
        self.assertEqual(response.status_code, 200)
        admin.refresh_from_db()
        self.assertIsNotNone(admin.last_login)
        self.assertEqual(localtime(admin.last_login).isoformat(), _TEST_DATE)
