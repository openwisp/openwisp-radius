import swapper
from django.urls import reverse
from django.utils.timezone import localtime
from freezegun import freeze_time
from rest_framework.authtoken.models import Token

from openwisp_radius.api import views as api_views
from openwisp_utils.tests import capture_any_output

from ...utils import load_model
from .. import _TEST_DATE
from ..mixins import ApiTokenMixin, BaseTestCase

RadiusToken = load_model('RadiusToken')
PhoneToken = load_model('PhoneToken')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')


class TestApiUserToken(ApiTokenMixin, BaseTestCase):
    def _get_url(self):
        return reverse('radius:user_auth_token', args=[self.default_org.slug])

    def _user_auth_token_helper(self, username):
        url = self._get_url()
        response = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['key'], Token.objects.first().key)
        self.assertEqual(
            response.data['radius_user_token'], RadiusToken.objects.first().key,
        )
        self.assertTrue(response.data['is_active'])

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
                self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})
        api_views.renew_required = True

    def test_user_auth_token_400_credentials(self):
        url = self._get_url()
        r = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('Unable to log in', r.json()['non_field_errors'][0])

    @capture_any_output()
    def test_user_auth_token_400_organization(self):
        url = self._get_url()
        self._get_org_user()
        OrganizationUser.objects.all().delete()
        r = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('is not member', r.json()['non_field_errors'][0])

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
        response = self.client.post(url, payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data['response_code'], 'AUTH_TOKEN_VALIDATION_SUCCESSFUL'
        )
        self.assertEqual(response.data['auth_token'], token.key)
        self.assertEqual(
            response.data['radius_user_token'], RadiusToken.objects.first().key,
        )
        user = token.user
        self.assertEqual(user, RadiusToken.objects.first().user)
        self.assertEqual(
            response.data['username'], user.username,
        )
        self.assertEqual(
            response.data['is_active'], user.is_active,
        )
        if user.is_active:
            phone_number = user.phone_number
        else:
            phone_number = PhoneToken.objects.filter(user=user).first().phone_number

        if phone_number:
            phone_number = str(phone_number)

        self.assertEqual(
            response.data['phone_number'], phone_number,
        )
        self.assertEqual(
            response.data['email'], user.email,
        )

    def test_validate_auth_token_with_active_user(self):
        user = self._get_user_with_org()
        self._test_validate_auth_token_helper(user)

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
