from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from openwisp_radius.utils import load_model
from openwisp_users.tests.utils import TestOrganizationMixin
from openwisp_utils.tests import capture_any_output

RadiusAccounting = load_model('RadiusAccounting')
RadiusToken = load_model('RadiusToken')
User = get_user_model()


class TestIntegrations(TestOrganizationMixin, TestCase):
    def test_swagger_api_docs(self):
        admin = self._get_admin()
        self.client.force_login(admin)
        response = self.client.get(reverse('schema-swagger-ui'), {'format': 'openapi'})
        self.assertEqual(response.status_code, 200)

    def test_captive_portal_login_mock(self):
        url = reverse('captive_portal_login_mock')
        radius_token, ra = (None, None)

        with self.subTest('no action to perform, ensure no error'):
            response = self.client.post(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(RadiusAccounting.objects.count(), 0)
            self.assertEqual(RadiusToken.objects.count(), 0)

        with self.subTest('radius token matches, session is created'):
            user = self._get_user()
            org = self._get_org()
            radius_token = RadiusToken.objects.create(user=user, organization=org)
            response = self.client.post(url, {'auth_pass': radius_token.key})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(RadiusToken.objects.count(), 1)
            self.assertEqual(RadiusAccounting.objects.count(), 1)
            ra = RadiusAccounting.objects.first()
            self.assertIsNone(ra.stop_time)
            self.assertEqual(ra.username, user.username)

        return radius_token, ra

    @capture_any_output()
    def test_captive_portal_logout_mock(self):
        url = reverse('captive_portal_logout_mock')

        with self.subTest('no action to perform, ensure no error'):
            response = self.client.post(url)
            self.assertEqual(response.status_code, 200)
            response = self.client.post(url, {'logout_id': '123'})
            self.assertEqual(response.status_code, 200)

        radius_token, ra = self.test_captive_portal_login_mock()

        with self.subTest('logout_id matches, RadiusAccounting closed'):
            assert radius_token
            assert ra
            response = self.client.post(url, {'logout_id': ra.session_id})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(RadiusToken.objects.count(), 1)
            self.assertEqual(RadiusAccounting.objects.count(), 1)
            ra.refresh_from_db()
            self.assertIsNotNone(ra.stop_time)
            self.assertEqual(ra.terminate_cause, 'User-Request')
