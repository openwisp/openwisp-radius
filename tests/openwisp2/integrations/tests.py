from unittest import mock
from urllib.parse import urlparse

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from openwisp_radius.utils import load_model
from openwisp_users.tests.utils import TestOrganizationMixin
from openwisp_utils.tests import capture_any_output

RadiusAccounting = load_model('RadiusAccounting')
RadiusToken = load_model('RadiusToken')
User = get_user_model()


def mock_post_request(url, data, timeout, *args, **kwargs):
    client = Client()
    url = urlparse(url).path
    assert url == reverse('radius:accounting')
    client.post(url, data=data, content_type='application/json')


class TestIntegrations(TestOrganizationMixin, TestCase):
    def test_swagger_api_docs(self):
        admin = self._get_admin()
        self.client.force_login(admin)
        response = self.client.get(reverse('schema-swagger-ui'), {'format': 'openapi'})
        self.assertEqual(response.status_code, 200)

    def _create_rad_token(self):
        user = self._get_user()
        org = self._get_org()
        radius_token = RadiusToken.objects.filter(user=user, organization=org).first()
        if not radius_token:
            radius_token = RadiusToken.objects.create(user=user, organization=org)
        return radius_token

    @capture_any_output()
    @mock.patch('openwisp2.views.requests.post', mock_post_request)
    def test_captive_portal_login_mock(self, *args, **kwargs):
        url = reverse('captive_portal_login_mock')
        radius_token, ra = (None, None)

        with self.subTest('no action to perform, ensure no error'):
            response = self.client.post(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(RadiusAccounting.objects.count(), 0)
            self.assertEqual(RadiusToken.objects.count(), 0)

        with self.subTest('radius token matches, session is created'):
            user = self._get_user()
            radius_token = self._create_rad_token()
            response = self.client.post(url, {'auth_pass': radius_token.key})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(RadiusToken.objects.count(), 1)
            self.assertEqual(RadiusAccounting.objects.count(), 1)
            ra = RadiusAccounting.objects.first()
            self.assertIsNone(ra.stop_time)
            self.assertEqual(ra.username, user.username)

        return radius_token, ra

    @capture_any_output()
    @mock.patch('openwisp2.views.requests.post', mock_post_request)
    def test_captive_portal_logout_mock(self, *args, **kwargs):
        url = reverse('captive_portal_logout_mock')

        with self.subTest('no action to perform, ensure no error'):
            response = self.client.post(url)
            self.assertEqual(response.status_code, 200)
            response = self.client.post(url, {'logout_id': '123'})
            self.assertEqual(response.status_code, 200)

        radius_token = self._create_rad_token()
        response = self.client.post(
            reverse('captive_portal_login_mock'), {'auth_pass': radius_token.key}
        )
        ra = RadiusAccounting.objects.first()
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
