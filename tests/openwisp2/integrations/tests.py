from django.test import TestCase
from django.urls import reverse

from openwisp_users.tests.utils import TestOrganizationMixin


class TestIntegrations(TestOrganizationMixin, TestCase):
    def test_swagger_api_docs(self):
        admin = self._get_admin()
        self.client.force_login(admin)
        response = self.client.get(reverse('schema-swagger-ui'), {'format': 'openapi'})
        self.assertEqual(response.status_code, 200)
