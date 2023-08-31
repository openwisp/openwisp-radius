from django.test import TestCase, tag
from django.urls import reverse

from openwisp_users.tests.utils import TestOrganizationMixin

from .mixins import CreateDeviceMonitoringMixin


@tag('radius_monitoring')
class TestDeviceAdmin(TestOrganizationMixin, CreateDeviceMonitoringMixin, TestCase):
    app_label = 'config'

    def setUp(self):
        admin = self._create_admin()
        self.client.force_login(admin)

    def test_radius_session_tab(self):
        device = self._create_device()
        response = self.client.get(
            reverse(f'admin:{self.app_label}_device_change', args=[device.id])
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            '<div class="js-inline-admin-formset inline-group" id="radius-sessions">',
        )
        self.assertContains(
            response,
            '<tbody id="radius-session-tbody"></tbody>',
        )
