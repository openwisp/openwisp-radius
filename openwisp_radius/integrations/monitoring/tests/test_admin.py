from django.test import TestCase, tag
from django.urls import reverse
from django.utils import timezone

from openwisp_radius.tests import _RADACCT, CreateRadiusObjectsMixin

from ..utils import get_datetime_filter_start_date, get_datetime_filter_stop_date
from .mixins import CreateDeviceMonitoringMixin


@tag('radius_monitoring')
class TestDeviceAdmin(CreateRadiusObjectsMixin, CreateDeviceMonitoringMixin, TestCase):
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

    def test_radius_dashboard_chart_data(self):
        options = _RADACCT.copy()
        options['unique_id'] = '117'
        options['start_time'] = timezone.now().strftime('%Y-%m-%d 00:00:00')
        options['input_octets'] = '1234567890'
        self._create_radius_accounting(**options)
        response = self.client.get(reverse('admin:index'))
        self.assertEqual(response.status_code, 200)
        start_time = get_datetime_filter_start_date()
        end_time = get_datetime_filter_stop_date()
        self.assertContains(
            response,
            (
                '{\'name\': "Today\'s RADIUS sessions", \'query_params\': '
                '{\'values\': [1], \'labels\': [\'Open\']}, \'colors\': '
                '[\'#267126\'], \'filters\': [\'True\'], \'labels\': '
                '{\'open\': \'Open\', \'closed\': \'Closed\'}, \'target_link\': '
                '\'/admin/openwisp_radius/radiusaccounting/?start_time__gte='
                f'{start_time}&start_time__lt={end_time}'
                '&stop_time__isnull=\'}, 31: {\'name\': "Today\'s RADIUS traffic (GB)",'
                ' \'query_params\': {\'values\': [1.0], \'labels\': '
                '[\'Download traffic (GB)\']}, \'colors\': [\'#1f77b4\'], \'labels\': '
                '{\'download_traffic\': \'Download traffic (GB)\', \'upload_traffic\': '
                '\'Upload traffic (GB)\'}, \'filtering\': \'False\', \'target_link\': '
                '\'/admin/openwisp_radius/radiusaccounting/?start_time__gte='
                f'{start_time}&start_time__lt={end_time}\''
                '}'
            ),
        )
