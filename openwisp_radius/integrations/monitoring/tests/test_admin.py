from django.test import TestCase, override_settings, tag
from django.urls import reverse
from freezegun import freeze_time

from openwisp_radius.tests import _RADACCT, CreateRadiusObjectsMixin

from ..utils import (
    get_datetime_filter_start_datetime,
    get_datetime_filter_stop_datetime,
)
from .mixins import CreateDeviceMonitoringMixin


@tag("radius_monitoring")
class TestDeviceAdmin(CreateRadiusObjectsMixin, CreateDeviceMonitoringMixin, TestCase):
    app_label = "config"
    radius_label = "openwisp_radius"

    def setUp(self):
        admin = self._create_admin()
        self.client.force_login(admin)

    def test_radius_session_tab(self):
        device = self._create_device()
        response = self.client.get(
            reverse(f"admin:{self.app_label}_device_change", args=[device.id])
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

    @freeze_time("2025-02-13 00:00:00+05:30")
    @override_settings(TIME_ZONE="Asia/Kolkata")
    def test_radius_dashboard_chart_data(self):
        options = _RADACCT.copy()
        # Create RADIUS Accounting with UTC time
        options["unique_id"] = "117"
        options["start_time"] = "2025-02-12T18:29:00+00:00"
        options["input_octets"] = "1234567890"
        # Create RADIUS Accounting with IST time
        self._create_radius_accounting(**options)
        options["unique_id"] = "118"
        options["start_time"] = "2025-02-13 00:00:00+05:30"
        # The dashboard queries RadiusAccounting with localdate,
        # therefore, it should not return the RADIUS Accounting created
        #  with UTC time as it will be on the previous day.
        self._create_radius_accounting(**options)
        response = self.client.get(reverse("admin:index"))
        self.assertEqual(response.status_code, 200)
        start_time = get_datetime_filter_start_datetime()
        end_time = get_datetime_filter_stop_datetime()
        self.assertContains(
            response,
            (
                "{'name': \"Today's RADIUS sessions\", 'query_params': "
                "{'values': [1], 'labels': ['Open']}, 'colors': "
                "['#267126'], 'filters': ['True'], 'labels': "
                "{'open': 'Open', 'closed': 'Closed'}, 'target_link': "
                "'/admin/openwisp_radius/radiusaccounting/?start_time__gte="
                f"{start_time}&start_time__lt={end_time}"
                "&stop_time__isnull='}, 31: {'name': \"Today's RADIUS traffic (GB)\","
                " 'query_params': {'values': [1.0], 'labels': "
                "['Download traffic (GB)']}, 'colors': ['#1f77b4'], 'labels': "
                "{'download_traffic': 'Download traffic (GB)', 'upload_traffic': "
                "'Upload traffic (GB)'}, 'filtering': 'False', 'target_link': "
                "'/admin/openwisp_radius/radiusaccounting/?start_time__gte="
                f"{start_time}&start_time__lt={end_time}'"
                "}"
            ),
        )

    def test_radius_dashboard_chart_filter_url(self):
        path = reverse(f"admin:{self.radius_label}_radiusaccounting_changelist")
        response = self.client.get(
            "{path}?start_time__gte={start_time}&start_time__lt={stop_time}".format(
                path=path,
                start_time=get_datetime_filter_start_datetime(),
                stop_time=get_datetime_filter_stop_datetime(),
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.request["QUERY_STRING"], "e=1")
        self.assertContains(
            response,
            '<div class="selected-option" tabindex="0" title="Today">',
        )
