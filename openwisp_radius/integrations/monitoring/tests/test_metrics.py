from io import StringIO
from unittest import skipUnless
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.cache.backends.locmem import LocMemCache
from django.core.management import call_command
from django.db import DatabaseError, transaction
from django.test import tag
from django.utils import timezone
from swapper import load_model

from openwisp_radius.tests import _RADACCT
from openwisp_radius.tests.mixins import BaseTransactionTestCase

from .. import settings as monitoring_settings
from ..migrations import create_general_metrics
from ..utils import sha1_hash
from .mixins import CreateDeviceMonitoringMixin

# Discovery imports tests before filtering tags, but tasks require Monitoring models.
MONITORING_INSTALLED = apps.is_installed("openwisp_radius.integrations.monitoring")
if MONITORING_INSTALLED:
    from ..tasks import (
        RECONCILIATION_LOCK_KEY,
        RECONCILIATION_STATE_KEY,
        _accounting_totals,
        _reconciliation_lock,
        _recover_baseline,
        _traffic_delta,
        _traffic_point,
        post_save_radiusaccounting,
        reconcile_radius_traffic,
    )

TASK_PATH = "openwisp_radius.integrations.monitoring.tasks"

RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
OrganizationUser = load_model("openwisp_users", "OrganizationUser")
RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")
User = get_user_model()


@tag("radius_monitoring")
@skipUnless(MONITORING_INSTALLED, "RADIUS Monitoring integration is not installed")
class TestMetrics(CreateDeviceMonitoringMixin, BaseTransactionTestCase):
    def _read_chart(self, chart, **kwargs):
        return chart.read(
            additional_query_kwargs={"additional_params": kwargs},
        )

    def _get_metric_traces(self, metric_key, organization_id):
        chart = self.metric_model.objects.get(key=metric_key).chart_set.first()
        points = self._read_chart(
            chart,
            organization_id=[str(organization_id)],
        )
        return {trace_name: values[-1] for trace_name, values in points["traces"]}

    def _assert_pending_verification_excluded(self, points):
        """
        Ensure that pending_verification users do not contribute
        to metric outputs.

        This validates both:
        - trace-level values (time series data)
        - summary-level aggregation
        """
        self.assertEqual(points["traces"][0][1][-1], 0)
        summary = points.get("summary", {})
        # Summary should not contain any positive counts
        for key, value in summary.items():
            self.assertEqual(
                value,
                0,
                f"pending_verification leaked into summary for key={key}",
            )

    def _create_registered_user(self, **kwargs):
        options = {
            "is_verified": False,
            "method": "mobile_phone",
            "organization": self.default_org,
        }
        options.update(**kwargs)
        if "user" not in options:
            options["user"] = self._create_user()
        reg_user = RegisteredUser(**options)
        reg_user.full_clean()
        reg_user.save()
        return reg_user

    @patch("logging.Logger.warning")
    def test_post_save_radiusaccounting(self, *args):
        user = self._create_user()
        reg_user = self._create_registered_user(user=user)
        device = self._create_device()
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "117",
                "username": user.username,
                "called_station_id": device.mac_address.replace("-", ":").upper(),
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": "8000000000",
                "output_octets": "9000000000",
            }
        )
        options["stop_time"] = timezone.now()

        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration="radius_acc",
                name="RADIUS Accounting",
                key="radius_acc",
                object_id=str(device.id),
                content_type=ContentType.objects.get_for_model(self.device_model),
                extra_tags={
                    "called_station_id": device.mac_address,
                    "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                    "location_id": str(device_loc.location.id),
                    "method": reg_user.method,
                    "organization_id": str(self.default_org.id),
                },
            ).count(),
            1,
        )
        metric = self.metric_model.objects.filter(configuration="radius_acc").first()
        traffic_chart = metric.chart_set.get(configuration="radius_traffic")
        points = traffic_chart.read()
        self.assertEqual(points["traces"][0][0], "download")
        self.assertEqual(points["traces"][0][1][-1], 0)
        self.assertEqual(points["traces"][1][0], "upload")
        self.assertEqual(points["traces"][1][1][-1], 0)
        self.assertEqual(points["summary"], {"upload": 0, "download": 0})

        session_chart = metric.chart_set.get(configuration="rad_session")
        points = session_chart.read()
        self.assertEqual(points["traces"][0][0], "mobile_phone")
        self.assertEqual(points["traces"][0][1][-1], 1)
        self.assertEqual(points["summary"], {"mobile_phone": 1})

    @patch("logging.Logger.warning")
    def test_post_save_radiusaccounting_device_without_location(self, *args):
        user = self._create_user()
        reg_user = self._create_registered_user(user=user)
        device = self._create_device()
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "117",
                "username": user.username,
                "called_station_id": device.mac_address.replace("-", ":").upper(),
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": "8000000000",
                "output_octets": "9000000000",
            }
        )
        options["stop_time"] = timezone.now()
        self._create_radius_accounting(**options)
        with self.subTest("location_id should not be set"):
            self.assertEqual(
                self.metric_model.objects.filter(
                    configuration="radius_acc",
                    name="RADIUS Accounting",
                    key="radius_acc",
                    object_id=str(device.id),
                    content_type=ContentType.objects.get_for_model(self.device_model),
                    extra_tags={
                        "called_station_id": device.mac_address,
                        "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                        "method": reg_user.method,
                        "organization_id": str(self.default_org.id),
                    },
                ).count(),
                1,
            )
        with self.subTest("Deleting device without location_id should not fail"):
            self.device_model.objects.all().delete()
            self.assertEqual(self.device_model.objects.count(), 0)
            self.assertEqual(
                self.metric_model.objects.filter(
                    key="radius_acc", object_id=str(device.id)
                ).count(),
                0,
            )

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_post_save_radiusaccouting_open_session(self, mocked_delay):
        """
        Regression test ensuring open or interim accounting sessions do not
        write monitoring metrics before their cumulative octet values are final.
        """
        radius_options = _RADACCT.copy()
        radius_options["unique_id"] = "117"
        session = self._create_radius_accounting(**radius_options)
        self.assertEqual(session.stop_time, None)
        mocked_delay.assert_not_called()

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_radius_accounting_closed_handler_open_session(self, mocked_delay):
        # Import locally because the standard test suite runs without monitoring.
        from ..receivers import radius_accounting_closed_handler

        radius_options = _RADACCT.copy()
        radius_options["unique_id"] = "open-session-handler"
        session = RadiusAccounting(**radius_options)
        self.assertEqual(session.stop_time, None)
        radius_accounting_closed_handler(session)
        mocked_delay.assert_not_called()

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_radius_accounting_closed_handler_naive_stop_time(self, mocked_delay):
        # Import locally because the standard test suite runs without monitoring.
        from ..receivers import radius_accounting_closed_handler

        naive_stop_time = timezone.datetime(2026, 1, 1, 12, 0, 0)
        radius_options = _RADACCT.copy()
        radius_options.update(
            {
                "unique_id": "naive-stop-time-handler",
                "organization": self.default_org,
                "called_station_id": "AA-BB-CC-DD-EE-FF",
                "calling_station_id": "00:00:00:00:00:00",
                "stop_time": naive_stop_time,
            }
        )
        session = RadiusAccounting(**radius_options)
        radius_accounting_closed_handler(session)
        mocked_delay.assert_called_once_with(
            username=radius_options["username"],
            organization_id=str(self.default_org.id),
            input_octets=radius_options["input_octets"],
            output_octets=radius_options["output_octets"],
            calling_station_id=radius_options["calling_station_id"],
            called_station_id=radius_options["called_station_id"],
            time=timezone.make_aware(naive_stop_time),
        )

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_accounting_on_nas_reboot_writes_monitoring_metric(self, mocked_delay):
        """
        Regression test for https://github.com/openwisp/openwisp-radius/issues/734.

        Sessions closed by Accounting-On must write monitoring metrics even
        though the closure path uses bulk_update instead of model save().
        """
        radius_options = _RADACCT.copy()
        radius_options.update(
            {
                "unique_id": "nas-reboot-session",
                "called_station_id": "AA-BB-CC-DD-EE-FF",
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": 8000000000,
                "output_octets": 9000000000,
                "stop_time": None,
            }
        )
        self._create_radius_accounting(**radius_options)
        mocked_delay.assert_not_called()
        closed_count = RadiusAccounting._close_stale_sessions_on_nas_boot(
            called_station_id=radius_options["called_station_id"]
        )
        self.assertEqual(closed_count, 1)
        session = RadiusAccounting.objects.get(unique_id=radius_options["unique_id"])
        mocked_delay.assert_called_once_with(
            username=radius_options["username"],
            organization_id=str(self.default_org.id),
            input_octets=radius_options["input_octets"],
            output_octets=radius_options["output_octets"],
            calling_station_id=radius_options["calling_station_id"],
            called_station_id=radius_options["called_station_id"],
            time=session.stop_time,
        )
        mocked_delay.reset_mock()
        closed_count = RadiusAccounting._close_stale_sessions_on_nas_boot(
            called_station_id=radius_options["called_station_id"]
        )
        self.assertEqual(closed_count, 0)
        mocked_delay.assert_not_called()

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_close_previous_radius_accounting_writes_monitoring_metric(
        self, mocked_delay
    ):
        """
        Regression test ensuring sessions closed by the previous-session
        cleanup path write monitoring metrics despite using bulk_update.
        """
        radius_options = _RADACCT.copy()
        radius_options.update(
            {
                "unique_id": "previous-session",
                "called_station_id": "AA-BB-CC-DD-EE-FF",
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": 8000000000,
                "output_octets": 9000000000,
                "stop_time": None,
            }
        )
        self._create_radius_accounting(**radius_options)
        mocked_delay.assert_not_called()
        new_session_options = radius_options.copy()
        new_session_options.update(
            {
                "unique_id": "new-session",
                "input_octets": 1000000000,
                "output_octets": 2000000000,
            }
        )
        self._create_radius_accounting(**new_session_options)
        session = RadiusAccounting.objects.get(unique_id=radius_options["unique_id"])
        mocked_delay.assert_called_once_with(
            username=radius_options["username"],
            organization_id=str(self.default_org.id),
            input_octets=radius_options["input_octets"],
            output_octets=radius_options["output_octets"],
            calling_station_id=radius_options["calling_station_id"],
            called_station_id=radius_options["called_station_id"],
            time=session.stop_time,
        )

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_closed_radius_accounting_metric_uses_stop_time(self, mocked_delay):
        """
        Regression test ensuring sessions created already closed are
        snapshotted at stop_time rather than task execution time.
        """
        stop_time = timezone.now() - timezone.timedelta(days=1)
        radius_options = _RADACCT.copy()
        radius_options.update(
            {
                "unique_id": "closed-session-stop-time",
                "called_station_id": "AA-BB-CC-DD-EE-FF",
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": 8000000000,
                "output_octets": 9000000000,
                "stop_time": stop_time,
            }
        )
        self._create_radius_accounting(**radius_options)
        mocked_delay.assert_called_once_with(
            username=radius_options["username"],
            organization_id=str(self.default_org.id),
            input_octets=radius_options["input_octets"],
            output_octets=radius_options["output_octets"],
            calling_station_id=radius_options["calling_station_id"],
            called_station_id=radius_options["called_station_id"],
            time=stop_time,
        )

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_editing_closed_radius_accounting_does_not_write_metric_again(
        self, mocked_delay
    ):
        """
        Regression test ensuring edits to already closed sessions do not write
        duplicate monitoring metrics after the first close snapshot.
        """
        stop_time = timezone.now()
        radius_options = _RADACCT.copy()
        radius_options.update(
            {
                "unique_id": "closed-session-edit",
                "called_station_id": "AA-BB-CC-DD-EE-FF",
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": 8000000000,
                "output_octets": 9000000000,
                "stop_time": stop_time,
            }
        )
        session = self._create_radius_accounting(**radius_options)
        mocked_delay.assert_called_once()
        mocked_delay.reset_mock()
        session.terminate_cause = "User-Request"
        session.save(update_fields=["terminate_cause"])
        mocked_delay.assert_not_called()

    @patch("logging.Logger.warning")
    def test_post_save_radius_accounting_shared_accounting(self, mocked_logger):
        """
        This test ensures that the metric is written with the device's MAC address
        when the OPENWISP_RADIUS_MONITORING_SHARED_ACCOUNTING is
        set to True, even if the RadiusAccounting session and the related device
        have different organizations.
        """
        from .. import settings as app_settings

        user = self._create_user()
        reg_user = self._create_registered_user(user=user)
        org2 = self._get_org("org2")
        device = self._create_device(organization=org2)
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "117",
                "username": user.username,
                "called_station_id": device.mac_address.replace("-", ":").upper(),
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": "8000000000",
                "output_octets": "9000000000",
            }
        )
        options["stop_time"] = timezone.now()
        device_metric_qs = self.metric_model.objects.filter(
            configuration="radius_acc",
            name="RADIUS Accounting",
            key="radius_acc",
            object_id=str(device.id),
            content_type=ContentType.objects.get_for_model(self.device_model),
            extra_tags={
                "called_station_id": device.mac_address,
                "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                "location_id": str(device_loc.location.id),
                "method": reg_user.method,
                "organization_id": str(self.default_org.id),
            },
        )

        with self.subTest("Test SHARED_ACCOUNTING is set to False"):
            with patch.object(app_settings, "SHARED_ACCOUNTING", False):
                self._create_radius_accounting(**options)
            self.assertEqual(
                device_metric_qs.count(),
                0,
            )
            # The metric is created without the device_id
            self.assertEqual(
                self.metric_model.objects.filter(
                    configuration="radius_acc",
                    name="RADIUS Accounting",
                    key="radius_acc",
                    object_id=None,
                    content_type=None,
                    extra_tags={
                        "called_station_id": device.mac_address,
                        "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                        "method": reg_user.method,
                        "organization_id": str(self.default_org.id),
                    },
                ).count(),
                1,
            )

        with self.subTest("Test SHARED_ACCOUNTING is set to True"):
            with patch.object(app_settings, "SHARED_ACCOUNTING", True):
                options["unique_id"] = "118"
                self._create_radius_accounting(**options)
            self.assertEqual(
                device_metric_qs.count(),
                1,
            )
            metric = device_metric_qs.first()
            self.assertEqual(
                metric.extra_tags["organization_id"], str(self.default_org.id)
            )
            traffic_chart = metric.chart_set.get(configuration="radius_traffic")
            points = traffic_chart.read()
            self.assertEqual(points["traces"][0][0], "download")
            self.assertEqual(points["traces"][0][1][-1], 0)
            self.assertEqual(points["traces"][1][0], "upload")
            self.assertEqual(points["traces"][1][1][-1], 0)
            self.assertEqual(points["summary"], {"upload": 0, "download": 0})

    @patch("logging.Logger.warning")
    def test_post_save_radius_accounting_device_not_found(self, mocked_logger):
        """
        This test checks that radius accounting metric is created
        even if the device could not be found with the called_station_id.
        This scenario can happen on an installations which uses the
        convert_called_station_id feature, but it is not configured
        properly leaving all called_station_id unconverted.
        """
        cache.clear()
        user = self._create_user()
        reg_user = self._create_registered_user(user=user)
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "117",
                "username": user.username,
                "called_station_id": "11:22:33:44:55:66",
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": "8000000000",
                "output_octets": "9000000000",
            }
        )
        options["stop_time"] = timezone.now()
        # Remove calls for user registration from mocked logger
        mocked_logger.reset_mock()
        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration="radius_acc",
                name="RADIUS Accounting",
                key="radius_acc",
                object_id=None,
                content_type=None,
                extra_tags={
                    "called_station_id": "11:22:33:44:55:66",
                    "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                    "method": reg_user.method,
                    "organization_id": str(self.default_org.id),
                },
            ).count(),
            1,
        )
        # The TransactionTestCase truncates all the data after each test.
        # The general metrics and charts which are created by migrations
        # get deleted after each test. Therefore, we create them again here.
        create_general_metrics(None, None)
        metric = self.metric_model.objects.filter(configuration="radius_acc").first()
        # A dedicated chart for this metric was not created since the
        # related device was not identified by the called_station_id.
        # The data however can be retrieved from the general charts.
        self.assertEqual(metric.chart_set.count(), 0)
        general_traffic_chart = self.chart_model.objects.get(
            configuration="gen_rad_traffic"
        )
        points = general_traffic_chart.read()
        self.assertEqual(points["traces"][0][0], "download")
        self.assertEqual(points["traces"][0][1][-1], 0)
        self.assertEqual(points["traces"][1][0], "upload")
        self.assertEqual(points["traces"][1][1][-1], 0)
        self.assertEqual(points["summary"], {"upload": 0, "download": 0})

        general_session_chart = self.chart_model.objects.get(
            configuration="gen_rad_session"
        )
        points = general_session_chart.read()
        self.assertEqual(points["traces"][0][0], "mobile_phone")
        self.assertEqual(points["traces"][0][1][-1], 1)
        self.assertEqual(points["summary"], {"mobile_phone": 1})
        mocked_logger.assert_called_once_with(
            f'Device object not found with MAC "{options["called_station_id"]}"'
            f' and organization "{self.default_org.id}".'
            " The metric will be written without a related object!"
        )

    @patch("logging.Logger.info")
    def test_post_save_radius_accounting_registereduser_not_found(self, mocked_logger):
        """
        This test checks that radius accounting metric is created
        even if the RegisteredUser object could not be found for the user.
        This scenario can happen on an installations which do not require
        users to signup to access the internet/
        """
        user = self._create_user()
        device = self._create_device()
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "117",
                "username": user.username,
                "called_station_id": device.mac_address.replace("-", ":").upper(),
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": "8000000000",
                "output_octets": "9000000000",
            }
        )
        options["stop_time"] = timezone.now()

        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration="radius_acc",
                name="RADIUS Accounting",
                key="radius_acc",
                object_id=str(device.id),
                content_type=ContentType.objects.get_for_model(self.device_model),
                extra_tags={
                    "called_station_id": device.mac_address,
                    "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                    "location_id": str(device_loc.location.id),
                    "method": "unspecified",
                    "organization_id": str(self.default_org.id),
                },
            ).count(),
            1,
        )
        metric = self.metric_model.objects.filter(configuration="radius_acc").first()
        traffic_chart = metric.chart_set.get(configuration="radius_traffic")
        points = traffic_chart.read()
        self.assertEqual(points["traces"][0][0], "download")
        self.assertEqual(points["traces"][0][1][-1], 0)
        self.assertEqual(points["traces"][1][0], "upload")
        self.assertEqual(points["traces"][1][1][-1], 0)
        self.assertEqual(points["summary"], {"upload": 0, "download": 0})

        session_chart = metric.chart_set.get(configuration="rad_session")
        points = session_chart.read()
        self.assertEqual(points["traces"][0][0], "unspecified")
        self.assertEqual(points["traces"][0][1][-1], 1)
        self.assertEqual(points["summary"], {"unspecified": 1})
        mocked_logger.assert_called_once_with(
            f'RegisteredUser object not found for "{user.username}".'
            ' The metric will be written with "unspecified" registration method!'
        )

    def test_post_save_radiusaccounting_pending_verification(self):
        """
        Test that when a user has a RegisteredUser with method="pending_verification",
        the metric is written with "unspecified" instead of None.
        """
        user = self._create_user()
        self._create_registered_user(user=user, method="pending_verification")
        device = self._create_device()
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "pending_001",
                "username": user.username,
                "called_station_id": device.mac_address.replace("-", ":").upper(),
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": "8000000000",
                "output_octets": "9000000000",
            }
        )
        options["stop_time"] = timezone.now()
        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration="radius_acc",
                name="RADIUS Accounting",
                key="radius_acc",
                object_id=str(device.id),
                content_type=ContentType.objects.get_for_model(self.device_model),
                extra_tags={
                    "called_station_id": device.mac_address,
                    "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                    "location_id": str(device_loc.location.id),
                    "method": "unspecified",
                    "organization_id": str(self.default_org.id),
                },
            ).count(),
            1,
        )

    def test_post_save_radiusaccounting_does_not_fallback_to_other_org(
        self,
    ):
        """
        Test that a RegisteredUser from another organization is not used
        when accounting is written for the current organization.
        """
        user = self._create_user()
        self._create_registered_user(
            user=user, organization=self.default_org, method="mobile_phone"
        )
        org2 = self._create_org(name="metrics-org-2", slug="metrics-org-2")
        self._create_org_user(user=user, organization=org2)
        self._create_registered_user(user=user, organization=org2, method="email")
        device = self._create_device()
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "org_spec_001",
                "username": user.username,
                "called_station_id": device.mac_address.replace("-", ":").upper(),
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": "8000000000",
                "output_octets": "9000000000",
            }
        )
        options["stop_time"] = timezone.now()
        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration="radius_acc",
                name="RADIUS Accounting",
                key="radius_acc",
                object_id=str(device.id),
                content_type=ContentType.objects.get_for_model(self.device_model),
                extra_tags={
                    "called_station_id": device.mac_address,
                    "calling_station_id": sha1_hash("00:00:00:00:00:00"),
                    "location_id": str(device_loc.location.id),
                    "method": "mobile_phone",
                    "organization_id": str(self.default_org.id),
                },
            ).count(),
            1,
        )

    def test_write_user_registration_metrics(self):
        from ..tasks import write_user_registration_metrics

        # The TransactionTestCase truncates all the data after each test.
        # The general metrics and charts which are created by migrations
        # get deleted after each test. Therefore, we create them again here.
        # The "Metric._get_metric" caches the metric, this interferes with
        # create_general_metrics, hence we clear the cache here.
        cache.clear()
        create_general_metrics(None, None)
        org = self._get_org()
        user_signup_metric = self.metric_model.objects.get(key="user_signups")
        total_user_signup_metric = self.metric_model.objects.get(key="tot_user_signups")
        with self.subTest(
            "User does not has OrganizationUser and RegisteredUser object"
        ):
            self._get_admin()
            write_user_registration_metrics.delay()

            user_signup_chart = user_signup_metric.chart_set.first()
            all_points = self._read_chart(
                user_signup_chart, organization_id=["__all__"]
            )
            self.assertEqual(all_points["traces"][0][0], "unspecified")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(all_points["summary"], {"unspecified": 1})
            org_points = self._read_chart(
                user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(len(org_points["traces"]), 0)

            total_user_signup_chart = total_user_signup_metric.chart_set.first()
            all_points = self._read_chart(
                total_user_signup_chart, organization_id=["__all__"]
            )
            self.assertEqual(all_points["traces"][0][0], "unspecified")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(all_points["summary"], {"unspecified": 1})
            org_points = self._read_chart(
                total_user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(len(org_points["traces"]), 0)

        self.metric_model.post_delete_receiver(user_signup_metric)
        self.metric_model.post_delete_receiver(total_user_signup_metric)
        User.objects.all().delete()

        with self.subTest("User has OrganizationUser but no RegisteredUser object"):
            user = self._create_org_user(organization=org).user
            write_user_registration_metrics.delay()

            user_signup_chart = user_signup_metric.chart_set.first()
            all_points = self._read_chart(
                user_signup_chart, organization_id=["__all__"]
            )
            self.assertEqual(all_points["traces"][0][0], "unspecified")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(all_points["summary"], {"unspecified": 1})
            org_points = self._read_chart(
                user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(all_points["traces"][0][0], "unspecified")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(all_points["summary"], {"unspecified": 1})

            total_user_signup_chart = total_user_signup_metric.chart_set.first()
            all_points = self._read_chart(
                total_user_signup_chart, organization_id=["__all__"]
            )
            self.assertEqual(all_points["traces"][0][0], "unspecified")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(all_points["summary"], {"unspecified": 1})
            org_points = self._read_chart(
                total_user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(all_points["traces"][0][0], "unspecified")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(all_points["summary"], {"unspecified": 1})

        self.metric_model.post_delete_receiver(user_signup_metric)
        self.metric_model.post_delete_receiver(total_user_signup_metric)

        with self.subTest(
            "Test user has both OrganizationUser and RegisteredUser object"
        ):
            self._create_registered_user(user=user)
            write_user_registration_metrics.delay()

            user_signup_chart = user_signup_metric.chart_set.first()
            all_points = self._read_chart(
                user_signup_chart, organization_id=["__all__"]
            )
            self.assertEqual(all_points["traces"][0][0], "mobile_phone")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(all_points["summary"]["mobile_phone"], 1)
            self.assertEqual(all_points["summary"].get("unspecified", 0), 0)
            org_points = self._read_chart(
                user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(org_points["traces"][0][0], "mobile_phone")
            self.assertEqual(org_points["traces"][0][1][-1], 1)
            self.assertEqual(org_points["summary"]["mobile_phone"], 1)
            self.assertEqual(org_points["summary"].get("unspecified", 0), 0)

            total_user_signup_chart = total_user_signup_metric.chart_set.first()
            org_points = self._read_chart(
                total_user_signup_chart, organization_id=["__all__"]
            )
            self.assertEqual(org_points["traces"][0][0], "mobile_phone")
            self.assertEqual(org_points["traces"][0][1][-1], 1)
            self.assertEqual(org_points["summary"]["mobile_phone"], 1)
            self.assertEqual(org_points["summary"].get("unspecified", 0), 0)
            org_points = self._read_chart(
                total_user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(org_points["traces"][0][0], "mobile_phone")
            self.assertEqual(org_points["traces"][0][1][-1], 1)
            self.assertEqual(org_points["summary"]["mobile_phone"], 1)
            self.assertEqual(org_points["summary"].get("unspecified", 0), 0)

    def test_pending_verification_excluded_from_metrics(self):
        from ..tasks import write_user_registration_metrics

        cache.clear()
        create_general_metrics(None, None)
        org = self._create_org(name="pending_verification_test_org")
        user_signup_metric = self.metric_model.objects.get(key="user_signups")
        total_user_signup_metric = self.metric_model.objects.get(key="tot_user_signups")
        user = self._create_org_user(organization=org).user
        self._create_registered_user(
            user=user, organization=org, method="pending_verification"
        )
        write_user_registration_metrics.delay()

        user_signup_chart = user_signup_metric.chart_set.first()
        org_points = self._read_chart(user_signup_chart, organization_id=[str(org.pk)])
        all_points = self._read_chart(user_signup_chart, organization_id=["__all__"])
        self.assertEqual(len(org_points["traces"]), 0)
        self._assert_pending_verification_excluded(all_points)

        total_user_signup_chart = total_user_signup_metric.chart_set.first()
        org_points = self._read_chart(
            total_user_signup_chart, organization_id=[str(org.pk)]
        )
        all_points = self._read_chart(
            total_user_signup_chart, organization_id=["__all__"]
        )
        self.assertEqual(len(org_points["traces"]), 0)
        self._assert_pending_verification_excluded(all_points)

    def test_write_user_registration_metrics_uses_org_specific_methods(self):
        """
        Ensure organization metrics use the registration method associated
        with that specific organization membership.

        Scenario:
        - One user belongs to two organizations.
        - The user has one RegisteredUser row per organization.
        - Each RegisteredUser uses a different registration method.

        Expected behavior:
        - Global metrics aggregate both methods.
        - Each organization only counts its own method.
        """
        from ..tasks import write_user_registration_metrics

        def _get_metric_traces(metric_key, organization_id):
            chart = self.metric_model.objects.get(key=metric_key).chart_set.first()
            points = self._read_chart(
                chart,
                organization_id=[str(organization_id)],
            )
            return {trace_name: values[-1] for trace_name, values in points["traces"]}

        cache.clear()
        create_general_metrics(None, None)
        org1 = self._get_org()
        org2 = self._create_org(name="org2", slug="org2")
        user = self._create_user()
        self._create_org_user(user=user, organization=org1)
        self._create_org_user(user=user, organization=org2)
        self._create_registered_user(
            user=user,
            organization=org1,
            method="mobile_phone",
        )
        self._create_registered_user(
            user=user,
            organization=org2,
            method="email",
        )
        write_user_registration_metrics.delay()
        for metric_key in ["user_signups", "tot_user_signups"]:
            all_points = _get_metric_traces(metric_key, "__all__")
            org1_points = _get_metric_traces(metric_key, org1.pk)
            org2_points = _get_metric_traces(metric_key, org2.pk)

            # Global metrics aggregate registrations from all organizations.
            self.assertEqual(all_points.get("mobile_phone", 0), 1)
            self.assertEqual(all_points.get("email", 0), 1)

            # org1 only counts its own registration method.
            self.assertEqual(org1_points.get("mobile_phone", 0), 1)
            self.assertEqual(org1_points.get("email", 0), 0)

            # org2 only counts its own registration method.
            self.assertEqual(org2_points.get("email", 0), 1)
            self.assertEqual(org2_points.get("mobile_phone", 0), 0)

    def test_write_user_registration_metrics_scopes_membership_window_per_org(
        self,
    ):
        """
        Ensure signup metrics scope organization membership windows per organization.

        Scenario:
        - One user belongs to two organizations.
        - The membership in org1 was created before the metric window.
        - The membership in org2 was created within the metric window.
        - The user has a RegisteredUser only for org1.

        Expected behavior:
        - org1 does not count the user in ``user_signups`` because the
        membership is outside the current window.
        - org2 counts the user as ``unspecified`` in ``user_signups`` because
        the membership is within the current window and no RegisteredUser
        exists for org2.
        - ``tot_user_signups`` still counts org1 with its registration method.
        - org2 must not inherit org1's registration method.
        """
        from ..tasks import write_user_registration_metrics

        cache.clear()
        create_general_metrics(None, None)
        org1 = self._get_org()
        org2 = self._create_org(name="org2-window-scope", slug="org2-window-scope")
        old_time = timezone.now() - timezone.timedelta(hours=2)
        user = self._create_user(date_joined=old_time)
        org1_membership = self._create_org_user(
            user=user,
            organization=org1,
        )
        OrganizationUser.objects.filter(pk=org1_membership.pk).update(created=old_time)
        self._create_registered_user(
            user=user,
            organization=org1,
            method="mobile_phone",
        )
        self._create_org_user(
            user=user,
            organization=org2,
        )

        write_user_registration_metrics.delay()

        org1_user_signups = self._get_metric_traces("user_signups", org1.pk)
        org2_user_signups = self._get_metric_traces("user_signups", org2.pk)
        org1_total_signups = self._get_metric_traces("tot_user_signups", org1.pk)
        org2_total_signups = self._get_metric_traces("tot_user_signups", org2.pk)
        self.assertEqual(org1_user_signups.get("mobile_phone", 0), 0)
        self.assertEqual(org2_user_signups.get("unspecified", 0), 1)
        self.assertEqual(org1_total_signups.get("mobile_phone", 0), 1)
        self.assertEqual(org2_total_signups.get("unspecified", 0), 1)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_reconciliation_reports_growth_after_session_reopens(self, batch_write):
        device = self._create_device()
        options = _RADACCT.copy()
        options.update(
            unique_id="reopened-session",
            called_station_id=device.mac_address,
            calling_station_id="00:00:00:00:00:00",
            input_octets=100,
            output_octets=200,
            stop_time=timezone.now(),
        )
        session = self._create_radius_accounting(**options)
        reconcile_radius_traffic(seed=True)
        batch_write.reset_mock()
        RadiusAccounting.objects.filter(pk=session.pk).update(
            stop_time=None, input_octets=120, output_octets=230
        )
        reconcile_radius_traffic()
        points = batch_write.call_args.args[0]
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0][1]["value"], 20)
        self.assertEqual(points[0][1]["extra_values"]["output_octets"], 30)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_cleanup_preserves_traffic_since_previous_observation(self, batch_write):
        device = self._create_device()
        options = _RADACCT.copy()
        options.update(
            unique_id="expired-session",
            called_station_id=device.mac_address,
            calling_station_id="00:00:00:00:00:00",
            input_octets=20,
            output_octets=20,
            stop_time=timezone.now() - timezone.timedelta(days=20),
        )
        self._create_radius_accounting(**options)
        options.update(
            unique_id="retained-session",
            input_octets=80,
            output_octets=80,
            stop_time=None,
        )
        session = self._create_radius_accounting(**options)
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            input_octets=95, output_octets=95
        )
        output = StringIO()
        call_command("delete_old_radacct", 10, stdout=output)
        self.assertEqual(
            output.getvalue().strip(), "Deleted sessions older than 10 days"
        )
        batch_write.reset_mock()
        reconcile_radius_traffic()
        points = batch_write.call_args.args[0]
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0][1]["value"], 15)
        self.assertEqual(points[0][1]["extra_values"]["output_octets"], 15)

    @patch(f"{TASK_PATH}.Metric.write")
    def test_closed_session_writes_user_without_traffic(self, write):
        device = self._create_device()
        post_save_radiusaccounting(
            username="test-user",
            organization_id=str(self.default_org.pk),
            input_octets=100,
            output_octets=200,
            calling_station_id="00:11:22:33:44:55",
            called_station_id=device.mac_address,
        )
        self.assertEqual(write.call_args.args[0], 0)
        self.assertEqual(write.call_args.kwargs["extra_values"]["output_octets"], 0)
        self.assertEqual(
            write.call_args.kwargs["extra_values"]["username"], sha1_hash("test-user")
        )
        self.assertEqual(write.call_args.kwargs["check"], False)

    @patch(f"{TASK_PATH}.post_save_radiusaccounting.delay")
    def test_accounting_totals_group_sessions_and_missing_counters(self, closed):
        options = _RADACCT.copy()
        options.update(
            unique_id="totals-closed",
            called_station_id="AA-BB-CC-DD-EE-FF",
            input_octets=100,
            output_octets=None,
            stop_time=timezone.now(),
        )
        self._create_radius_accounting(**options)
        closed.assert_called_once()
        options.update(
            unique_id="totals-open",
            called_station_id="aa:bb:cc:dd:ee:ff",
            input_octets=None,
            output_octets=200,
            stop_time=None,
        )
        self._create_radius_accounting(**options)
        totals = list(_accounting_totals(RadiusAccounting.objects.all()))
        self.assertEqual(
            totals,
            [
                {
                    "organization_id": self.default_org.pk,
                    "station": "aa:bb:cc:dd:ee:ff",
                    "input_total": 100,
                    "output_total": 200,
                }
            ],
        )

    def test_reconciliation_calculates_directions_independently(self):
        self.assertEqual(
            _traffic_delta(
                group=("organization", "station"),
                previous=(100, 200),
                current=(120, 250),
            ),
            (20, 50),
        )

    @patch(f"{TASK_PATH}.logger.warning")
    def test_reconciliation_reports_decreases_without_negative_traffic(self, warning):
        group = ("organization", "station")
        self.assertEqual(
            _traffic_delta(group=group, previous=(100, 200), current=(90, 250)),
            (0, 50),
        )
        warning.assert_called_once()

    def test_reconciliation_keeps_growth_with_negative_baseline(self):
        self.assertEqual(
            _traffic_delta(
                group=("organization", "station"),
                previous=(-20, -30),
                current=(0, 0),
            ),
            (20, 30),
        )

    @patch(f"{TASK_PATH}.Metric.read")
    def test_checkpoint_recovery_uses_stable_accounting_group(self, read):
        read.return_value = [
            {
                "time": "2026-01-01T00:00:00Z",
                "baseline_input": 100,
                "baseline_output": 200,
            }
        ]
        self.assertEqual(_recover_baseline("organization", "aa:bb"), (100, 200))
        self.assertEqual(
            read.call_args.kwargs["tags"],
            {
                "accounting_organization_id": "organization",
                "called_station_id": "aa:bb",
            },
        )

    @patch(f"{TASK_PATH}.Metric.read")
    def test_checkpoint_recovery_selects_latest_across_device_locations(self, read):
        read.return_value = [
            {
                "time": "2026-01-02T00:00:00Z",
                "baseline_input": 120,
                "baseline_output": 230,
            },
            {
                "time": "2026-01-01T00:00:00Z",
                "baseline_input": 100,
                "baseline_output": 200,
            },
        ]
        self.assertEqual(_recover_baseline("organization", "aa:bb"), (120, 230))

    def test_checkpoint_recovery_excludes_session_closure_points(self):
        tags = {
            "accounting_organization_id": str(self.default_org.pk),
            "called_station_id": "aa:bb:cc:dd:ee:ff",
        }
        metric = self.metric_model(
            key="radius_acc",
            configuration="radius_acc",
            field_name="input_octets",
            extra_tags=tags,
        )
        now = timezone.now()
        metric.write(
            0,
            extra_values={
                "output_octets": 0,
                "baseline_input": 100,
                "baseline_output": 200,
            },
            time=now - timezone.timedelta(minutes=1),
            check=False,
        )
        metric.write(
            0,
            extra_values={"output_octets": 0, "username": sha1_hash("test-user")},
            time=now,
            check=False,
        )
        self.assertEqual(
            _recover_baseline(str(self.default_org.pk), tags["called_station_id"]),
            (100, 200),
        )

    def test_checkpoint_recovery_after_location_change(self):
        tags = {
            "accounting_organization_id": str(self.default_org.pk),
            "called_station_id": "aa:bb:cc:dd:ee:ff",
            "location_id": "previous-location",
        }
        metric = self.metric_model(
            key="radius_acc",
            configuration="radius_acc",
            field_name="input_octets",
            extra_tags=tags,
        )
        metric.write(
            0,
            extra_values={
                "output_octets": 0,
                "baseline_input": 100,
                "baseline_output": 200,
            },
            time=timezone.now() - timezone.timedelta(minutes=1),
            check=False,
        )
        tags["location_id"] = "current-location"
        metric.extra_tags = tags
        metric.write(
            0,
            extra_values={
                "output_octets": 0,
                "baseline_input": 120,
                "baseline_output": 230,
            },
            check=False,
        )
        self.assertEqual(
            _recover_baseline(str(self.default_org.pk), tags["called_station_id"]),
            (120, 230),
        )

    @patch(
        f"{TASK_PATH}.cache",
        new_callable=lambda: LocMemCache("reconciliation-lock-test", {}),
    )
    def test_reconciliation_lock_prevents_overlapping_operations(self, test_cache):
        with _reconciliation_lock() as acquired:
            self.assertEqual(acquired, True)
            with _reconciliation_lock() as overlapping:
                self.assertEqual(overlapping, False)
        with _reconciliation_lock() as acquired_after_release:
            self.assertEqual(acquired_after_release, True)

    @patch(
        f"{TASK_PATH}.cache",
        new_callable=lambda: LocMemCache("reconciliation-lock-replacement-test", {}),
    )
    def test_reconciliation_lock_does_not_delete_a_replacement_lock(self, test_cache):
        with _reconciliation_lock() as acquired:
            self.assertEqual(acquired, True)
            test_cache.set(RECONCILIATION_LOCK_KEY, "replacement", timeout=60)
        self.assertEqual(test_cache.get(RECONCILIATION_LOCK_KEY), "replacement")

    def _create_traffic_session(self, **kwargs):
        options = _RADACCT.copy()
        options.update(
            unique_id="traffic-session",
            called_station_id=self.TEST_MAC_ADDRESS,
            calling_station_id="00:00:00:00:00:00",
            input_octets=100,
            output_octets=200,
            stop_time=None,
        )
        options.update(kwargs)
        return self._create_radius_accounting(**options)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_reconciliation_seeds_then_counts_new_groups(self, batch_write):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 0)
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=130)
        self._create_traffic_session(
            unique_id="new-group",
            called_station_id="00:22:33:44:55:66",
            input_octets=10,
            output_octets=None,
        )
        batch_write.reset_mock()
        with patch(f"{TASK_PATH}.logger.warning"):
            reconcile_radius_traffic()
        points = [
            point for call in batch_write.call_args_list for point in call.args[0]
        ]
        self.assertEqual(sorted(point[1]["value"] for point in points), [10, 30])
        self.assertEqual(
            sorted(point[1]["extra_values"]["output_octets"] for point in points),
            [0, 0],
        )
        self.assertEqual(len(points), 2)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_submission_failure_retries_same_point_before_new_growth(self, batch_write):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=120)
        batch_write.side_effect = RuntimeError("broker unavailable")
        with self.assertRaisesMessage(RuntimeError, "broker unavailable"):
            reconcile_radius_traffic()
        pending = batch_write.call_args.args[0]
        self.assertEqual(pending[0][1]["value"], 20)
        saved = cache.get(RECONCILIATION_STATE_KEY)
        batch_write.reset_mock()
        with patch(
            f"{TASK_PATH}._accounting_totals", side_effect=DatabaseError("offline")
        ):
            with self.assertRaisesMessage(DatabaseError, "offline"):
                reconcile_radius_traffic()
        batch_write.assert_not_called()
        self.assertEqual(
            cache.get(RECONCILIATION_STATE_KEY)["queued"][0][1],
            saved["queued"][0][1],
        )
        self.assertEqual(cache.get(RECONCILIATION_STATE_KEY)["groups"], saved["groups"])
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=135)
        batch_write.reset_mock()
        batch_write.side_effect = None
        reconcile_radius_traffic()
        retried = batch_write.call_args_list[0].args[0]
        self.assertEqual(retried[0][1], pending[0][1])
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 15)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_query_and_recovery_failures_preserve_cached_state(self, batch_write):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        saved = cache.get(RECONCILIATION_STATE_KEY)
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=120)
        batch_write.reset_mock()
        with patch(
            f"{TASK_PATH}._accounting_totals", side_effect=DatabaseError("offline")
        ):
            with self.assertRaisesMessage(DatabaseError, "offline"):
                reconcile_radius_traffic()
        self.assertEqual(cache.get(RECONCILIATION_STATE_KEY), saved)
        batch_write.assert_not_called()
        cache.delete(RECONCILIATION_STATE_KEY)
        with patch(
            f"{TASK_PATH}.Metric.read", side_effect=RuntimeError("TSDB offline")
        ):
            with self.assertRaisesMessage(RuntimeError, "TSDB offline"):
                reconcile_radius_traffic()
        self.assertEqual(cache.get(RECONCILIATION_STATE_KEY), None)
        batch_write.assert_not_called()

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_invalid_payload_is_not_submitted_or_saved(self, batch_write):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        saved = cache.get(RECONCILIATION_STATE_KEY)
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=120)
        batch_write.reset_mock()
        with patch(
            f"{TASK_PATH}.Metric.write", side_effect=ValueError("invalid field")
        ):
            with self.assertRaisesMessage(ValueError, "invalid field"):
                reconcile_radius_traffic()
        batch_write.assert_not_called()
        self.assertEqual(cache.get(RECONCILIATION_STATE_KEY), saved)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_cleanup_last_row_preserves_growth_and_negative_baseline(self, batch_write):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            input_octets=120,
            output_octets=230,
            stop_time=timezone.now() - timezone.timedelta(days=20),
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        state = cache.get(RECONCILIATION_STATE_KEY)
        group = (str(self.default_org.pk), self.TEST_MAC_ADDRESS)
        self.assertEqual(state["groups"][group], (-20, -30))
        checkpoint = batch_write.call_args.args[0][0][1]
        self.assertEqual(checkpoint["value"], 0)
        self.assertEqual(checkpoint["extra_values"]["baseline_input"], -20)
        reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 20)
        self.assertEqual(
            batch_write.call_args.args[0][0][1]["extra_values"]["output_octets"], 30
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 0)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_cleanup_rollback_does_not_adjust_baseline(self, batch_write):
        self._create_device()
        self._create_traffic_session(
            stop_time=timezone.now() - timezone.timedelta(days=20)
        )
        reconcile_radius_traffic(seed=True)
        saved = cache.get(RECONCILIATION_STATE_KEY)
        batch_write.reset_mock()
        queryset_class = type(RadiusAccounting.objects.all())
        original_delete = queryset_class.delete

        def delete_then_fail(queryset):
            original_delete(queryset)
            raise DatabaseError("rollback")

        with patch.object(queryset_class, "delete", delete_then_fail):
            with self.assertRaisesMessage(DatabaseError, "rollback"):
                call_command("delete_old_radacct", 10, stdout=StringIO())
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        self.assertEqual(cache.get(RECONCILIATION_STATE_KEY), saved)
        batch_write.assert_not_called()

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_cleanup_submission_failure_retains_adjustment_for_retry(self, batch_write):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            input_octets=125,
            stop_time=timezone.now() - timezone.timedelta(days=20),
        )
        batch_write.side_effect = RuntimeError("broker offline")
        with self.assertRaisesMessage(RuntimeError, "broker offline"):
            call_command("delete_old_radacct", 10, stdout=StringIO())
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        checkpoint = batch_write.call_args.args[0][0][1]
        self.assertEqual(checkpoint["extra_values"]["baseline_input"], -25)
        batch_write.side_effect = None
        batch_write.reset_mock()
        reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args_list[0].args[0][0][1], checkpoint)
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 25)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_cleanup_before_activation_does_not_create_baselines(self, batch_write):
        self._create_device()
        self._create_traffic_session(
            stop_time=timezone.now() - timezone.timedelta(days=20)
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        self.assertEqual(cache.get(RECONCILIATION_STATE_KEY), None)
        batch_write.assert_not_called()

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_reconciliation_and_cleanup_read_only_under_lock(self, batch_write):
        with _reconciliation_lock() as acquired:
            self.assertEqual(acquired, True)
            with patch(f"{TASK_PATH}._accounting_totals") as totals:
                reconcile_radius_traffic()
                with self.assertRaisesMessage(Exception, "retry cleanup"):
                    call_command("delete_old_radacct", 10, stdout=StringIO())
            totals.assert_not_called()
        batch_write.assert_not_called()

    def test_cleanup_checkpoint_recovers_after_cache_loss(self):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            input_octets=125,
            stop_time=timezone.now() - timezone.timedelta(days=20),
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        # Keep a retained row in the group so recovery can discover it in SQL.
        self._create_traffic_session(unique_id="retained", input_octets=10)
        cache.delete(RECONCILIATION_STATE_KEY)
        with patch(f"{TASK_PATH}.Metric.batch_write") as batch_write:
            reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 35)

    def test_previously_unmatched_device_keeps_recovered_baseline(self):
        session = self._create_traffic_session()
        with patch(f"{TASK_PATH}.logger.warning"):
            reconcile_radius_traffic(seed=True)
        device = self._create_device()
        cache.delete(RECONCILIATION_STATE_KEY)
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=125)
        with patch(f"{TASK_PATH}.Metric.batch_write") as batch_write:
            reconcile_radius_traffic()
        metric, options = batch_write.call_args.args[0][0]
        self.assertEqual(options["value"], 25)
        self.assertEqual(metric.object_id, str(device.pk))

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_cleanup_keeps_reopened_session(self, batch_write):
        self._create_device()
        session = self._create_traffic_session(
            stop_time=timezone.now() - timezone.timedelta(days=20)
        )
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            stop_time=None, input_octets=120
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        session.refresh_from_db()
        self.assertEqual(session.stop_time, None)
        reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 20)

    def setUp(self):
        cache.delete(RECONCILIATION_STATE_KEY)
        super().setUp()

    def test_hourly_points_preserve_device_general_and_location_charts(self):
        device = self._create_device()
        previous_location = self._create_location(organization=device.organization)
        device_location = self._create_device_location(
            content_object=device, location=previous_location
        )
        first_session = self._create_traffic_session(input_octets=10**9)
        second_session = self._create_traffic_session(
            unique_id="second-session", input_octets=2 * 10**9
        )
        reconcile_radius_traffic(seed=True)
        current_location = self._create_location(
            name="current-location", organization=device.organization
        )
        device_location.location = current_location
        device_location.full_clean()
        device_location.save()
        RadiusAccounting.objects.filter(pk=first_session.pk).update(
            input_octets=2 * 10**9, output_octets=10**9
        )
        RadiusAccounting.objects.filter(pk=second_session.pk).update(
            input_octets=4 * 10**9, output_octets=2 * 10**9
        )
        reconcile_radius_traffic()
        create_general_metrics(None, None)
        general_chart = self.chart_model.objects.get(configuration="gen_rad_traffic")
        self.assertEqual(general_chart.read()["summary"]["download"], 3)
        metric = self.metric_model.objects.get(
            object_id=str(device.pk),
            extra_tags__location_id=str(current_location.pk),
        )
        points = metric.read(fields=["input_octets", "baseline_input"])
        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["input_octets"], 3 * 10**9)
        self.assertEqual(points[0]["baseline_input"], 6 * 10**9)
        self.assertEqual(metric.extra_tags["organization_id"], str(self.default_org.pk))
        self.assertNotIn("username", metric.extra_tags)
        self.assertEqual(
            metric.chart_set.get(configuration="radius_traffic").read()["summary"][
                "download"
            ],
            3,
        )
        self.assertEqual(
            self._read_chart(
                general_chart,
                organization_id=[str(self.default_org.pk)],
                location_id=[str(current_location.pk)],
            )["summary"]["download"],
            3,
        )

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_hourly_groups_preserve_organization_isolation_and_shared_accounting(
        self, batch_write
    ):
        device = self._create_device()
        other_org = self._create_org(name="other-organization")
        own_session = self._create_traffic_session()
        shared_session = self._create_traffic_session(
            unique_id="shared-session", organization=other_org
        )
        with patch(f"{TASK_PATH}.logger.warning"):
            reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=own_session.pk).update(input_octets=110)
        RadiusAccounting.objects.filter(pk=shared_session.pk).update(input_octets=120)
        batch_write.reset_mock()
        with patch.object(monitoring_settings, "SHARED_ACCOUNTING", False):
            with patch(f"{TASK_PATH}.logger.warning"):
                reconcile_radius_traffic()
        points = {
            point[0].extra_tags["accounting_organization_id"]: point
            for call in batch_write.call_args_list
            for point in call.args[0]
        }
        own_metric, own_options = points[str(self.default_org.pk)]
        unmatched_metric, unmatched_options = points[str(other_org.pk)]
        self.assertEqual(own_metric.object_id, str(device.pk))
        self.assertEqual(own_options["value"], 10)
        self.assertEqual(unmatched_metric.object_id, None)
        self.assertEqual(unmatched_options["value"], 20)
        RadiusAccounting.objects.filter(pk=shared_session.pk).update(input_octets=135)
        batch_write.reset_mock()
        with patch.object(monitoring_settings, "SHARED_ACCOUNTING", True):
            reconcile_radius_traffic()
        points = {
            point[0].extra_tags["accounting_organization_id"]: point
            for call in batch_write.call_args_list
            for point in call.args[0]
        }
        shared_metric, shared_options = points[str(other_org.pk)]
        self.assertEqual(shared_metric.object_id, str(device.pk))
        self.assertEqual(shared_options["value"], 15)
        self.assertEqual(shared_metric.extra_tags["organization_id"], str(other_org.pk))

    def test_recovery_includes_group_whose_last_row_was_deleted(self):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            input_octets=125, stop_time=timezone.now() - timezone.timedelta(days=20)
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        cache.delete(RECONCILIATION_STATE_KEY)
        with patch(f"{TASK_PATH}.Metric.batch_write") as batch_write:
            reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 25)

    def test_empty_initialization_recovers_before_first_session(self):
        output = StringIO()
        call_command("seed_radius_traffic", stdout=output)
        self.assertEqual(output.getvalue(), "RADIUS traffic baselines initialized.\n")
        cache.delete(RECONCILIATION_STATE_KEY)
        self._create_device()
        self._create_traffic_session(input_octets=25)
        with patch(f"{TASK_PATH}.Metric.batch_write") as batch_write:
            reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 25)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_successive_cleanup_runs_subtract_only_deleted_rows(self, batch_write):
        self._create_device()
        first_session = self._create_traffic_session()
        second_session = self._create_traffic_session(unique_id="second-session")
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=first_session.pk).update(
            input_octets=125, stop_time=timezone.now() - timezone.timedelta(days=20)
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        RadiusAccounting.objects.filter(pk=second_session.pk).update(
            input_octets=130, stop_time=timezone.now() - timezone.timedelta(days=20)
        )
        call_command("delete_old_radacct", 10, stdout=StringIO())
        reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 55)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_reconciliation_uses_new_totals_after_independent_counter_decrease(
        self, batch_write
    ):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            input_octets=90, output_octets=220
        )
        with patch(f"{TASK_PATH}.logger.warning") as warning:
            reconcile_radius_traffic()
        warning.assert_called_once()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 0)
        self.assertEqual(
            batch_write.call_args.args[0][0][1]["extra_values"]["output_octets"], 20
        )
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=105)
        reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 15)

    @patch("openwisp_monitoring.monitoring.tasks.timeseries_batch_write.delay")
    def test_reconciliation_advances_after_queue_submission_not_persistence(
        self, delay
    ):
        self._create_device()
        session = self._create_traffic_session()
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.filter(pk=session.pk).update(input_octets=125)
        delay.reset_mock()
        reconcile_radius_traffic()
        delay.assert_called_once()
        queued = delay.call_args.kwargs["data"]
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0]["values"]["input_octets"], 25)
        self.assertEqual(queued[0]["values"]["baseline_input"], 125)
        self.assertNotIn("username", queued[0]["values"])
        self.assertIn("check_threshold_kwargs", queued[0])
        state = cache.get(RECONCILIATION_STATE_KEY)
        self.assertEqual(state["queued"], None)
        self.assertEqual(
            state["groups"][(str(self.default_org.pk), self.TEST_MAC_ADDRESS)],
            (125, 200),
        )
        self.assertEqual(
            self.metric_model.objects.get(configuration="radius_acc").read(), []
        )

    @patch(f"{TASK_PATH}.Metric.read", side_effect=RuntimeError("TSDB offline"))
    @patch(f"{TASK_PATH}.Metric.write")
    def test_closure_does_not_restore_traffic_during_recovery_outage(self, write, read):
        self._create_device()
        post_save_radiusaccounting(
            username="test-user",
            organization_id=str(self.default_org.pk),
            input_octets=100,
            output_octets=200,
            calling_station_id="00:11:22:33:44:55",
            called_station_id=self.TEST_MAC_ADDRESS,
        )
        self.assertEqual(write.call_args.args[0], 0)
        self.assertEqual(write.call_args.kwargs["extra_values"]["output_octets"], 0)
        self.assertEqual(write.call_args.kwargs["check"], False)
        read.assert_not_called()

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_cleanup_aggregates_all_expired_sessions_before_commit(self, batch_write):
        self._create_device()
        options = _RADACCT.copy()
        options.update(
            organization=self.default_org,
            called_station_id=self.TEST_MAC_ADDRESS,
            input_octets=1,
            output_octets=2,
            start_time=timezone.now() - timezone.timedelta(days=30),
            stop_time=timezone.now() - timezone.timedelta(days=20),
        )
        # Generate volume, not test scenarios. Bypass closure signals because
        # these rows represent retained history already reported before cutover.
        RadiusAccounting.objects.bulk_create(
            [
                RadiusAccounting(
                    **(options | {"unique_id": f"expired-{session_number}"})
                )
                for session_number in range(1001)
            ]
        )
        reconcile_radius_traffic(seed=True)
        RadiusAccounting.objects.update(input_octets=2)
        batch_write.reset_mock()
        original_on_commit = transaction.on_commit
        callbacks = []

        def register_callback(callback, *args, **kwargs):
            def verified_callback():
                self.assertEqual(transaction.get_connection().in_atomic_block, False)
                self.assertEqual(RadiusAccounting.objects.count(), 0)
                with _reconciliation_lock() as acquired:
                    self.assertEqual(acquired, False)
                callbacks.append(callback)
                callback()

            original_on_commit(verified_callback, *args, **kwargs)

        with patch(
            "openwisp_radius.management.commands.base."
            "delete_old_radacct.transaction.on_commit",
            side_effect=register_callback,
        ):
            call_command("delete_old_radacct", 10, stdout=StringIO())
        self.assertEqual(len(callbacks), 1)
        batch_write.assert_called_once()
        checkpoint = batch_write.call_args.args[0][0][1]
        self.assertEqual(checkpoint["value"], 0)
        self.assertEqual(checkpoint["extra_values"]["baseline_input"], -1001)
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        reconcile_radius_traffic()
        self.assertEqual(batch_write.call_args.args[0][0][1]["value"], 1001)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    def test_reconciliation_validates_whole_batch_before_queueing(self, batch_write):
        self._create_device()
        self._create_traffic_session()
        self._create_traffic_session(
            unique_id="another-group", called_station_id="00:22:33:44:55:66"
        )
        with patch(f"{TASK_PATH}.logger.warning"):
            reconcile_radius_traffic(seed=True)
        saved = cache.get(RECONCILIATION_STATE_KEY)
        RadiusAccounting.objects.update(input_octets=125)
        prepared = []

        def prepare_point(*args, **kwargs):
            point = _traffic_point(*args, **kwargs)
            prepared.append(point)
            if len(prepared) == 2:
                point[1]["extra_values"]["invalid_field"] = 1
            return point

        batch_write.reset_mock()
        with patch(f"{TASK_PATH}._traffic_point", side_effect=prepare_point):
            with patch(f"{TASK_PATH}.logger.warning"):
                with self.assertRaisesMessage(ValueError, "invalid_field"):
                    reconcile_radius_traffic()
        batch_write.assert_not_called()
        self.assertEqual(cache.get(RECONCILIATION_STATE_KEY), saved)

    @patch(f"{TASK_PATH}.Metric.batch_write")
    @patch(f"{TASK_PATH}._recover_baseline", return_value=None)
    def test_reconciliation_processes_groups_beyond_first_batch(
        self, recover, batch_write
    ):
        metric = self.metric_model(
            key="radius_acc", configuration="radius_acc", field_name="input_octets"
        )
        # SQL aggregation and device lookup have separate coverage. Synthetic
        # groups make the batching boundary independent of device setup cost.
        rows = [
            {
                "organization_id": self.default_org.pk,
                "station": f"station-{group_number}",
                "input_total": 50,
                "output_total": 100,
            }
            for group_number in range(1001)
        ]
        with patch(f"{TASK_PATH}._accounting_totals", return_value=iter(rows)):
            with patch(f"{TASK_PATH}._accounting_metric", return_value=metric):
                reconcile_radius_traffic(seed=True)
        self.assertEqual(
            [len(call.args[0]) for call in batch_write.call_args_list], [1000, 1]
        )
        self.assertEqual(len(cache.get(RECONCILIATION_STATE_KEY)["groups"]), 1001)
        current_rows = [row | {"input_total": 75} for row in rows]
        batch_write.reset_mock()
        with patch(f"{TASK_PATH}._accounting_totals", return_value=iter(current_rows)):
            with patch(f"{TASK_PATH}._accounting_metric", return_value=metric):
                reconcile_radius_traffic()
        self.assertEqual(
            [len(call.args[0]) for call in batch_write.call_args_list], [1000, 1]
        )
        self.assertEqual(
            sum(
                point[1]["value"]
                for call in batch_write.call_args_list
                for point in call.args[0]
            ),
            1001 * 25,
        )
