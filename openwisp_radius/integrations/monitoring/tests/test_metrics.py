from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.test import tag
from django.utils import timezone
from swapper import load_model

from openwisp_radius.tests import _RADACCT
from openwisp_radius.tests.mixins import BaseTransactionTestCase

from ..migrations import create_general_metrics
from ..utils import sha1_hash
from .mixins import CreateDeviceMonitoringMixin

TASK_PATH = "openwisp_radius.integrations.monitoring.tasks"

RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
OrganizationUser = load_model("openwisp_users", "OrganizationUser")
RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")
User = get_user_model()


@tag("radius_monitoring")
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
        self.assertEqual(points["traces"][0][1][-1], 8)
        self.assertEqual(points["traces"][1][0], "upload")
        self.assertEqual(points["traces"][1][1][-1], 9)
        self.assertEqual(points["summary"], {"upload": 9, "download": 8})

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

    @patch("openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting")
    def test_post_save_radiusaccouting_open_session(self, mocked_task):
        radius_options = _RADACCT.copy()
        radius_options["unique_id"] = "117"
        session = self._create_radius_accounting(**radius_options)
        self.assertEqual(session.stop_time, None)
        mocked_task.assert_not_called()

    @patch(
        "openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting.delay"
    )
    def test_accounting_on_nas_reboot_writes_monitoring_metric(self, mocked_delay):
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
        RadiusAccounting._close_stale_sessions_on_nas_boot(
            called_station_id=radius_options["called_station_id"]
        )
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
    def test_close_previous_radius_accounting_writes_monitoring_metric(
        self, mocked_delay
    ):
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
            self.assertEqual(points["traces"][0][1][-1], 8)
            self.assertEqual(points["traces"][1][0], "upload")
            self.assertEqual(points["traces"][1][1][-1], 9)
            self.assertEqual(points["summary"], {"upload": 9, "download": 8})

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
        self.assertEqual(points["traces"][0][1][-1], 8)
        self.assertEqual(points["traces"][1][0], "upload")
        self.assertEqual(points["traces"][1][1][-1], 9)
        self.assertEqual(points["summary"], {"upload": 9, "download": 8})

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
        self.assertEqual(points["traces"][0][1][-1], 8)
        self.assertEqual(points["traces"][1][0], "upload")
        self.assertEqual(points["traces"][1][1][-1], 9)
        self.assertEqual(points["summary"], {"upload": 9, "download": 8})

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
            self.assertEqual(
                all_points["summary"], {"mobile_phone": 1, "unspecified": 0}
            )
            org_points = self._read_chart(
                user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(all_points["traces"][0][0], "mobile_phone")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(
                all_points["summary"], {"mobile_phone": 1, "unspecified": 0}
            )

            total_user_signup_chart = total_user_signup_metric.chart_set.first()
            org_points = self._read_chart(
                total_user_signup_chart, organization_id=["__all__"]
            )
            self.assertEqual(org_points["traces"][0][0], "mobile_phone")
            self.assertEqual(org_points["traces"][0][1][-1], 1)
            self.assertEqual(
                org_points["summary"], {"mobile_phone": 1, "unspecified": 0}
            )
            org_points = self._read_chart(
                total_user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(all_points["traces"][0][0], "mobile_phone")
            self.assertEqual(all_points["traces"][0][1][-1], 1)
            self.assertEqual(
                all_points["summary"], {"mobile_phone": 1, "unspecified": 0}
            )

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
