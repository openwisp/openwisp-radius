from io import StringIO
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import tag
from django.utils import timezone
from swapper import load_model

from openwisp_radius.integrations.monitoring.tests.mixins import (
    CreateDeviceMonitoringMixin,
)
from openwisp_radius.integrations.monitoring.utils import sha1_hash
from openwisp_radius.tests import _RADACCT
from openwisp_radius.tests.mixins import BaseTransactionTestCase

RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")


@tag("radius_monitoring", "rebuild_radius_accounting_metrics")
class TestRebuildRadiusAccountingMetrics(
    CreateDeviceMonitoringMixin, BaseTransactionTestCase
):
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

    def _create_closed_accounting_without_metric(self, **kwargs):
        options = _RADACCT.copy()
        options.update(
            {
                "unique_id": "closed-without-metric",
                "calling_station_id": "00:00:00:00:00:00",
                "input_octets": 8000000000,
                "output_octets": 9000000000,
            }
        )
        options.update(kwargs)
        stop_time = options.pop("stop_time", timezone.now())
        terminate_cause = options.pop("terminate_cause", "NAS-Reboot")
        session = self._create_radius_accounting(**options)
        RadiusAccounting.objects.filter(pk=session.pk).update(
            stop_time=stop_time,
            terminate_cause=terminate_cause,
        )
        session.refresh_from_db()
        return session

    def test_rebuild_radius_accounting_metrics_dry_run(self):
        user = self._create_user()
        device = self._create_device()
        self._create_registered_user(user=user)
        self._create_closed_accounting_without_metric(
            username=user.username,
            called_station_id=device.mac_address.replace("-", ":").upper(),
        )
        out = StringIO()
        call_command("rebuild_radius_accounting_metrics", stdout=out)
        self.assertIn("Dry run: 1 closed sessions would be processed.", out.getvalue())
        self.assertEqual(
            self.metric_model.objects.filter(configuration="radius_acc").count(), 0
        )

    @patch(
        "openwisp_radius.integrations.monitoring.management.commands."
        "rebuild_radius_accounting_metrics.timeseries_db.query"
    )
    @patch("logging.Logger.warning")
    def test_rebuild_radius_accounting_metrics_commit(
        self, mocked_warning, mocked_query
    ):
        user = self._create_user()
        reg_user = self._create_registered_user(user=user)
        device = self._create_device()
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        session = self._create_closed_accounting_without_metric(
            username=user.username,
            called_station_id=device.mac_address.replace("-", ":").upper(),
        )
        out = StringIO()
        call_command("rebuild_radius_accounting_metrics", commit=True, stdout=out)
        self.assertIn("Processed 1 closed sessions.", out.getvalue())
        delete_queries = [
            call.args[0]
            for call in mocked_query.call_args_list
            if call.args[0].startswith("DELETE FROM radius_acc")
        ]
        self.assertEqual(len(delete_queries), 1)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration="radius_acc",
                name="RADIUS Accounting",
                key="radius_acc",
                object_id=str(device.id),
                content_type=ContentType.objects.get_for_model(self.device_model),
                extra_tags={
                    "called_station_id": device.mac_address,
                    "calling_station_id": sha1_hash(session.calling_station_id),
                    "location_id": str(device_loc.location.id),
                    "method": reg_user.method,
                    "organization_id": str(self.default_org.id),
                },
            ).count(),
            1,
        )

    @patch("logging.Logger.warning")
    def test_rebuild_radius_accounting_metrics_nas_reboot_filter(self, *args):
        user = self._create_user()
        device = self._create_device()
        self._create_registered_user(user=user)
        self._create_closed_accounting_without_metric(
            unique_id="matching-session",
            username=user.username,
            called_station_id=device.mac_address.replace("-", ":").upper(),
        )
        self._create_closed_accounting_without_metric(
            unique_id="ignored-session",
            username=user.username,
            called_station_id=device.mac_address.replace("-", ":").upper(),
            terminate_cause="Session-Timeout",
        )
        out = StringIO()
        call_command(
            "rebuild_radius_accounting_metrics",
            commit=True,
            stdout=out,
        )
        self.assertIn("Processed 1 closed sessions.", out.getvalue())
        metric = self.metric_model.objects.get(configuration="radius_acc")
        points = metric.chart_set.get(configuration="radius_traffic").read()
        self.assertEqual(points["summary"], {"upload": 9, "download": 8})
