from io import StringIO
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import tag
from django.utils import timezone
from swapper import load_model

from openwisp_radius.integrations.monitoring import tasks
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
        "rebuild_radius_accounting_metrics.timeseries_db.delete_metric_data"
    )
    @patch("logging.Logger.warning")
    def test_rebuild_radius_accounting_metrics_commit(
        self, mocked_warning, mocked_delete
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
        output = out.getvalue()
        self.assertIn("Starting to rebuild 1 accounting metrics.", output)
        self.assertIn("Processed 1 of 1 accounting metrics.", output)
        self.assertEqual(mocked_delete.call_count, 1)
        self.assertEqual(
            mocked_delete.call_args.kwargs,
            {
                "key": "radius_acc",
                "tags": {
                    "organization_id": str(self.default_org.id),
                    "calling_station_id": sha1_hash(session.calling_station_id),
                    "called_station_id": session.called_station_id,
                },
                "timestamp": session.stop_time,
            },
        )
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
    def test_rebuild_radius_accounting_metrics_deletes_only_session_point(self, *args):
        user = self._create_user()
        device = self._create_device()
        self._create_registered_user(user=user)
        called_station_id = device.mac_address.replace("-", ":").upper()
        # this session was accounted correctly and must not be deleted
        accounted_session = self._create_closed_accounting_without_metric(
            unique_id="accounted-session",
            username=user.username,
            called_station_id=called_station_id,
            terminate_cause="Session-Timeout",
            stop_time=timezone.now() - timezone.timedelta(hours=1),
            input_octets=1000000000,
            output_octets=2000000000,
        )
        tasks.post_save_radiusaccounting(
            username=accounted_session.username,
            organization_id=str(accounted_session.organization_id),
            input_octets=accounted_session.input_octets,
            output_octets=accounted_session.output_octets,
            calling_station_id=accounted_session.calling_station_id,
            called_station_id=accounted_session.called_station_id,
            time=accounted_session.stop_time,
        )
        self._create_closed_accounting_without_metric(
            username=user.username,
            called_station_id=called_station_id,
        )
        call_command(
            "rebuild_radius_accounting_metrics", commit=True, stdout=StringIO()
        )
        metric = self.metric_model.objects.get(configuration="radius_acc")
        points = metric.chart_set.get(configuration="radius_traffic").read()
        # the point of the accounted session is still there:
        # 8 + 1 GB of download and 9 + 2 GB of upload
        self.assertEqual(points["summary"], {"upload": 11, "download": 9})

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
        output = out.getvalue()
        self.assertIn("Starting to rebuild 1 accounting metrics.", output)
        self.assertIn("Processed 1 of 1 accounting metrics.", output)
        metric = self.metric_model.objects.get(configuration="radius_acc")
        points = metric.chart_set.get(configuration="radius_traffic").read()
        self.assertEqual(points["summary"], {"upload": 9, "download": 8})
