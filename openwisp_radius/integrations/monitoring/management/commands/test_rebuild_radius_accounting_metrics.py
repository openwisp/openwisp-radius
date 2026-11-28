from io import StringIO
from unittest import skipUnless
from unittest.mock import patch

from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.management import CommandError, call_command
from django.test import tag
from django.utils import timezone
from swapper import load_model

from openwisp_radius.integrations.monitoring.tests.mixins import (
    CreateDeviceMonitoringMixin,
)
from openwisp_radius.integrations.monitoring.utils import sha1_hash
from openwisp_radius.tests import _RADACCT
from openwisp_radius.tests.mixins import BaseTransactionTestCase

# Discovery imports tests before filtering tags, but tasks require Monitoring models.
MONITORING_INSTALLED = apps.is_installed("openwisp_radius.integrations.monitoring")
if MONITORING_INSTALLED:
    from openwisp_radius.integrations.monitoring.metrics.accounting import (
        RECONCILIATION_STATE_KEY,
    )
    from openwisp_radius.integrations.monitoring.tasks import reconcile_radius_traffic

RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")


@tag("radius_monitoring", "rebuild_radius_accounting_metrics")
@skipUnless(MONITORING_INSTALLED, "RADIUS Monitoring integration is not installed")
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
        call_command(
            "rebuild_radius_accounting_metrics",
            commit=True,
            end=timezone.now().isoformat(),
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("Starting to rebuild 1 accounting metrics.", output)
        self.assertIn("Processed 1 of 1 accounting metrics.", output)
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
            end=timezone.now().isoformat(),
            stdout=out,
        )
        output = out.getvalue()
        self.assertIn("Starting to rebuild 1 accounting metrics.", output)
        self.assertIn("Processed 1 of 1 accounting metrics.", output)
        metric = self.metric_model.objects.get(configuration="radius_acc")
        points = metric.chart_set.get(configuration="radius_traffic").read()
        self.assertEqual(points["summary"], {"upload": 9, "download": 8})

    def test_commit_requires_legacy_end_time(self):
        with self.assertRaisesMessage(
            CommandError, "--end is required when writing legacy metrics."
        ):
            call_command("rebuild_radius_accounting_metrics", commit=True)

    def test_commit_cannot_rebuild_hourly_period(self):
        cache.delete(RECONCILIATION_STATE_KEY)
        reconcile_radius_traffic(seed=True)
        with self.assertRaisesMessage(
            CommandError, "--end must be before hourly baseline initialization."
        ):
            call_command(
                "rebuild_radius_accounting_metrics",
                commit=True,
                end=timezone.now().isoformat(),
                stdout=StringIO(),
            )

    @patch("openwisp_radius.integrations.monitoring.metrics.accounting.Metric.read")
    def test_commit_end_boundary_with_existing_checkpoint(self, read):
        read.return_value = [{"time": "2026-01-02T00:00:00+00:00"}]
        with self.subTest("end before checkpoint"):
            output = StringIO()
            call_command(
                "rebuild_radius_accounting_metrics",
                commit=True,
                end="2026-01-01T23:59:59+00:00",
                stdout=output,
            )
            self.assertIn(
                "Starting to rebuild 0 accounting metrics.", output.getvalue()
            )

        with self.subTest("end at checkpoint"):
            with self.assertRaisesMessage(
                CommandError, "--end must be before hourly baseline initialization."
            ):
                call_command(
                    "rebuild_radius_accounting_metrics",
                    commit=True,
                    end="2026-01-02T00:00:00+00:00",
                    stdout=StringIO(),
                )

        with self.subTest("end after checkpoint"):
            with self.assertRaisesMessage(
                CommandError, "--end must be before hourly baseline initialization."
            ):
                call_command(
                    "rebuild_radius_accounting_metrics",
                    commit=True,
                    end="2026-01-02T00:00:01+00:00",
                    stdout=StringIO(),
                )
