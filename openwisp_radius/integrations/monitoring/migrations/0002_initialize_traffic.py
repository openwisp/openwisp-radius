"""Record open-session traffic once when upgrading RADIUS Monitoring."""

import swapper
from django.core.exceptions import FieldDoesNotExist
from django.db import migrations

from ..metrics.accounting import initialize_traffic

ACCOUNTING_MODEL = ("openwisp_radius", "RadiusAccounting")


def initialize_open_session_traffic(apps, schema_editor):
    accounting = apps.get_model(swapper.get_model_name(*ACCOUNTING_MODEL))
    queryset = accounting._base_manager.using(schema_editor.connection.alias)
    # A fresh swapped install may not have reached the migration that adds
    # the organization field. A legacy Monitoring install already has it.
    try:
        accounting._meta.get_field("organization")
    except FieldDoesNotExist:
        if not queryset.exists():
            return
        raise
    initialize_traffic(queryset)


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius_monitoring", "0001_initial"),
        swapper.dependency("geo", "DeviceLocation"),
        swapper.dependency(
            *ACCOUNTING_MODEL,
            version=(
                None
                if swapper.is_swapped(*ACCOUNTING_MODEL)
                else "0002_initial_openwisp_radius"
            ),
        ),
    ]
    # Newly created metrics must be committed before Monitoring workers use them.
    # SQL rollback cannot undo queued writes, so the cutover is irreversible.
    atomic = False
    operations = [migrations.RunPython(initialize_open_session_traffic)]
