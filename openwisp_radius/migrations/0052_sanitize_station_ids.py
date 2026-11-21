from django.db import migrations

import openwisp_radius.base.fields

from . import sanitize_station_ids


def _field(**kwargs):
    return openwisp_radius.base.fields.MacAddressField(
        blank=True, max_length=253, null=True, **kwargs
    )


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius", "0051_remove_privileged_users_from_batches"),
    ]

    operations = [
        migrations.AlterField(
            model_name="radiusaccounting",
            name="called_station_id",
            field=_field(
                db_column="calledstationid",
                db_index=True,
                verbose_name="called station ID",
            ),
        ),
        migrations.AlterField(
            model_name="radiusaccounting",
            name="calling_station_id",
            field=_field(
                db_column="callingstationid",
                db_index=True,
                verbose_name="calling station ID",
            ),
        ),
        migrations.AlterField(
            model_name="radiuspostauth",
            name="called_station_id",
            field=_field(db_column="calledstationid", verbose_name="called station ID"),
        ),
        migrations.AlterField(
            model_name="radiuspostauth",
            name="calling_station_id",
            field=_field(
                db_column="callingstationid", verbose_name="calling station ID"
            ),
        ),
        # shortcut: converts all rows in a single transaction,
        # split into batches if this becomes a problem on huge tables
        migrations.RunPython(
            sanitize_station_ids, reverse_code=migrations.RunPython.noop
        ),
    ]
