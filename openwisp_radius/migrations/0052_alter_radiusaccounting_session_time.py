# Widen acctsessiontime to store the full unsigned RADIUS session time range.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius", "0051_remove_privileged_users_from_batches"),
    ]

    operations = [
        migrations.AlterField(
            model_name="radiusaccounting",
            name="session_time",
            field=models.PositiveBigIntegerField(
                blank=True,
                db_column="acctsessiontime",
                null=True,
                verbose_name="session time",
            ),
        ),
    ]
