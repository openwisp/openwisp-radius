from django.db import migrations

from . import UUIDMigrator


class Migration(migrations.Migration):

    dependencies = [
        ('openwisp_radius', '0010_alter_radiusmodels_pk'),
    ]

    operations = [
        migrations.RunPython(
            UUIDMigrator.upgrade_primary_keys, reverse_code=migrations.RunPython.noop
        ),
    ]
