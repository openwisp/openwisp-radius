from django.db import migrations

from . import (
    migrate_registered_users_multitenant_forward,
    migrate_registered_users_multitenant_reverse,
)


def migrate_registered_users_forward(apps, schema_editor):
    migrate_registered_users_multitenant_forward(
        apps, schema_editor, app_label="openwisp_radius"
    )


def migrate_registered_users_reverse(apps, schema_editor):
    migrate_registered_users_multitenant_reverse(
        apps, schema_editor, app_label="openwisp_radius"
    )


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius", "0043_registereduser_add_uuid"),
    ]

    operations = [
        migrations.RunPython(
            migrate_registered_users_forward,
            migrate_registered_users_reverse,
        ),
    ]
