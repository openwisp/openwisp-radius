import swapper
from django.conf import settings
from django.db import migrations

from . import (
    migrate_registered_users_multitenant_forward,
    migrate_registered_users_multitenant_reverse,
    populate_phonetoken_organization,
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
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        swapper.dependency("openwisp_users", "Organization"),
        ("openwisp_radius", "0045_registereduser_add_uuid"),
    ]

    operations = [
        migrations.RunPython(
            populate_phonetoken_organization,
            migrations.RunPython.noop,
        ),
        migrations.RunPython(
            migrate_registered_users_forward,
            migrate_registered_users_reverse,
        ),
    ]
