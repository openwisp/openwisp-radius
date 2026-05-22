# Generated manually

import swapper
from django.conf import settings
from django.db import migrations

from openwisp_radius.migrations import get_swapped_model


def copy_batch_expiration_to_user(apps, schema_editor):
    RadiusBatch = get_swapped_model(apps, "openwisp_radius", "RadiusBatch")
    batches = RadiusBatch.objects.exclude(expiration_date__isnull=True).order_by(
        "-created", "-pk"
    )
    for batch in batches.iterator():
        batch.users.filter(expiration_date__isnull=True).update(
            expiration_date=batch.expiration_date
        )


class Migration(migrations.Migration):
    dependencies = [
        (
            "openwisp_radius",
            "0047_registered_user_multitenant_constraints",
        ),
        swapper.dependency(
            *swapper.split(settings.AUTH_USER_MODEL),
            version="0022_user_expiration_date",
        ),
    ]

    operations = [
        migrations.RunPython(
            copy_batch_expiration_to_user,
            reverse_code=migrations.RunPython.noop,
        )
    ]
