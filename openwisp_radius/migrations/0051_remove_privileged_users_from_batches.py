import swapper
from django.conf import settings
from django.db import migrations
from django.db.models import F, Q

from openwisp_radius.migrations import get_swapped_model


def remove_privileged_users_from_batches(apps, schema_editor):
    """
    Batches could include existing users before importing them was
    rejected: staff users and superusers are removed from the batches,
    so that deleting a batch cannot delete their accounts. The changes
    made by the import are reverted too: the expiration date set by the
    batch is cleared and the membership created by the batch in its
    organization is removed, so that its administrators cannot manage
    the account.
    """
    RadiusBatch = get_swapped_model(apps, "openwisp_radius", "RadiusBatch")
    User = RadiusBatch._meta.get_field("users").related_model
    # the real model is used so that the delete signals are sent:
    # other modules may run cleanup operations when a user leaves an org
    OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")
    User.objects.filter(
        Q(is_staff=True) | Q(is_superuser=True),
        radius_batch__expiration_date=F("expiration_date"),
    ).update(expiration_date=None)
    batch_users = RadiusBatch.users.through.objects.filter(
        Q(user__is_staff=True) | Q(user__is_superuser=True)
    ).select_related("radiusbatch")
    for batch_user in batch_users.iterator():
        batch = batch_user.radiusbatch
        org_users = OrganizationUser.objects.filter(
            user_id=batch_user.user_id,
            organization_id=batch.organization_id,
            is_admin=False,
            created__gte=batch.created,
        )
        for org_user in org_users.iterator():
            org_user.delete()
    batch_users.delete()


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius", "0050_radiusbatch_group_radiusbatch_notes"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        swapper.dependency("openwisp_users", "OrganizationUser"),
    ]

    operations = [
        migrations.RunPython(
            remove_privileged_users_from_batches,
            reverse_code=migrations.RunPython.noop,
        )
    ]
