# Manually Created

from django.db import migrations

from openwisp_radius.migrations import (
    add_default_groups,
    add_default_group_to_existing_users,
    assign_permissions_to_groups,
    add_default_organization,
)
import swapper


class Migration(migrations.Migration):
    """
    Set default group and move existing
    users to the default group
    """

    org_model = swapper.get_model_name('openwisp_radius', 'Nas')
    model_app_label = swapper.split(org_model)[0]
    dependencies = [
        (model_app_label, '0001_initial'),
    ]

    operations = [
        migrations.RunPython(
            add_default_organization, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            add_default_groups, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            add_default_group_to_existing_users, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            assign_permissions_to_groups, reverse_code=migrations.RunPython.noop
        ),
    ]
