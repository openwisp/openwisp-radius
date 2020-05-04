# Manually Created

from django.db import migrations

from openwisp_radius.migrations import (
    add_default_groups,
    add_default_group_to_existing_users,
    assign_permissions_to_groups,
    add_default_organization,
)


class Migration(migrations.Migration):
    """
    Set default group and move existing
    users to the default group
    """

    dependencies = [('sample_radius', '0001_initial')]

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
