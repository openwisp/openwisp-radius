# Manually Created

from django.db import migrations

from . import add_default_group_to_existing_users, add_default_groups


class Migration(migrations.Migration):
    """
    Set default group and move existing
    users to the default group
    """

    dependencies = [('openwisp_radius', '0002_initial_openwisp_radius')]

    operations = [
        migrations.RunPython(
            add_default_groups, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            add_default_group_to_existing_users, reverse_code=migrations.RunPython.noop
        ),
    ]
