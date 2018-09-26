from django.db import migrations

from django_freeradius.migrations import add_default_groups, add_default_group_to_existing_users


class Migration(migrations.Migration):
    dependencies = [
        ('openwisp_radius', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(add_default_groups,
                             reverse_code=migrations.RunPython.noop),
        migrations.RunPython(add_default_group_to_existing_users,
                             reverse_code=migrations.RunPython.noop),
    ]
