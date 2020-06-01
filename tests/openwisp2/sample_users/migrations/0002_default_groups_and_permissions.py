# Manually Created
from django.db import migrations
from openwisp_users.migrations import (
    set_default_organization_uuid,
    create_default_groups,
)
import swapper


class Migration(migrations.Migration):

    org_model = swapper.get_model_name('openwisp_users', 'organization')
    model_app_label = swapper.split(org_model)[0]
    dependencies = [
        (model_app_label, '0001_initial'),
    ]

    operations = [
        migrations.RunPython(
            set_default_organization_uuid, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            create_default_groups, reverse_code=migrations.RunPython.noop
        ),
    ]
