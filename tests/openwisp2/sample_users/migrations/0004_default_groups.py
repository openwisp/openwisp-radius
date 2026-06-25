# Manually Created

import swapper
from django.db import migrations

from openwisp_users.migrations import (
    add_api_key_permissions_to_admins,
    allow_admins_change_organization,
    create_default_groups,
    set_default_organization_uuid,
    update_admins_permissions,
)


class Migration(migrations.Migration):
    org_model = swapper.get_model_name("openwisp_users", "organization")
    dependencies = [
        swapper.dependency(*swapper.split(org_model), version="0002_apikey")
    ]

    operations = [
        migrations.RunPython(
            set_default_organization_uuid, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            create_default_groups, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            update_admins_permissions, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            allow_admins_change_organization, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            add_api_key_permissions_to_admins, reverse_code=migrations.RunPython.noop
        ),
    ]
