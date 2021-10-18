from django.db import migrations

from . import assign_permissions_to_groups
import swapper


class Migration(migrations.Migration):
    if swapper.is_swapped('openwisp_users', 'group'):
        model = swapper.get_model_name('openwisp_users', 'group')
        model_app_label = swapper.split(model)[0]
        group_dependency = (model_app_label, '0001_initial')
    else:
        group_dependency = ('openwisp_users', '0004_default_groups')

    dependencies = [
        group_dependency,
        ('openwisp_users', '0004_default_groups'),
        ('openwisp_radius', '0003_default_radius_groups'),
    ]
    operations = [
        migrations.RunPython(
            assign_permissions_to_groups, reverse_code=migrations.RunPython.noop
        )
    ]
