from django.db import migrations
from django.contrib.auth.models import Permission

from . import create_default_permissions


def assign_permissions_to_groups(apps, schema_editor):
    create_default_permissions(apps, schema_editor)
    Group = apps.get_model('openwisp_users', 'Group')

    try:
        admin = Group.objects.get(name='Administrator')
        operator = Group.objects.get(name='Operator')
    # consider failures custom cases
    # that do not have to be dealt with
    except Group.DoesNotExist:
        return

    operators_and_admins_can_manage = ['radiuspostauth', 'radiusaccounting']
    operators_read_only_admins_manage = [
        'radiuscheck',
        'radiusreply',
        'radiusgroup',
        'radiusgroupcheck',
        'radiusgroupreply',
        'radiususergroup',
        'nas',
        'radiusbatch',
        'organizationradiussettings',
    ]
    manage_operations = ['add', 'change', 'delete']

    for action in manage_operations:
        for model_name in operators_and_admins_can_manage:
            permission = Permission.objects.get(
                codename='{}_{}'.format(action, model_name)
            )
            admin.permissions.add(permission.pk)
            operator.permissions.add(permission.pk)
    for model_name in operators_read_only_admins_manage:
        try:
            permission = Permission.objects.get(codename='view_{}'.format(model_name))
            operator.permissions.add(permission.pk)
        except Permission.DoesNotExist:
            pass
        for action in manage_operations:
            permission_ad = Permission.objects.get(
                codename='{}_{}'.format(action, model_name)
            )
            admin.permissions.add(permission_ad.pk)


class Migration(migrations.Migration):
    dependencies = [
        ('openwisp_users', '0004_default_groups'),
        ('openwisp_radius', '0003_default_radius_groups'),
    ]
    operations = [
        migrations.RunPython(
            assign_permissions_to_groups, reverse_code=migrations.RunPython.noop
        )
    ]
