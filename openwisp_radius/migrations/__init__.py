import uuid

import swapper
from django.conf import settings
from django.contrib.auth.management import create_permissions
from django.contrib.auth.models import Permission

from ..utils import create_default_groups


def get_swapped_model(apps, app_name, model_name):
    model_path = swapper.get_model_name(app_name, model_name)
    app, model = swapper.split(model_path)
    return apps.get_model(app, model)


def delete_old_radius_token(apps, schema_editor):
    RadiusToken = get_swapped_model(apps, 'openwisp_radius', 'RadiusToken')
    RadiusToken.objects.all().delete()


def add_default_organization(apps, schema_editor):
    """
    Set default organization using
    settings._OPENWISP_DEFAULT_ORG_UUID
    """
    models = ['nas', 'radiusaccounting', 'radiuscheck', 'radiuspostauth', 'radiusreply']
    if hasattr(settings, '_OPENWISP_DEFAULT_ORG_UUID'):
        default_org_id = settings._OPENWISP_DEFAULT_ORG_UUID
    else:  # pragma: no-cover (corner case)
        Organization = get_swapped_model(apps, 'openwisp_users', 'Organization')
        default_org_id = Organization.objects.first().pk
    for model in models:
        Model = get_swapped_model(apps, 'openwisp_radius', model)
        for record in Model.objects.all().iterator():
            record.organization_id = default_org_id
            record.save()

    OrganizationRadiusSettings = get_swapped_model(
        apps, 'openwisp_radius', 'organizationradiussettings'
    )
    OrganizationRadiusSettings.objects.create(organization_id=default_org_id)


def add_default_groups(apps, schema_editor):
    Organization = get_swapped_model(apps, 'openwisp_users', 'Organization')
    RadiusGroup = get_swapped_model(apps, 'openwisp_radius', 'RadiusGroup')
    for organization in Organization.objects.all():
        if not RadiusGroup.objects.filter(organization_id=organization.pk).exists():
            create_default_groups(organization, apps=apps)


def add_default_group_to_existing_users(apps, schema_editor):
    Organization = get_swapped_model(apps, 'openwisp_users', 'Organization')
    OrganizationUser = get_swapped_model(apps, 'openwisp_users', 'OrganizationUser')
    RadiusUserGroup = get_swapped_model(apps, 'openwisp_radius', 'RadiusUserGroup')
    RadiusGroup = get_swapped_model(apps, 'openwisp_radius', 'RadiusGroup')
    for organization in Organization.objects.all():
        default_group = RadiusGroup.objects.filter(
            organization_id=organization.pk, default=True
        )
        if default_group.exists():
            default_group = default_group.first()
            for orguser in OrganizationUser.objects.filter(
                organization_id=organization.pk
            ):
                user = orguser.user
                if not RadiusUserGroup.objects.filter(user=user).exists():
                    user_group = RadiusUserGroup(
                        user_id=user.id,
                        username=user.username,
                        group_id=default_group.id,
                    )
                    user_group.save()


def create_default_permissions(apps, schema_editor):
    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, apps=apps, verbosity=0)
        app_config.models_module = None


def assign_permissions_to_groups(apps, schema_editor):
    create_default_permissions(apps, schema_editor)
    Group = get_swapped_model(apps, 'openwisp_users', 'Group')

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
            permission = Permission.objects.get(codename=f'{action}_{model_name}')
            admin.permissions.add(permission.pk)
            operator.permissions.add(permission.pk)
    for model_name in operators_read_only_admins_manage:
        try:
            permission = Permission.objects.get(codename=f'view_{model_name}')
            operator.permissions.add(permission.pk)
        except Permission.DoesNotExist:
            pass
        for action in manage_operations:
            permission_ad = Permission.objects.get(codename=f'{action}_{model_name}')
            admin.permissions.add(permission_ad.pk)


def popluate_uuids(apps, schema_editor):
    models = [
        'RadiusCheck',
        'RadiusReply',
        'RadiusGroupCheck',
        'RadiusGroupReply',
        'RadiusUserGroup',
        'RadiusPostAuth',
        'Nas',
    ]
    for model in models:
        model = get_swapped_model(apps, 'openwisp_radius', model)
        for obj in model.objects.all():
            obj.uuid = uuid.uuid4()
            obj.save(update_fields=['uuid'])


def populate_phonetoken_phone_number(apps, schema_editor):
    PhoneToken = get_swapped_model(apps, 'openwisp_radius', 'PhoneToken')
    for phone_token in PhoneToken.objects.all():
        phone_token.phone_number = phone_token.user.phone_number
        phone_token.save(update_fields=['phone_number'])
