import os
import _pickle as pickle
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


class UUIDMigrator:
    _backup_file_name = 'backup.pk1'

    @classmethod
    def backup_data(cls, apps, schema_editor):
        models = [
            'RadiusCheck',
            'RadiusReply',
            'RadiusGroupCheck',
            'RadiusGroupReply',
            'RadiusUserGroup',
            'Nas',
            'RadiusAccounting',
            'RadiusPostAuth',
        ]
        current_objects = []
        for model in models:
            model = get_swapped_model(apps, 'openwisp_radius', model)
            if model.objects.first() and not isinstance(
                model.objects.first().pk, uuid.UUID
            ):
                current_objects += list(model.objects.all())
                model.objects.all().delete()
        with open(cls._backup_file_name, 'wb') as f:
            pickle.dump(current_objects, f, -1)
            f.close()

    @classmethod
    def upgrade_primary_keys(cls, apps, schema_editor):
        with open(cls._backup_file_name, 'rb') as f:
            for obj in pickle.load(f):
                if obj is None:
                    continue
                if hasattr(obj, 'unique_id'):
                    obj.pk = obj.unique_id
                else:
                    obj.pk = uuid.uuid4()
                obj.save()
            f.close()
        os.remove(cls._backup_file_name)
