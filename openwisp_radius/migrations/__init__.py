from django.conf import settings
from django.contrib.auth.management import create_permissions

from django_freeradius.migrations import get_swapped_model

from ..utils import create_default_groups


def add_default_organization(apps, schema_editor):
    """
    Set default organization using
    settings._OPENWISP_DEFAULT_ORG_UUID
    """
    models = ['nas', 'radiusaccounting', 'radiuscheck', 'radiuspostauth', 'radiusreply']

    for model in models:
        Model = apps.get_model('openwisp_radius', model)
        for record in Model.objects.all().iterator():
            record.organization_id = settings._OPENWISP_DEFAULT_ORG_UUID
            record.save()


def add_default_groups(apps, schema_editor):
    Organization = apps.get_model('openwisp_users', 'Organization')
    RadiusGroup = get_swapped_model(apps, 'django_freeradius', 'RadiusGroup')
    for organization in Organization.objects.all():
        if not RadiusGroup.objects.filter(organization_id=organization.pk).exists():
            create_default_groups(organization)


def add_default_group_to_existing_users(apps, schema_editor):
    Organization = apps.get_model('openwisp_users', 'Organization')
    OrganizationUser = apps.get_model('openwisp_users', 'OrganizationUser')
    RadiusUserGroup = get_swapped_model(apps, 'django_freeradius', 'RadiusUserGroup')
    RadiusGroup = get_swapped_model(apps, 'django_freeradius', 'RadiusGroup')
    for organization in Organization.objects.all():
        default_group = RadiusGroup.objects.filter(organization_id=organization.pk,
                                                   default=True)
        if default_group.exists():
            default_group = default_group.first()
            for orguser in OrganizationUser.objects.filter(organization_id=organization.pk):
                user = orguser.user
                if not RadiusUserGroup.objects.filter(user=user).exists():
                    user_group = RadiusUserGroup(user_id=user.id,
                                                 username=user.username,
                                                 group_id=default_group.id)
                    user_group.save()

def create_default_permissions(apps, schema_editor):
    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, apps=apps, verbosity=0)
        app_config.models_module = None

