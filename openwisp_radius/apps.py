import swapper
from django.contrib.auth import get_user_model
from django.db.models import signals
from django_freeradius.apps import DjangoFreeradiusConfig
from django_freeradius.utils import update_user_related_records

from .utils import create_default_groups


def set_default_group_handler(sender, instance, created, **kwargs):
    if created:
        RadiusGroup = swapper.load_model('django_freeradius', 'RadiusGroup')
        RadiusUserGroup = swapper.load_model('django_freeradius', 'RadiusUserGroup')
        queryset = RadiusGroup.objects.filter(
            default=True,
            organization_id=instance.organization.pk
        )
        if queryset.exists():
            ug = RadiusUserGroup(user=instance.user,
                                 group=queryset.first())
            ug.full_clean()
            ug.save()


def create_default_groups_handler(sender, instance, created, **kwargs):
    if created:
        create_default_groups(organization=instance)


class OpenwispRadiusConfig(DjangoFreeradiusConfig):
    name = 'openwisp_radius'

    def check_settings(self):
        pass

    def connect_signals(self):
        from openwisp_users.models import Organization, OrganizationUser
        User = get_user_model()
        signals.post_save.connect(create_default_groups_handler,
                                  sender=Organization)
        signals.post_save.connect(update_user_related_records, sender=User)
        signals.post_save.connect(set_default_group_handler, sender=OrganizationUser)
