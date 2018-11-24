from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_save
from django_freeradius.apps import DjangoFreeradiusConfig
from django_freeradius.utils import update_user_related_records

from .receivers import (create_default_groups_handler, organization_post_save, organization_pre_save,
                        set_default_group_handler)


class OpenwispRadiusConfig(DjangoFreeradiusConfig):
    name = 'openwisp_radius'

    def check_settings(self):
        pass

    def connect_signals(self):
        from openwisp_users.models import Organization, OrganizationUser
        User = get_user_model()
        post_save.connect(create_default_groups_handler,
                          sender=Organization,
                          dispatch_uid='create_default_groups')
        post_save.connect(update_user_related_records,
                          sender=User,
                          dispatch_uid='update_user_related_records')
        post_save.connect(set_default_group_handler,
                          sender=OrganizationUser,
                          dispatch_uid='set_default_group')
        pre_save.connect(organization_pre_save,
                         sender=Organization,
                         dispatch_uid='openwisp_radius_org_pre_save')
        post_save.connect(organization_post_save,
                          sender=Organization,
                          dispatch_uid='openwisp_radius_org_post_save')
