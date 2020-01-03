from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_save
from django.utils.translation import ugettext_lazy as _
from django_freeradius.apps import DjangoFreeradiusConfig
from django_freeradius.utils import update_user_related_records

from .receivers import (create_default_groups_handler, organization_post_save, organization_pre_save,
                        set_default_group_handler)


class OpenwispRadiusConfig(DjangoFreeradiusConfig):
    name = 'openwisp_radius'

    def ready(self, *args, **kwargs):
        super().ready(*args, **kwargs)
        self.add_default_menu_items()

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

    def add_default_menu_items(self):
        menu_setting = 'OPENWISP_DEFAULT_ADMIN_MENU_ITEMS'
        items = [
            {'model': 'openwisp_radius.RadiusAccounting',
             'label': _('Radius sessions')},
        ]
        if not hasattr(settings, menu_setting):
            setattr(settings, menu_setting, items)
        else:
            current_menu = getattr(settings, menu_setting)
            current_menu += items
