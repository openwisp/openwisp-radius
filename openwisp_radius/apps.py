import swapper
from django.apps import AppConfig
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models.signals import post_delete, post_save, pre_save
from django.utils.translation import gettext_lazy as _

from .receivers import (
    create_default_groups_handler,
    organization_post_save,
    organization_pre_save,
    set_default_group_handler,
)
from .utils import load_model, update_user_related_records


class OpenwispRadiusConfig(AppConfig):
    name = 'openwisp_radius'
    label = 'openwisp_radius'
    verbose_name = 'Freeradius'

    def ready(self, *args, **kwargs):
        self.connect_signals()
        self.add_default_menu_items()

    def connect_signals(self):
        Organization = swapper.load_model('openwisp_users', 'Organization')
        OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
        OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
        RadiusToken = load_model('RadiusToken')
        User = get_user_model()

        post_save.connect(
            create_default_groups_handler,
            sender=Organization,
            dispatch_uid='create_default_groups',
        )
        post_save.connect(
            update_user_related_records,
            sender=User,
            dispatch_uid='update_user_related_records',
        )
        post_save.connect(
            set_default_group_handler,
            sender=OrganizationUser,
            dispatch_uid='set_default_group',
        )
        pre_save.connect(
            organization_pre_save,
            sender=Organization,
            dispatch_uid='openwisp_radius_org_pre_save',
        )
        post_save.connect(
            organization_post_save,
            sender=Organization,
            dispatch_uid='openwisp_radius_org_post_save',
        )
        post_delete.connect(
            self.radiustoken_post_delete,
            sender=RadiusToken,
            dispatch_uid='openwisp_radius_radiustoken_post_delete',
        )
        post_save.connect(
            self.radiusorgsettings_post_save,
            sender=OrganizationRadiusSettings,
            dispatch_uid='openwisp_radius_organizationradiussettings_post_save',
        )
        post_delete.connect(
            self.radiusorgsettings_post_delete,
            sender=OrganizationRadiusSettings,
            dispatch_uid='openwisp_radius_organizationradiussettings_post_delete',
        )

    def radiustoken_post_delete(self, instance, **kwargs):
        instance.delete_cache()

    def radiusorgsettings_post_save(self, instance, **kwargs):
        instance.save_cache()

    def radiusorgsettings_post_delete(self, instance, **kwargs):
        instance.delete_cache()

    def add_default_menu_items(self):
        menu_setting = 'OPENWISP_DEFAULT_ADMIN_MENU_ITEMS'
        items = [
            {'model': f'{self.label}.RadiusAccounting', 'label': _('Radius sessions')}
        ]
        if not hasattr(settings, menu_setting):
            setattr(settings, menu_setting, items)
        else:
            current_menu = getattr(settings, menu_setting)
            current_menu += items
