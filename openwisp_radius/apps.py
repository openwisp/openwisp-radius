import swapper
from allauth.account.apps import AccountConfig
from allauth.socialaccount.apps import SocialAccountConfig
from django.contrib.auth import get_user_model
from django.db.models.signals import post_delete, post_save, pre_save
from django.utils.translation import gettext_lazy as _
from swapper import get_model_name

from openwisp_utils.admin_theme.menu import register_menu_group
from openwisp_utils.api.apps import ApiAppConfig
from openwisp_utils.utils import default_or_test

from . import settings as app_settings
from .receivers import (
    convert_radius_called_station_id,
    create_default_groups_handler,
    organization_post_save,
    organization_pre_save,
    send_email_on_new_accounting_handler,
    set_default_group_handler,
)
from .registration import register_registration_method
from .signals import radius_accounting_success
from .utils import load_model, update_user_related_records


class OpenwispRadiusConfig(ApiAppConfig):
    name = 'openwisp_radius'
    label = 'openwisp_radius'
    verbose_name = 'Freeradius'

    API_ENABLED = True
    REST_FRAMEWORK_SETTINGS = {
        'DEFAULT_THROTTLE_RATES': {
            # None by default
            'authorize': None,
            'postauth': None,
            'accounting': None,
            'obtain_auth_token': None,
            'validate_auth_token': None,
            'create_phone_token': None,
            'validate_phone_token': None,
            # Relaxed throttling Policy
            'others': default_or_test('400/hour', None),
        },
    }
    AccountConfig.default_auto_field = 'django.db.models.AutoField'
    SocialAccountConfig.default_auto_field = 'django.db.models.AutoField'

    def ready(self, *args, **kwargs):
        super().ready(*args, **kwargs)
        self.connect_signals()
        self.regiser_menu_groups()

        if app_settings.SOCIAL_LOGIN_ENABLED:
            register_registration_method('social_login', _('Social login'))
        if app_settings.SAML_LOGIN_ENABLED:
            register_registration_method(
                'saml',
                app_settings.SAML_REGISTRATION_METHOD_LABEL,
                strong_identity=True,
            )

    def connect_signals(self):
        Organization = swapper.load_model('openwisp_users', 'Organization')
        OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
        OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
        RadiusToken = load_model('RadiusToken')
        RadiusAccounting = load_model('RadiusAccounting')
        User = get_user_model()
        from openwisp_radius.api.freeradius_views import AccountingView

        radius_accounting_success.connect(
            send_email_on_new_accounting_handler,
            sender=AccountingView,
            dispatch_uid='send_email_on_new_accounting',
        )

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
        if app_settings.CONVERT_CALLED_STATION_ON_CREATE:
            post_save.connect(
                convert_radius_called_station_id,
                sender=RadiusAccounting,
                dispatch_uid='openwisp_radius_convert_called_station_id',
            )

    def radiustoken_post_delete(self, instance, **kwargs):
        instance.delete_cache()

    def radiusorgsettings_post_save(self, instance, **kwargs):
        instance.save_cache()

    def radiusorgsettings_post_delete(self, instance, **kwargs):
        instance.delete_cache()

    def regiser_menu_groups(self):
        items = {
            1: {
                'label': _('Accounting Sessions'),
                'model': get_model_name(self.label, 'RadiusAccounting'),
                'name': 'changelist',
                'icon': 'ow-radius-accounting',
            },
            2: {
                'label': _('Groups'),
                'model': get_model_name(self.label, 'RadiusGroup'),
                'name': 'changelist',
                'icon': 'ow-radius-group',
            },
            3: {
                'label': _('NAS'),
                'model': get_model_name(self.label, 'Nas'),
                'name': 'changelist',
                'icon': 'ow-radius-nas',
            },
            4: {
                'label': _('Checks'),
                'model': get_model_name(self.label, 'RadiusCheck'),
                'name': 'changelist',
                'icon': 'ow-radius-checks',
            },
            5: {
                'label': _('Replies'),
                'model': get_model_name(self.label, 'RadiusReply'),
                'name': 'changelist',
                'icon': 'ow-radius-replies',
            },
            6: {
                'label': _('Batch user Creation'),
                'model': get_model_name(self.label, 'RadiusBatch'),
                'name': 'changelist',
                'icon': 'ow-batch-creation',
            },
            7: {
                'label': _('Post Auth Log'),
                'model': get_model_name(self.label, 'RadiusPostAuth'),
                'name': 'changelist',
                'icon': 'ow-radius-post-log',
            },
        }
        if getattr(app_settings, 'DEBUG', False):
            items[8] = {
                'label': _('Radius Token'),
                'model': get_model_name(self.label, 'RadiusToken'),
                'name': 'changelist',
                'icon': 'ow-radius-token',
            }
        register_menu_group(
            position=70,
            config={'label': _('RADIUS'), 'items': items, 'icon': 'ow-radius'},
        )
