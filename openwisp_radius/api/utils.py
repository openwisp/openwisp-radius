import logging

from django.core.exceptions import ObjectDoesNotExist
from swapper import load_model

from .. import settings as app_settings

logger = logging.getLogger(__name__)

Organization = load_model('openwisp_users', 'Organization')
OrganizationRadiusSettings = load_model('openwisp_radius', 'OrganizationRadiusSettings')


class ErrorDictMixin(object):
    def _get_error_dict(self, error):
        dict_ = error.message_dict.copy()
        if '__all__' in dict_:
            dict_['non_field_errors'] = dict_.pop('__all__')
        return dict_


class IDVerificationHelper(object):
    def _needs_identity_verification(self, organization_filter_kwargs={}, org=None):
        try:
            if not org:
                org = Organization.objects.select_related('radius_settings').get(
                    **organization_filter_kwargs
                )
            return org.radius_settings.get_setting('needs_identity_verification')
        except ObjectDoesNotExist:
            return app_settings.NEEDS_IDENTITY_VERIFICATION

    def is_identity_verified_strong(self, user):
        try:
            return user.registered_user.is_identity_verified_strong
        except ObjectDoesNotExist:
            return False
