import logging

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import APIException
from swapper import load_model

from .. import settings as app_settings

logger = logging.getLogger(__name__)

Organization = load_model('openwisp_users', 'Organization')


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
            id_ver = org.radius_settings.needs_identity_verification
            if id_ver is None:
                return app_settings.NEEDS_IDENTITY_VERIFICATION
            return id_ver
        except ObjectDoesNotExist:
            return app_settings.NEEDS_IDENTITY_VERIFICATION

    def is_identity_verified_strong(self, user):
        try:
            return user.registered_user.is_identity_verified_strong
        except ObjectDoesNotExist:
            return False


def is_sms_verification_enabled(org):
    try:
        return org.radius_settings.get_sms_verification()
    except ObjectDoesNotExist:
        logger.exception(
            f'Got exception while accessing radius_settings for {org.name}'
        )
        raise APIException(
            _('Could not complete operation because of an internal misconfiguration')
        )


def is_registration_enabled(org):
    try:
        return org.radius_settings.get_registration_enabled()
    except ObjectDoesNotExist:
        logger.exception(
            f'Got exception while accessing radius_settings for {org.name}'
        )
        raise APIException(
            _('Could not complete operation because of an internal misconfiguration')
        )
