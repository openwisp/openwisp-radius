import logging

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)


class ErrorDictMixin(object):
    def _get_error_dict(self, error):
        dict_ = error.message_dict.copy()
        if '__all__' in dict_:
            dict_['non_field_errors'] = dict_.pop('__all__')
        return dict_


def is_sms_verification_enabled(org):
    try:
        return org.radius_settings.sms_verification
    except ObjectDoesNotExist:
        logger.exception(
            f'Got exception while accessing radius_settings for {org.name}'
        )
        raise APIException(
            _('Could not complete operation ' 'because of an internal misconfiguration')
        )
