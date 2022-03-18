import logging

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger()


def is_social_authentication_enabled(org):
    try:
        return org.radius_settings.get_social_registration_enabled()
    except ObjectDoesNotExist:
        logger.exception(
            f'Got exception while accessing radius_settings for {org.name}'
        )
        raise Exception(
            _('Could not complete operation because of an internal misconfiguration')
        )
