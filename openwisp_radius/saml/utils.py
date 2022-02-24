import logging
from urllib.parse import urlparse

from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger()


def get_url_or_path(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}'
    return parsed_url.path


def is_saml_authentication_enabled(org):
    try:
        return org.radius_settings.get_saml_registration_enabled()
    except ObjectDoesNotExist:
        logger.exception(
            f'Got exception while accessing radius_settings for {org.name}'
        )
        raise Exception(
            _('Could not complete operation because of an internal misconfiguration')
        )
