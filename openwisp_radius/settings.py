import hashlib
import logging
import os
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

# 'pre_django_setup' is supposed to be a logger
# that can work before registered Apps are
# ready in django.setup() process.
logger = logging.getLogger('pre_django_setup')


def get_settings_value(option, default):
    if hasattr(settings, f'DJANGO_FREERADIUS_{option}'):  # pragma: no cover
        logger.warning(
            _(
                f'DJANGO_FREERADIUS_{option} setting is deprecated. It will be '
                f'removed in the future, please use OPENWISP_RADIUS_{option} instead.'
            )
        )
        return getattr(settings, f'DJANGO_FREERADIUS_{option}')
    return getattr(settings, f'OPENWISP_RADIUS_{option}', default)


RADIUS_API = get_settings_value('API', True)
EDITABLE_ACCOUNTING = get_settings_value('EDITABLE_ACCOUNTING', False)
EDITABLE_POSTAUTH = get_settings_value('EDITABLE_POSTAUTH', False)
GROUPCHECK_ADMIN = get_settings_value('GROUPCHECK_ADMIN', False)
GROUPREPLY_ADMIN = get_settings_value('GROUPREPLY_ADMIN', False)
USERGROUP_ADMIN = get_settings_value('USERGROUP_ADMIN', False)
DEFAULT_SECRET_FORMAT = get_settings_value('DEFAULT_SECRET_FORMAT', 'NT-Password')
DISABLED_SECRET_FORMATS = get_settings_value('DISABLED_SECRET_FORMATS', [])
BATCH_DEFAULT_PASSWORD_LENGTH = get_settings_value('BATCH_DEFAULT_PASSWORD_LENGTH', 8)
BATCH_DELETE_EXPIRED = get_settings_value('BATCH_DELETE_EXPIRED', 18)
BATCH_MAIL_SUBJECT = get_settings_value('BATCH_MAIL_SUBJECT', 'Credentials')
BATCH_MAIL_SENDER = get_settings_value('BATCH_MAIL_SENDER', settings.DEFAULT_FROM_EMAIL)
API_AUTHORIZE_REJECT = get_settings_value('API_AUTHORIZE_REJECT', False)
SOCIAL_LOGIN_ENABLED = 'allauth.socialaccount' in settings.INSTALLED_APPS
DISPOSABLE_RADIUS_USER_TOKEN = get_settings_value('DISPOSABLE_RADIUS_USER_TOKEN', True)
API_ACCOUNTING_AUTO_GROUP = get_settings_value('API_ACCOUNTING_AUTO_GROUP', True)
FREERADIUS_ALLOWED_HOSTS = get_settings_value('FREERADIUS_ALLOWED_HOSTS', [])
EXTRA_NAS_TYPES = get_settings_value('EXTRA_NAS_TYPES', tuple())
MAX_CSV_FILE_SIZE = get_settings_value('MAX_FILE_SIZE', 5 * 1024 * 1024)
BATCH_PDF_TEMPLATE = get_settings_value(
    'BATCH_PDF_TEMPLATE',
    os.path.join(
        os.path.dirname(__file__), 'templates/openwisp-radius/prefix_pdf.html'
    ),
)
BATCH_MAIL_MESSAGE = get_settings_value(
    'BATCH_MAIL_MESSAGE', 'username: {}, password: {}'
)
RADCHECK_SECRET_VALIDATORS = get_settings_value(
    'RADCHECK_SECRET_VALIDATORS',
    {
        'regexp_lowercase': '[a-z]+',
        'regexp_uppercase': '[A-Z]+',
        'regexp_number': '[0-9]+',
        'regexp_special': '[\!\%\-_+=\[\]\
                          {\}\:\,\.\?\<\>\(\)\;]+',
    },
)

PASSWORD_RESET_URLS = {
    # fallback in case the specific org page is not defined
    'default': 'https://{site}/{organization}/password/reset/confirm/{uid}/{token}',
    # use the uuid because the slug can change
}

PASSWORD_RESET_URLS.update(get_settings_value('PASSWORD_RESET_URLS', {}))
SMS_DEFAULT_VERIFICATION = get_settings_value('SMS_DEFAULT_VERIFICATION', False)
# SMS_TOKEN_DEFAULT_VALIDITY time is in minutes
SMS_TOKEN_DEFAULT_VALIDITY = get_settings_value('SMS_TOKEN_DEFAULT_VALIDITY', 30)
SMS_TOKEN_LENGTH = get_settings_value('SMS_TOKEN_LENGTH', 6)
SMS_TOKEN_HASH_ALGORITHM = get_settings_value('SMS_TOKEN_HASH_ALGORITHM', 'sha256')
SMS_TOKEN_MAX_ATTEMPTS = get_settings_value('SMS_TOKEN_MAX_ATTEMPTS', 3)
SMS_TOKEN_MAX_USER_DAILY = get_settings_value('SMS_TOKEN_MAX_USER_DAILY', 3)
SMS_TOKEN_MAX_IP_DAILY = get_settings_value('SMS_TOKEN_MAX_IP_DAILY', 25)

try:  # pragma: no cover
    assert PASSWORD_RESET_URLS
    for key, value in PASSWORD_RESET_URLS.items():
        if key != 'default':
            try:
                UUID(key)
            except ValueError:
                raise AssertionError(f'{key} is not a valid UUID')
        assert all(['{organization}' in value, '{uid}' in value, '{token}' in value]), (
            f'{value} must contain ' + '{organization}, {uid} and {token}'  # noqa
        )
except AssertionError as error:  # pragma: no cover
    raise ImproperlyConfigured(
        f'OPENWISP_RADIUS_PASSWORD_RESET_URLS is invalid: {error}'
    )

try:
    SMS_TOKEN_HASH_ALGORITHM = getattr(hashlib, SMS_TOKEN_HASH_ALGORITHM)
except ImportError as error:  # pragma: no cover
    raise ImproperlyConfigured(
        f'OPENWISP_RADIUS_SMS_TOKEN_HASH_ALGORITHM is invalid: {error}'
    )

try:
    assert int(SMS_TOKEN_LENGTH) <= 8 and int(SMS_TOKEN_LENGTH) >= 4
except AssertionError:  # pragma: no cover
    raise ImproperlyConfigured(
        'OPENWISP_RADIUS_SMS_TOKEN_LENGTH must be a number between 4 and 8: '
        'lower would not be safe and higher would not be practical from '
        'a ux perspective.'
    )

ALLOWED_MOBILE_PREFIXES = get_settings_value('ALLOWED_MOBILE_PREFIXES', [])
