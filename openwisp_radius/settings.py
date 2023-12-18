import hashlib
import logging
import os
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

# 'pre_django_setup' is supposed to be a logger
# that can work before registered Apps are
# ready in django.setup() process.
logger = logging.getLogger('pre_django_setup')
DEBUG = settings.DEBUG


def get_settings_value(option, default):
    if hasattr(settings, f'DJANGO_FREERADIUS_{option}'):  # pragma: no cover
        logger.warning(
            f'DJANGO_FREERADIUS_{option} setting is deprecated. It will be '
            f'removed in the future, please use OPENWISP_RADIUS_{option} instead.'
        )
        return getattr(settings, f'DJANGO_FREERADIUS_{option}')
    return getattr(settings, f'OPENWISP_RADIUS_{option}', default)


def get_default_password_reset_url(urls):
    # default is kept for backward compatibility,
    # will be removed in future versions
    return urls.get('default') or urls.get('__all__')


RADIUS_API = get_settings_value('API', True)
RADIUS_API_BASEURL = get_settings_value('API_BASEURL', '/')
RADIUS_API_URLCONF = get_settings_value('API_URLCONF', None)
EDITABLE_ACCOUNTING = get_settings_value('EDITABLE_ACCOUNTING', False)
EDITABLE_POSTAUTH = get_settings_value('EDITABLE_POSTAUTH', False)
GROUPCHECK_ADMIN = get_settings_value('GROUPCHECK_ADMIN', False)
GROUPREPLY_ADMIN = get_settings_value('GROUPREPLY_ADMIN', False)
USERGROUP_ADMIN = get_settings_value('USERGROUP_ADMIN', False)
USER_ADMIN_RADIUSTOKEN_INLINE = get_settings_value(
    'USER_ADMIN_RADIUSTOKEN_INLINE', False
)
DEFAULT_SECRET_FORMAT = get_settings_value('DEFAULT_SECRET_FORMAT', 'NT-Password')
DISABLED_SECRET_FORMATS = get_settings_value('DISABLED_SECRET_FORMATS', [])
BATCH_DEFAULT_PASSWORD_LENGTH = get_settings_value('BATCH_DEFAULT_PASSWORD_LENGTH', 8)
BATCH_DELETE_EXPIRED = get_settings_value('BATCH_DELETE_EXPIRED', 18)
BATCH_MAIL_SUBJECT = get_settings_value('BATCH_MAIL_SUBJECT', 'Credentials')
BATCH_MAIL_SENDER = get_settings_value('BATCH_MAIL_SENDER', settings.DEFAULT_FROM_EMAIL)
API_AUTHORIZE_REJECT = get_settings_value('API_AUTHORIZE_REJECT', False)
SOCIAL_REGISTRATION_CONFIGURED = 'allauth.socialaccount' in getattr(
    settings, 'INSTALLED_APPS', []
)
SOCIAL_REGISTRATION_ENABLED = get_settings_value('SOCIAL_REGISTRATION_ENABLED', False)
SAML_REGISTRATION_CONFIGURED = 'djangosaml2' in getattr(settings, 'INSTALLED_APPS', [])
SAML_REGISTRATION_ENABLED = get_settings_value('SAML_REGISTRATION_ENABLED', False)
MAC_ADDR_ROAMING_ENABLED = get_settings_value('MAC_ADDR_ROAMING_ENABLED', False)
SAML_REGISTRATION_METHOD_LABEL = get_settings_value(
    'SAML_REGISTRATION_METHOD_LABEL', _('Single Sign-On (SAML)')
)
SAML_IS_VERIFIED = get_settings_value('SAML_IS_VERIFIED', False)
SAML_UPDATES_PRE_EXISTING_USERNAME = get_settings_value(
    'SAML_UPDATES_PRE_EXISTING_USERNAME', False
)
UNVERIFY_INACTIVE_USERS = get_settings_value('UNVERIFY_INACTIVE_USERS', 0)
DELETE_INACTIVE_USERS = get_settings_value('DELETE_INACTIVE_USERS', 0)
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
PASSWORD_RESET_URLS = {
    # fallback in case the specific org page is not defined
    '__all__': 'https://{site}/{organization}/password/reset/confirm/{uid}/{token}',
    # use the uuid because the slug can change
}
PASSWORD_RESET_URLS.update(get_settings_value('PASSWORD_RESET_URLS', {}))
DEFAULT_PASSWORD_RESET_URL = get_default_password_reset_url(PASSWORD_RESET_URLS)
SMS_VERIFICATION_ENABLED = get_settings_value('SMS_VERIFICATION_ENABLED', False)
COA_ENABLED = get_settings_value('COA_ENABLED', False)
# SMS_TOKEN_DEFAULT_VALIDITY time is in minutes
SMS_TOKEN_DEFAULT_VALIDITY = get_settings_value('SMS_TOKEN_DEFAULT_VALIDITY', 30)
SMS_TOKEN_LENGTH = get_settings_value('SMS_TOKEN_LENGTH', 6)
SMS_TOKEN_HASH_ALGORITHM = get_settings_value('SMS_TOKEN_HASH_ALGORITHM', 'sha256')
SMS_TOKEN_MAX_ATTEMPTS = get_settings_value('SMS_TOKEN_MAX_ATTEMPTS', 5)
SMS_TOKEN_MAX_USER_DAILY = get_settings_value('SMS_TOKEN_MAX_USER_DAILY', 5)
SMS_COOLDOWN = get_settings_value('SMS_COOLDOWN', 30)
# default is high because openwisp-wifi-login-pages results always as 1 IP
SMS_TOKEN_MAX_IP_DAILY = get_settings_value('SMS_TOKEN_MAX_IP_DAILY', 999)
ALLOWED_MOBILE_PREFIXES = get_settings_value('ALLOWED_MOBILE_PREFIXES', [])
ALLOW_FIXED_LINE_OR_MOBILE = get_settings_value('ALLOW_FIXED_LINE_OR_MOBILE', False)
REGISTRATION_API_ENABLED = get_settings_value('REGISTRATION_API_ENABLED', True)
NEEDS_IDENTITY_VERIFICATION = get_settings_value('NEEDS_IDENTITY_VERIFICATION', False)
SMS_MESSAGE_TEMPLATE = get_settings_value(
    'SMS_MESSAGE_TEMPLATE', '{organization} verification code: {code}'
)
OPTIONAL_REGISTRATION_FIELDS = get_settings_value(
    'OPTIONAL_REGISTRATION_FIELDS',
    {
        'first_name': 'disabled',
        'last_name': 'disabled',
        'birth_date': 'disabled',
        'location': 'disabled',
    },
)

try:  # pragma: no cover
    assert PASSWORD_RESET_URLS
    for key, value in PASSWORD_RESET_URLS.items():
        if key != '__all__' and key != 'default':
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

# Path of urls that need to be refered in migrations files.
CSV_URL_PATH = 'api/v1/radius/organization/'
try:
    PRIVATE_STORAGE_INSTANCE = import_string(
        get_settings_value(
            'PRIVATE_STORAGE_INSTANCE',
            'openwisp_radius.private_storage.storage.private_file_system_storage',
        )
    )
except ImportError:
    raise ImproperlyConfigured('Failed to import PRIVATE_STORAGE_INSTANCE')

CALLED_STATION_IDS = get_settings_value('CALLED_STATION_IDS', {})

for organization in CALLED_STATION_IDS.keys():  # pragma: no cover
    try:
        UUID(organization)
    except ValueError:
        logger.warning(
            'Organization slug in CALLED_STATION_IDS setting is deprecated. '
            'It will be removed in future, please replace '
            f'organization slug: {organization} with its id.'
        )
CONVERT_CALLED_STATION_ON_CREATE = get_settings_value(
    'CONVERT_CALLED_STATION_ON_CREATE', False
)
OPENVPN_DATETIME_FORMAT = get_settings_value(
    'OPENVPN_DATETIME_FORMAT', u'%a %b %d %H:%M:%S %Y'
)

TRAFFIC_COUNTER_CHECK_NAME = get_settings_value(
    'TRAFFIC_COUNTER_CHECK_NAME', 'Max-Daily-Session-Traffic'
)
TRAFFIC_COUNTER_REPLY_NAME = get_settings_value(
    'TRAFFIC_COUNTER_REPLY_NAME', 'ChilliSpot-Max-Total-Octets'
)
RADCLIENT_ATTRIBUTE_DICTIONARIES = get_settings_value(
    'RADCLIENT_ATTRIBUTE_DICTIONARIES', []
)

# counters
COUNTERS_POSTGRESQL = (
    'openwisp_radius.counters.postgresql.daily_counter.DailyCounter',
    'openwisp_radius.counters.postgresql.daily_traffic_counter.DailyTrafficCounter',
    'openwisp_radius.counters.postgresql.monthly_traffic_counter.MonthlyTrafficCounter',
)
COUNTERS_MYSQL = (
    'openwisp_radius.counters.mysql.daily_counter.DailyCounter',
    'openwisp_radius.counters.mysql.daily_traffic_counter.DailyTrafficCounter',
    'openwisp_radius.counters.mysql.monthly_traffic_counter.MonthlyTrafficCounter',
)
COUNTERS_SQLITE = (
    'openwisp_radius.counters.sqlite.daily_counter.DailyCounter',
    'openwisp_radius.counters.sqlite.daily_traffic_counter.DailyTrafficCounter',
    'openwisp_radius.counters.sqlite.monthly_traffic_counter.MonthlyTrafficCounter',
)
DEFAULT_COUNTERS = {
    'django.db.backends.postgresql': COUNTERS_POSTGRESQL,
    'django.db.backends.mysql': COUNTERS_MYSQL,
    'django.db.backends.sqlite3': COUNTERS_SQLITE,
    # GIS backends
    'django.contrib.gis.db.backends.postgis': COUNTERS_POSTGRESQL,
    'django.contrib.gis.db.backends.mysql': COUNTERS_MYSQL,
    'django.contrib.gis.db.backends.spatialite': COUNTERS_SQLITE,
    'openwisp_utils.db.backends.spatialite': COUNTERS_SQLITE,
}

try:
    _counters = get_settings_value(
        'COUNTERS', DEFAULT_COUNTERS[settings.DATABASES['default']['ENGINE']]
    )
except KeyError as e:  # pragma: no cover
    raise ImproperlyConfigured(str(e))

RADIUS_ATTRIBUTES_TYPE_MAP = get_settings_value('RADIUS_ATTRIBUTES_TYPE_MAP', {})

COUNTERS = []
CHECK_ATTRIBUTE_COUNTERS_MAP = {}
for counter_path in _counters:
    try:
        counter_class = import_string(counter_path)
    except ImportError as e:  # pragma: no cover
        raise ImproperlyConfigured(str(e))
    COUNTERS.append(counter_class)
    CHECK_ATTRIBUTE_COUNTERS_MAP[counter_class.check_name] = counter_class


# Extend the EXPORT_USERS_COMMAND_CONFIG[fields]
if not hasattr(settings, 'OPENWISP_USERS_EXPORT_USERS_COMMAND_CONFIG'):
    from openwisp_users import settings as ow_users_settings

    ow_users_settings.EXPORT_USERS_COMMAND_CONFIG['fields'].extend(
        ['registered_user.method', 'registered_user.is_verified']
    )
    ow_users_settings.EXPORT_USERS_COMMAND_CONFIG['select_related'].extend(
        ['registered_user']
    )
