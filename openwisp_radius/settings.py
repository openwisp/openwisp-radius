import hashlib
from uuid import UUID

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# TODO: document this setting
PASSWORD_RESET_URLS = {
    # fallback in case the specific org page is not defined
    'default': 'https://example.com/{organization}/password/reset/{uid}/{token}',
    # use the uuid because the slug can change
}

PASSWORD_RESET_URLS.update(getattr(settings, 'OPENWISP_RADIUS_PASSWORD_RESET_URLS', {}))
SMS_DEFAULT_VERIFICATION = getattr(settings, 'OPENWISP_RADIUS_SMS_DEFAULT_VERIFICATION', False)
SMS_TOKEN_DEFAULT_VALIDITY = getattr(settings, 'OPENWISP_RADIUS_SMS_TOKEN_DEFAULT_VALIDITY', 30)  # minutes
SMS_TOKEN_LENGTH = getattr(settings, 'OPENWISP_RADIUS_SMS_TOKEN_LENGTH', 6)
SMS_TOKEN_HASH_ALGORITHM = getattr(settings, 'OPENWISP_RADIUS_SMS_TOKEN_HASH_ALGORITHM', 'sha256')
SMS_TOKEN_MAX_ATTEMPTS = getattr(settings, 'OPENWISP_RADIUS_SMS_TOKEN_MAX_ATTEMPTS', 3)
SMS_TOKEN_MAX_USER_DAILY = getattr(settings, 'OPENWISP_RADIUS_SMS_TOKEN_MAX_USER_DAILY', 3)
SMS_TOKEN_MAX_IP_DAILY = getattr(settings, 'OPENWISP_RADIUS_SMS_TOKEN_MAX_IP_DAILY', 25)

try:  # pragma: no cover
    assert PASSWORD_RESET_URLS
    for key, value in PASSWORD_RESET_URLS.items():
        if key != 'default':
            try:
                UUID(key)
            except ValueError:
                raise AssertionError('{} is not a valid UUID'.format(key))
        assert all([
            '{organization}' in value,
            '{uid}' in value,
            '{token}' in value,
        ]), ('{} must contain '.format(value) +  # noqa
             '{organization}, {uid} and {token}')
except AssertionError as e:
    raise ImproperlyConfigured(
        'OPENWISP_RADIUS_PASSWORD_RESET_URLS is invalid: {}'.format(str(e))
    )

try:  # pragma: no cover
    SMS_TOKEN_HASH_ALGORITHM = getattr(hashlib, SMS_TOKEN_HASH_ALGORITHM)
except ImportError as e:
    raise ImproperlyConfigured(
        'OPENWISP_RADIUS_SMS_TOKEN_HASH_ALGORITHM is invalid: {}'.format(str(e))
    )

try:  # pragma: no cover
    assert int(SMS_TOKEN_LENGTH) <= 8 and int(SMS_TOKEN_LENGTH) >= 4
except AssertionError:
    raise ImproperlyConfigured(
        'OPENWISP_RADIUS_SMS_TOKEN_LENGTH must be a number between 4 and 8: '
        'lower would not be safe and higher would not be practical from '
        'a ux perspective.'
    )
