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
        ]), ('{} must contain '.format(value) +
             '{organization}, {uid} and {token}')
except AssertionError as e:
    raise ImproperlyConfigured(
        'OPENWISP_RADIUS_PASSWORD_RESET_URLS is invalid: {}'.format(str(e))
    )
