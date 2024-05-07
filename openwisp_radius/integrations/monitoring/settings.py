from django.conf import settings


def get_settings_value(option, default):
    return getattr(settings, f'OPENWISP_RADIUS_MONITORING_{option}', default)


DEVICE_LOOKUP_IGNORE_ORGANIZATION = get_settings_value(
    'DEVICE_LOOKUP_IGNORE_ORGANIZATION',
    False,
)
