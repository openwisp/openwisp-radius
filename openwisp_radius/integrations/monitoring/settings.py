from django.conf import settings


def get_settings_value(option, default):
    return getattr(settings, f'OPENWISP_RADIUS_MONITORING_{option}', default)


SHARED_ACCOUNTING = get_settings_value(
    'SHARED_ACCOUNTING',
    False,
)
