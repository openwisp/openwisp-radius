from django.core import checks

from . import settings as app_settings


@checks.register
def check_saml_registration_enabled(app_configs, **kwargs):
    errors = []
    if (
        not app_settings.SAML_REGISTRATION_CONFIGURED
        and app_settings.SAML_REGISTRATION_ENABLED
    ):
        errors.append(
            checks.Warning(
                msg='Improperly Configured',
                hint=(
                    'You have set "OPENWISP_RADIUS_SAML_REGISTRATION_ENABLED" to '
                    '"True", but did not configure the project properly. '
                    'Kindly refer to the "Single Sign-On (SAML) Login" section '
                    'of the OpenWISP RADIUS documentation and configure your '
                    'project correctly. Registration using SAML will not work '
                    'in the current configuration.'
                ),
                obj='Settings',
            )
        )
    return errors


@checks.register
def check_social_registration_enabled(app_configs, **kwargs):
    errors = []
    if (
        not app_settings.SOCIAL_REGISTRATION_CONFIGURED
        and app_settings.SOCIAL_REGISTRATION_ENABLED
    ):
        errors.append(
            checks.Warning(
                msg='Improperly Configured',
                hint=(
                    'You have set "OPENWISP_RADIUS_SOCIAL_REGISTRATION_ENABLED" to '
                    '"True", but did not configure the project properly. '
                    'Kindly refer to the "Social Login" section of the '
                    'OpenWISP RADIUS documentation and configure your '
                    'project correctly. Registration using social applications '
                    'will not work in the current configuration.'
                ),
                obj='Settings',
            )
        )
    return errors
