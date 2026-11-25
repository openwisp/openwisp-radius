from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.db import connections

from . import settings as app_settings
from .registration import validate_user_settable_registration_methods
from .utils import load_model


@checks.register
def check_saml_registration_enabled(app_configs, **kwargs):
    errors = []
    if (
        not app_settings.SAML_REGISTRATION_CONFIGURED
        and app_settings.SAML_REGISTRATION_ENABLED
    ):
        errors.append(
            checks.Warning(
                msg="Improperly Configured",
                hint=(
                    'You have set "OPENWISP_RADIUS_SAML_REGISTRATION_ENABLED" to '
                    '"True", but did not configure the project properly. '
                    'Kindly refer to the "Single Sign-On (SAML) Login" section '
                    "of the OpenWISP RADIUS documentation and configure your "
                    "project correctly. Registration using SAML will not work "
                    "in the current configuration."
                ),
                obj="Settings",
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
                msg="Improperly Configured",
                hint=(
                    'You have set "OPENWISP_RADIUS_SOCIAL_REGISTRATION_ENABLED" to '
                    '"True", but did not configure the project properly. '
                    'Kindly refer to the "Social Login" section of the '
                    "OpenWISP RADIUS documentation and configure your "
                    "project correctly. Registration using social applications "
                    "will not work in the current configuration."
                ),
                obj="Settings",
            )
        )
    return errors


@checks.register
def check_user_settable_registration_methods(app_configs, **kwargs):
    errors = []
    try:
        validate_user_settable_registration_methods(
            app_settings.USER_SETTABLE_REGISTRATION_METHODS
        )
    except ImproperlyConfigured as error:
        errors.append(
            checks.Error(
                msg="Improperly Configured",
                hint=str(error),
                obj="Settings",
            )
        )
    return errors


@checks.register(checks.Tags.database)
def check_group_session_timeouts(app_configs, **kwargs):
    if not kwargs.get("databases"):
        return []
    errors = []
    limit = app_settings.session_timeout_limit()
    model = load_model("RadiusGroupReply")
    for alias in kwargs["databases"]:
        # Database checks also run before migrations create this table.
        if model._meta.db_table not in connections[alias].introspection.table_names():
            continue
        replies = (
            model.objects.using(alias)
            .filter(
                attribute__in=("Session-Timeout", "reply:Session-Timeout"),
                group__isnull=False,
            )
            .select_related("group__organization")
        )
        for reply in replies.iterator():
            try:
                timeout = int(reply.value)
            except ValueError:
                timeout = -1
            if not 0 <= timeout <= limit:
                errors.append(
                    checks.Error(
                        f'Organization "{reply.group.organization}" group '
                        f'"{reply.group}" in database "{alias}" has '
                        f'Session-Timeout "{reply.value}", '
                        f"outside the allowed range 0 to {limit}.",
                        obj=reply,
                        id="openwisp_radius.E001",
                    )
                )
    return errors
