import ipaddress
import logging
from datetime import timedelta

import swapper
from celery import shared_task
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import management
from django.core.exceptions import ObjectDoesNotExist
from django.template import loader
from django.utils import timezone, translation
from django.utils.translation import gettext_lazy as _

from openwisp_utils.admin_theme.email import send_email
from openwisp_utils.tasks import OpenwispCeleryTask

from . import settings as app_settings
from .radclient.client import RadClient
from .utils import load_model

logger = logging.getLogger(__name__)


@shared_task
def delete_old_radacct(number_of_days=365):
    management.call_command('delete_old_radacct', number_of_days)


@shared_task
def cleanup_stale_radacct(number_of_days=365):
    management.call_command('cleanup_stale_radacct', number_of_days)


@shared_task
def delete_old_postauth(number_of_days=365):
    management.call_command('delete_old_postauth', number_of_days)


@shared_task
def deactivate_expired_users():
    management.call_command('deactivate_expired_users')


@shared_task
def delete_old_users(older_than_months=12):
    management.call_command('delete_old_users', older_than_months=older_than_months)


@shared_task
def delete_unverified_users(older_than_days=1, exclude_methods=''):
    management.call_command(
        'delete_unverified_users',
        older_than_days=older_than_days,
        exclude_methods=exclude_methods,
    )


@shared_task
def unverify_inactive_users():
    if not app_settings.UNVERIFY_INACTIVE_USERS:
        return
    RegisteredUser = load_model('RegisteredUser')
    RegisteredUser.objects.filter(
        user__is_staff=False,
        user__last_login__lt=timezone.now()
        - timedelta(days=app_settings.UNVERIFY_INACTIVE_USERS),
    ).update(is_verified=False)


@shared_task
def delete_inactive_users():
    if not app_settings.DELETE_INACTIVE_USERS:
        return
    User = get_user_model()
    User.objects.filter(
        is_staff=False,
        last_login__lt=timezone.now()
        - timedelta(days=app_settings.DELETE_INACTIVE_USERS),
    ).delete()


@shared_task
def convert_called_station_id(unique_id=None):
    management.call_command('convert_called_station_id', unique_id=unique_id)


@shared_task(base=OpenwispCeleryTask)
def send_login_email(accounting_data):
    from allauth.account.models import EmailAddress
    from sesame.utils import get_query_string

    Organization = swapper.load_model('openwisp_users', 'Organization')
    username = accounting_data.get('username', None)
    org_uuid = accounting_data.get('organization')
    organization = Organization.objects.select_related('radius_settings').get(
        id=org_uuid
    )

    try:
        org_radius_settings = organization.radius_settings
    except ObjectDoesNotExist:
        logger.warning(
            f'Organization "{organization.name}" does not '
            'have any OpenWISP RADIUS settings configured'
        )
        return

    login_url = org_radius_settings.login_url
    if not login_url:
        logger.debug(f'login_url is not defined for {organization.name} organization')
        return

    try:
        user = (
            EmailAddress.objects.select_related('user')
            .get(user__username=username, verified=True, primary=True)
            .user
        )
    except ObjectDoesNotExist:
        logger.warning(f'user with username "{username}" does not exists')
        return
    if not user.is_member(organization):
        logger.warning(
            f'user with username "{username}" is not member of "{organization.name}"'
        )
        return

    with translation.override(user.language):
        one_time_login_url = login_url + get_query_string(user)
        subject = _('New WiFi session started')
        context = {
            'user': user,
            'subject': subject,
            'call_to_action_url': one_time_login_url,
            'call_to_action_text': _('Manage Session'),
        }
        if hasattr(settings, 'SESAME_MAX_AGE'):
            context.update(
                {
                    'sesame_max_age': timezone.now()
                    + timedelta(seconds=settings.SESAME_MAX_AGE)
                }
            )
        body_html = loader.render_to_string('radius_accounting_start.html', context)
        send_email(subject, body_html, body_html, [user.email], context)


@shared_task
def perform_change_of_authorization(user_id, old_group_id, new_group_id):
    RadiusAccounting = load_model('RadiusAccounting')
    RadiusGroupCheck = load_model('RadiusGroupCheck')
    RadiusGroup = load_model('RadiusGroup')
    Nas = load_model('Nas')
    User = get_user_model()

    def get_radsecret_from_radacct(rad_acct):
        qs = Nas.objects.filter(organization_id=rad_acct.organization_id).only(
            'name', 'secret'
        )
        for nas in qs.iterator():
            if ipaddress.ip_address(rad_acct.nas_ip_address) in ipaddress.ip_network(
                nas.name
            ):
                return nas.secret

    def get_radius_attributes():
        attributes = {}
        rad_group_checks = RadiusGroupCheck.objects.filter(group_id=new_group_id)
        if rad_group_checks:
            for check in rad_group_checks:
                attributes[check.attribute] = f'{check.value}'
        elif (
            not rad_group_checks
            and RadiusGroup.objects.filter(id=new_group_id).exists()
        ):
            # The new group does not have any limitations.
            # Unset attributes set by the previous group.
            rad_group_checks = RadiusGroupCheck.objects.filter(group_id=old_group_id)
            for check in rad_group_checks:
                attributes[check.attribute] = ''
        return attributes

    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        logger.warning(
            f'Failed to find user with "{user_id}" ID. Skipping CoA operation.'
        )
        return
    # Check is user has open RadiusAccounting sessions
    open_sessions = RadiusAccounting.objects.filter(
        username=user.username, stop_time__isnull=True
    ).select_related('organization', 'organization__radius_settings')
    if not open_sessions:
        logger.warning(
            f'The user with "{user_id}" ID does not have any open'
            ' RadiusAccounting sessions. Skipping CoA operation.'
        )
        return
    try:
        new_rad_group = RadiusGroup.objects.only('name').get(id=new_group_id)
    except RadiusGroup.DoesNotExist:
        logger.warning(
            f'Failed to find RadiusGroup with "{new_group_id}".'
            ' Skipping CoA operation.'
        )
        return
    else:
        attributes = get_radius_attributes()

    attributes['User-Name'] = user.username
    updated_sessions = []
    for session in open_sessions:
        if not session.organization.radius_settings.get_setting('coa_enabled'):
            continue
        radsecret = get_radsecret_from_radacct(session)
        if not radsecret:
            logger.warning(
                f'Failed to find RADIUS secret for "{session.unique_id}"'
                ' RadiusAccounting object. Skipping CoA operation'
                ' for this session.'
            )
            continue
        client = RadClient(
            host=session.nas_ip_address,
            radsecret=radsecret,
        )
        result = client.perform_change_of_authorization(attributes)
        if result is True:
            session.groupname = new_rad_group.name
            updated_sessions.append(session)
        else:
            logger.warning(
                f'Failed to perform CoA for "{session.unique_id}"'
                f' RadiusAccounting object of "{user}" user'
            )
    RadiusAccounting.objects.bulk_update(updated_sessions, fields=['groupname'])
