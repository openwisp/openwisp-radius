import logging

import swapper
from celery import shared_task
from django.contrib.auth import get_user_model
from django.core import management
from django.core.exceptions import ObjectDoesNotExist
from django.template import loader
from django.utils.translation import activate
from django.utils.translation import gettext_lazy as _

from openwisp_utils.admin_theme.email import send_email

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
def convert_called_station_id(unique_id=None):
    management.call_command('convert_called_station_id', unique_id=unique_id)


@shared_task
def send_login_email(accounting_data):
    User = get_user_model()
    Organization = swapper.load_model('openwisp_users', 'Organization')
    username = accounting_data.get('username', None)
    org_uuid = accounting_data.get('organization')
    try:
        user = User.objects.get(username=username)
        organization = Organization.objects.get(id=org_uuid)
        if organization.is_member(user):
            from sesame.utils import get_query_string

            org_radius_settings = organization.radius_settings
            login_url = org_radius_settings.login_url
            if login_url:
                activate(user.language)
                one_time_login_url = login_url + get_query_string(user)
                subject = _('New radius accounting session started')
                context = {
                    'user': user,
                    'subject': subject,
                    'call_to_action_url': one_time_login_url,
                    'call_to_action_text': _('Manage Session'),
                }
                body_html = loader.render_to_string(
                    'radius_accounting_start.html', context
                )
                send_email(subject, body_html, body_html, [user.email], context)
            else:
                logger.error(
                    f'login_url is not defined for {organization.name} organization'
                )
        else:
            logger.warn(f'{username} is not the member of {organization.name}')
    except ObjectDoesNotExist:
        logger.warn(f'user with {username} does not exists')
