import logging
from datetime import timedelta

import swapper
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.core import management
from django.core.exceptions import ObjectDoesNotExist
from django.template import loader
from django.utils import timezone, translation
from django.utils.translation import gettext_lazy as _

from openwisp_utils.admin_theme.email import send_email
from openwisp_utils.tasks import OpenwispCeleryTask

from . import settings as app_settings
from .utils import get_one_time_login_url, load_model

logger = logging.getLogger(__name__)


@shared_task
def delete_old_radacct(number_of_days=365):
    management.call_command("delete_old_radacct", number_of_days)


@shared_task
def cleanup_stale_radacct(number_of_days=365, number_of_hours=0):
    management.call_command("cleanup_stale_radacct", number_of_days, number_of_hours)


@shared_task
def delete_old_postauth(number_of_days=365):
    management.call_command("delete_old_postauth", number_of_days)


@shared_task
def deactivate_expired_users():
    management.call_command("deactivate_expired_users")


@shared_task
def delete_old_radiusbatch_users(
    older_than_months=None,
    older_than_days=app_settings.BATCH_DELETE_EXPIRED,
):
    management.call_command(
        "delete_old_radiusbatch_users",
        older_than_months=older_than_months,
        older_than_days=older_than_days,
    )


@shared_task
def delete_unverified_users(older_than_days=1, exclude_methods=""):
    management.call_command(
        "delete_unverified_users",
        older_than_days=older_than_days,
        exclude_methods=exclude_methods,
    )


@shared_task
def unverify_inactive_users():
    RegisteredUser = load_model("RegisteredUser")
    RegisteredUser.unverify_inactive_users()


@shared_task
def delete_inactive_users():
    RegisteredUser = load_model("RegisteredUser")
    RegisteredUser.delete_inactive_users()


@shared_task
def convert_called_station_id(unique_id=None):
    management.call_command("convert_called_station_id", unique_id=unique_id)


@shared_task(base=OpenwispCeleryTask)
def send_login_email(accounting_data):
    from allauth.account.models import EmailAddress

    Organization = swapper.load_model("openwisp_users", "Organization")
    username = accounting_data.get("username", None)
    org_uuid = accounting_data.get("organization")
    organization = Organization.objects.select_related("radius_settings").get(
        id=org_uuid
    )
    try:
        user = (
            EmailAddress.objects.select_related("user")
            .get(user__username=username, verified=True, primary=True)
            .user
        )
    except ObjectDoesNotExist:
        logger.warning(f'user with username "{username}" does not exists')
        return

    one_time_login_url = get_one_time_login_url(user, organization)
    if not one_time_login_url:
        return

    with translation.override(user.language):
        subject = _("New WiFi session started")
        context = {
            "user": user,
            "subject": subject,
            "call_to_action_url": one_time_login_url,
            "call_to_action_text": _("Manage Session"),
        }
        if hasattr(settings, "SESAME_MAX_AGE"):
            context.update(
                {
                    "sesame_max_age": timezone.now()
                    + timedelta(seconds=settings.SESAME_MAX_AGE)
                }
            )
        body_html = loader.render_to_string("radius_accounting_start.html", context)
        send_email(subject, body_html, body_html, [user.email], context)


@shared_task
def perform_change_of_authorization(user_id, old_group_id, new_group_id):
    from .coa import coa_manager

    coa_manager.perform_change_of_authorization(user_id, old_group_id, new_group_id)


@shared_task(soft_time_limit=7200)
def process_radius_batch(batch_id, number_of_users=None):
    RadiusBatch = load_model("RadiusBatch")
    try:
        batch = RadiusBatch.objects.get(pk=batch_id)
    except ObjectDoesNotExist as e:
        logger.warning(f'process_radius_batch("{batch_id}") failed: {e}')
        return
    try:
        batch.process(number_of_users=number_of_users, is_async=True)
    except SoftTimeLimitExceeded:
        logger.error(
            "soft time limit hit while executing "
            f"process for {batch} "
            f"(ID: {batch_id})"
        )
