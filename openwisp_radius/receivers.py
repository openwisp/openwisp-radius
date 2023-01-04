"""
Receiver functions for django signals (eg: post_save)
"""
import logging

from celery.exceptions import OperationalError
from django.db import transaction

from openwisp_radius.tasks import send_login_email

from . import settings as app_settings
from . import tasks
from .utils import create_default_groups, load_model

logger = logging.getLogger(__name__)


def send_email_on_new_accounting_handler(sender, accounting_data, view, **kwargs):
    request = view.request
    accounting_data['organization'] = request.auth
    status_type = request.data.get('status_type')
    framed_protocol = accounting_data.get('framed_protocol')
    # don't send login email when the
    # accounting `framed_protocol` is 'PPP'
    if status_type == 'Start' and framed_protocol != 'PPP':
        try:
            send_login_email.delay(accounting_data)
        except OperationalError:
            logger.warning('Celery broker is unreachable')


def set_default_group_handler(sender, instance, created, **kwargs):
    if created:
        RadiusGroup = load_model('RadiusGroup')
        RadiusUserGroup = load_model('RadiusUserGroup')
        queryset = RadiusGroup.objects.filter(
            default=True, organization_id=instance.organization_id
        )
        if (
            queryset.exists()
            and not instance.user.radiususergroup_set.filter(
                group__organization_id=instance.organization_id
            ).exists()
        ):
            ug = RadiusUserGroup(user=instance.user, group=queryset.first())
            ug.full_clean()
            ug.save()


def create_default_groups_handler(sender, instance, created, **kwargs):
    if created:
        create_default_groups(organization=instance)


def organization_pre_save(instance, **kwargs):
    if instance._state.adding:
        return
    Organization = instance.__class__
    current = Organization.objects.get(pk=instance.pk)
    # TODO: this is a (hopefully) short-term necessary (ugly) hack
    # in the long term we will need to avoid relying on this
    # and find a solution to manage group check queries
    # of different organizations in a way that doesn't require
    # group names to be unique to each org
    if instance.slug != current.slug:
        instance.__old_slug = current.slug


def organization_post_save(instance, **kwargs):
    if instance._state.adding or not hasattr(instance, '__old_slug'):
        return
    RadiusGroup = load_model('RadiusGroup')
    for rg in RadiusGroup.objects.filter(organization=instance):
        rg.name = rg.name.replace(instance.__old_slug, instance.slug)
        rg.full_clean()
        rg.save()


def convert_radius_called_station_id(instance, created, **kwargs):
    if not created or not instance.called_station_id:
        return
    try:
        # organization slug is maintained for backward compatibility
        # but will removed in future versions
        assert instance.called_station_id in app_settings.CALLED_STATION_IDS.get(
            str(instance.organization.id), {}
        ).get(
            'unconverted_ids', []
        ) or instance.called_station_id in app_settings.CALLED_STATION_IDS.get(
            instance.organization.slug, {}
        ).get(
            'unconverted_ids', []
        )
    except AssertionError:
        return
    tasks.convert_called_station_id.delay(instance.unique_id)


def close_previous_radius_accounting_sessions(instance, created, **kwargs):
    if not created or not instance.called_station_id:
        return
    RadiusAccounting = load_model('RadiusAccounting')
    closed_session = []
    open_sessions = RadiusAccounting.objects.exclude(
        unique_id=instance.unique_id
    ).filter(
        stop_time__isnull=True,
        called_station_id=instance.called_station_id,
        calling_station_id=instance.calling_station_id,
        username=instance.username,
    )
    for session in open_sessions:
        session.stop_time = session.update_time
        session.terminate_cause = 'Session-Timeout'
        closed_session.append(session)
    RadiusAccounting.objects.bulk_update(
        closed_session, fields=['stop_time', 'terminate_cause']
    )


def radius_user_group_change(sender, instance, **kwargs):
    RadiusUserGroup = load_model('RadiusUserGroup')
    RadiusAccounting = load_model('RadiusAccounting')
    try:
        db_instance = RadiusUserGroup.objects.only('group_id').get(id=instance.id)
    except RadiusUserGroup.DoesNotExist:
        return
    user_has_open_session = RadiusAccounting.objects.filter(
        username=instance.username, stop_time__isnull=True
    ).exists()
    if instance.group_id != db_instance.group_id and user_has_open_session:
        transaction.on_commit(
            lambda: tasks.perform_change_of_authorization.delay(
                user_id=instance.user_id,
                old_group_id=db_instance.group_id,
                new_group_id=instance.group_id,
            )
        )
