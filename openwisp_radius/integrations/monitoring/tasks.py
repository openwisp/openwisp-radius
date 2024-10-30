import logging

from celery import shared_task
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, Q
from django.utils import timezone
from swapper import load_model

from . import settings as app_settings
from .utils import clean_registration_method, sha1_hash

Metric = load_model('monitoring', 'Metric')
Chart = load_model('monitoring', 'Chart')
RegisteredUser = load_model('openwisp_radius', 'RegisteredUser')
RadiusAccounting = load_model('openwisp_radius', 'RadiusAccounting')
OrganizationUser = load_model('openwisp_users', 'OrganizationUser')
Device = load_model('config', 'Device')
DeviceLocation = load_model('geo', 'Location')
User = get_user_model()

logger = logging.getLogger(__name__)


def _get_user_signup_metric(organization_id, registration_method):
    metric, _ = Metric._get_or_create(
        configuration='user_signups',
        name='User SignUps',
        key='user_signups',
        object_id=None,
        content_type=None,
        extra_tags={
            'organization_id': str(organization_id),
            'method': registration_method,
        },
    )
    return metric


def _get_total_user_signup_metric(organization_id, registration_method):
    metric, _ = Metric._get_or_create(
        configuration='tot_user_signups',
        name='Total User SignUps',
        key='tot_user_signups',
        object_id=None,
        content_type=None,
        extra_tags={
            'organization_id': str(organization_id),
            'method': registration_method,
        },
    )
    return metric


def _write_user_signup_metric_for_all(metric_key):
    metric_data = []
    start_time = timezone.now() - timezone.timedelta(hours=1)
    end_time = timezone.now()
    if metric_key == 'user_signups':
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric
    # Get the total number of registered users
    registered_user_query = RegisteredUser.objects.exclude(
        user__date_joined__gt=end_time,
    )
    if metric_key == 'user_signups':
        registered_user_query = registered_user_query.filter(
            user__date_joined__gt=start_time,
            user__date_joined__lte=end_time,
        )
    total_registered_users = dict(
        registered_user_query.values_list('method').annotate(
            count=Count('user', distinct=True)
        )
    )
    # Some manually created users, like superuser may not have a
    # RegisteredUser object. We would could them with "unspecified" method
    users_without_registereduser_query = User.objects.filter(
        registered_user__isnull=True
    )
    if metric_key == 'user_signups':
        users_without_registereduser_query = users_without_registereduser_query.filter(
            date_joined__gt=start_time,
            date_joined__lte=end_time,
        )
    users_without_registereduser = users_without_registereduser_query.count()

    # Add the number of users which do not have a related RegisteredUser
    # to the number of users which registered using "unspecified" method.
    try:
        total_registered_users[''] = (
            total_registered_users[''] + users_without_registereduser
        )
    except KeyError:
        total_registered_users[''] = users_without_registereduser

    for method, count in total_registered_users.items():
        method = clean_registration_method(method)
        metric = get_metric_func(organization_id='__all__', registration_method=method)
        metric_data.append((metric, {'value': count}))
    Metric.batch_write(metric_data)


def _write_user_signup_metrics_for_orgs(metric_key):
    metric_data = []
    start_time = timezone.now() - timezone.timedelta(hours=1)
    end_time = timezone.now()
    if metric_key == 'user_signups':
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric

    # Get the registration data for the past hour.
    # The query returns a tuple of organization_id, registration_method and
    # count of users who registered with that organization and method.
    registered_users_query = RegisteredUser.objects.exclude(
        user__openwisp_users_organizationuser__created__gt=end_time,
    )

    if metric_key == 'user_signups':
        registered_users_query = registered_users_query.filter(
            user__openwisp_users_organizationuser__created__gt=start_time,
            user__openwisp_users_organizationuser__created__lte=end_time,
        )
    registered_users = registered_users_query.values_list(
        'user__openwisp_users_organizationuser__organization_id', 'method'
    ).annotate(count=Count('user_id', distinct=True))

    # There could be users which were manually created (e.g. superuser)
    # which do not have related RegisteredUser object. Add the count
    # of such users with the "unspecified" method.
    users_without_registereduser_query = OrganizationUser.objects.filter(
        user__registered_user__isnull=True
    )
    if metric_key == 'user_signups':
        users_without_registereduser_query = users_without_registereduser_query.filter(
            created__gt=start_time, created__lte=end_time
        )
    users_without_registereduser = dict(
        users_without_registereduser_query.values_list('organization_id').annotate(
            count=Count('user_id', distinct=True)
        )
    )

    for org_id, registration_method, count in registered_users:
        registration_method = clean_registration_method(registration_method)
        if registration_method == 'unspecified':
            count += users_without_registereduser.get(org_id, 0)
        metric = get_metric_func(
            organization_id=org_id, registration_method=registration_method
        )
        metric_data.append((metric, {'value': count}))
    Metric.batch_write(metric_data)


@shared_task
def write_user_registration_metrics():
    """
    This task is expected to be executed hourly.

    This task writes user registration metrics to the InfluxDB.
    It writes to the following metrics:
        - User Signups: This shows the number of new users who
            have registered using different methods
        - Total User Signups: This shows the total number of
            users registered using different methods
    """
    _write_user_signup_metric_for_all(metric_key='user_signups')
    _write_user_signup_metric_for_all(metric_key='tot_user_signups')
    _write_user_signup_metrics_for_orgs(metric_key='user_signups')
    _write_user_signup_metrics_for_orgs(metric_key='tot_user_signups')


@shared_task
def post_save_radiusaccounting(
    username,
    organization_id,
    input_octets,
    output_octets,
    calling_station_id,
    called_station_id,
    time=None,
):
    try:
        registration_method = (
            RegisteredUser.objects.only('method').get(user__username=username).method
        )
    except RegisteredUser.DoesNotExist:
        logger.info(
            f'RegisteredUser object not found for "{username}".'
            ' The metric will be written with "unspecified" registration method!'
        )
        registration_method = 'unspecified'
    else:
        registration_method = clean_registration_method(registration_method)
    device_lookup = Q(mac_address__iexact=called_station_id.replace('-', ':'))
    # Do not use organization_id for device lookup if shared accounting is enabled
    if not app_settings.SHARED_ACCOUNTING:
        device_lookup &= Q(organization_id=organization_id)
    try:
        device = (
            Device.objects.select_related('devicelocation')
            .only('id', 'organization_id', 'devicelocation__location_id')
            .get(device_lookup)
        )
    except Device.DoesNotExist:
        logger.warning(
            f'Device object not found with MAC "{called_station_id}"'
            f' and organization "{organization_id}".'
            ' The metric will be written without a related object!'
        )
        object_id = None
        content_type = None
        location_id = None
        if app_settings.SHARED_ACCOUNTING:
            organization_id = None
    else:
        object_id = str(device.id)
        content_type = ContentType.objects.get_for_model(Device)
        if hasattr(device, 'devicelocation'):
            location_id = str(device.devicelocation.location_id)
        else:
            location_id = None

    metric, created = Metric._get_or_create(
        configuration='radius_acc',
        name='RADIUS Accounting',
        key='radius_acc',
        object_id=object_id,
        content_type=content_type,
        extra_tags={
            'organization_id': organization_id,
            'method': registration_method,
            'calling_station_id': sha1_hash(calling_station_id),
            'called_station_id': called_station_id,
            'location_id': location_id,
        },
    )
    metric.write(
        input_octets,
        extra_values={
            'output_octets': output_octets,
            'username': sha1_hash(username),
        },
        time=time,
    )
    if not object_id:
        # Adding a chart requires all parameters of extra_tags to be present.
        # A chart cannot be created without object_id and content_type.
        return
    if created:
        for configuration in metric.config_dict['charts'].keys():
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()
