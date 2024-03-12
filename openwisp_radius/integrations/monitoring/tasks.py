import hashlib
import logging

from celery import shared_task
from django.contrib.contenttypes.models import ContentType
from swapper import load_model

Metric = load_model('monitoring', 'Metric')
Chart = load_model('monitoring', 'Chart')
RegisteredUser = load_model('openwisp_radius', 'RegisteredUser')
OrganizationUser = load_model('openwisp_users', 'OrganizationUser')
Device = load_model('config', 'Device')
DeviceLocation = load_model('geo', 'Location')

logger = logging.getLogger(__name__)


def sha1_hash(input_string):
    sha1 = hashlib.sha1()
    sha1.update(input_string.encode('utf-8'))
    return sha1.hexdigest()


def clean_registration_method(method):
    if method == '':
        method = 'unspecified'
    return method


@shared_task
def post_save_registereduser(user_id, registration_method):
    metric_data = []
    org_query = OrganizationUser.objects.filter(user_id=user_id).values_list(
        'organization_id', flat=True
    )
    if not org_query:
        logger.warning(
            f'"{user_id}" is not a member of any organization.'
            ' Skipping user_signup metric writing!'
        )
        return
    registration_method = clean_registration_method(registration_method)
    for org_id in org_query:
        metric, _ = Metric._get_or_create(
            configuration='user_signups',
            name='User SignUps',
            key='user_signups',
            object_id=None,
            content_type=None,
            extra_tags={
                'organization_id': str(org_id),
                'method': registration_method,
            },
        )
        metric_data.append((metric, {'value': sha1_hash(str(user_id))}))
    Metric.batch_write(metric_data)


@shared_task
def post_save_organizationuser(user_id, organization_id):
    try:
        registration_method = (
            RegisteredUser.objects.only('method').get(user_id=user_id).method
        )
    except RegisteredUser.DoesNotExist:
        logger.warning(
            f'RegisteredUser object not found for "{user_id}".'
            ' Skipping user_signup metric writing!'
        )
        return
    registration_method = clean_registration_method(registration_method)
    metric, _ = Metric._get_or_create(
        configuration='user_signups',
        name='User SignUps',
        key='user_signups',
        object_id=None,
        content_type=None,
        extra_tags={'organization_id': organization_id, 'method': registration_method},
    )
    metric.write(sha1_hash(str(user_id)))


@shared_task
def post_save_radiusaccounting(
    username,
    organization_id,
    input_octets,
    output_octets,
    calling_station_id,
    called_station_id,
):
    try:
        registration_method = (
            RegisteredUser.objects.only('method').get(user__username=username).method
        )
    except RegisteredUser.DoesNotExist:
        logger.warning(
            f'RegisteredUser object not found for "{username}".'
            ' Skipping radius_acc metric writing!'
        )
        return
    else:
        registration_method = clean_registration_method(registration_method)

    try:
        device = (
            Device.objects.select_related('devicelocation')
            .only('id', 'devicelocation__location_id')
            .get(
                mac_address__iexact=called_station_id.replace('-', ':'),
                organization_id=organization_id,
            )
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
            'calling_station_id': calling_station_id,
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
