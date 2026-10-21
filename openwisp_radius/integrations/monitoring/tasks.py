import logging
from datetime import datetime

from celery import shared_task
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.utils import timezone
from swapper import load_model

from . import settings as app_settings
from . import utils
from .utils import clean_registration_method, sha1_hash

Metric = load_model("monitoring", "Metric")
Chart = load_model("monitoring", "Chart")
RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
Device = load_model("config", "Device")

logger = logging.getLogger(__name__)


@shared_task
def write_user_registration_metrics(start_time=None, end_time=None):
    """Writes registration metrics for an explicit or missing hour interval.

    When start_time and end_time are provided, writes that interval directly.
    Otherwise, fills in up to 24 completed UTC hours and queues another task
    if more work remains.
    """
    if start_time is not None or end_time is not None:
        if start_time is None or end_time is None:
            raise ValueError("start_time and end_time must be provided together")
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time)
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time)
        if not timezone.is_aware(start_time) or not timezone.is_aware(end_time):
            raise ValueError("start_time and end_time must be timezone-aware")
        if start_time >= end_time:
            raise ValueError("start_time must be earlier than end_time")
        utils._write_registration_metrics(start_time, end_time, write_completion=False)
        return
    if utils.write_registration_metrics():
        write_user_registration_metrics.delay()


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
    registration_method = (
        RegisteredUser.objects.only("method")
        .filter(user__username=username, organization_id=organization_id)
        .first()
    )
    if registration_method is None:
        logger.info(
            f'RegisteredUser object not found for "{username}".'
            ' The metric will be written with "unspecified" registration method!'
        )
        registration_method = "unspecified"
    else:
        registration_method = registration_method.method
    registration_method = clean_registration_method(registration_method)
    if registration_method is None:
        registration_method = "unspecified"
    device_lookup = Q(mac_address__iexact=called_station_id.replace("-", ":"))
    extra_tags = {
        "method": registration_method,
        "organization_id": organization_id,
        "calling_station_id": sha1_hash(calling_station_id),
        "called_station_id": called_station_id,
    }
    # Do not use organization_id for device lookup if shared accounting is enabled
    if not app_settings.SHARED_ACCOUNTING:
        device_lookup &= Q(organization_id=organization_id)
    try:
        device = (
            Device.objects.select_related("devicelocation")
            .only("id", "organization_id", "devicelocation__location_id")
            .get(device_lookup)
        )
    except Device.DoesNotExist:
        logger.warning(
            f'Device object not found with MAC "{called_station_id}"'
            f' and organization "{organization_id}".'
            " The metric will be written without a related object!"
        )
        object_id = None
        content_type = None
        if app_settings.SHARED_ACCOUNTING:
            extra_tags.pop("organization_id")
    else:
        object_id = str(device.id)
        content_type = ContentType.objects.get_for_model(Device)
        if hasattr(device, "devicelocation"):
            extra_tags["location_id"] = str(device.devicelocation.location_id)

    metric, created = Metric._get_or_create(
        configuration="radius_acc",
        name="RADIUS Accounting",
        key="radius_acc",
        object_id=object_id,
        content_type=content_type,
        extra_tags=extra_tags,
    )
    metric.write(
        input_octets,
        extra_values={
            "output_octets": output_octets,
            "username": sha1_hash(username),
        },
        time=time,
    )
    if not object_id:
        # Adding a chart requires all parameters of extra_tags to be present.
        # A chart cannot be created without object_id and content_type.
        return
    if created:
        for configuration in metric.config_dict["charts"].keys():
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()
