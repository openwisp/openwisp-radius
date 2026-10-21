import logging
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone

from celery import shared_task
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.db.models import Count, F, Q
from django.utils import timezone
from openwisp_monitoring.db import timeseries_db
from swapper import load_model

from . import settings as app_settings
from .utils import clean_registration_method, sha1_hash

Metric = load_model("monitoring", "Metric")
Chart = load_model("monitoring", "Chart")
RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")
OrganizationUser = load_model("openwisp_users", "OrganizationUser")
Device = load_model("config", "Device")
DeviceLocation = load_model("geo", "Location")
User = get_user_model()

logger = logging.getLogger(__name__)

REGISTRATION_METRICS_WATERMARK = "openwisp-radius:registration-metrics:v1:watermark"
REGISTRATION_METRICS_LOCK = "openwisp-radius:registration-metrics:v1:lock"
REGISTRATION_METRICS_LOCK_TIMEOUT = 900
REGISTRATION_METRICS_MAX_HOURS = 24


def _get_user_signup_metric(organization_id, registration_method):
    metric, _ = Metric._get_or_create(
        configuration="user_signups",
        name="User SignUps",
        key="user_signups",
        object_id=None,
        content_type=None,
        extra_tags={
            "organization_id": str(organization_id),
            "method": registration_method,
        },
    )
    return metric


def _get_total_user_signup_metric(organization_id, registration_method):
    metric, _ = Metric._get_or_create(
        configuration="tot_user_signups",
        name="Total User SignUps",
        key="tot_user_signups",
        object_id=None,
        content_type=None,
        extra_tags={
            "organization_id": str(organization_id),
            "method": registration_method,
        },
    )
    return metric


def _write_user_signup_metric_for_all(metric_key, start_time, end_time):
    metric_data = []
    if metric_key == "user_signups":
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric
    # Get the total number of registered users
    registered_user_query = RegisteredUser.objects.exclude(
        user__date_joined__gte=end_time,
    )
    if metric_key == "user_signups":
        registered_user_query = registered_user_query.filter(
            user__date_joined__gte=start_time,
            user__date_joined__lt=end_time,
        )
    total_registered_users = dict(
        registered_user_query.values_list("method").annotate(
            count=Count("user", distinct=True)
        )
    )
    # Some manually created users, like superuser may not have a
    # RegisteredUser object. We would count them with "unspecified" method
    users_without_registereduser_query = User.objects.filter(
        registered_users__isnull=True
    )
    if metric_key == "user_signups":
        users_without_registereduser_query = users_without_registereduser_query.filter(
            date_joined__gte=start_time,
            date_joined__lt=end_time,
        )
    else:
        users_without_registereduser_query = users_without_registereduser_query.filter(
            date_joined__lt=end_time
        )
    users_without_registereduser = users_without_registereduser_query.count()

    # Add the number of users which do not have a related RegisteredUser
    # to the number of users which registered using "unspecified" method.
    try:
        total_registered_users[""] = (
            total_registered_users[""] + users_without_registereduser
        )
    except KeyError:
        total_registered_users[""] = users_without_registereduser

    for method, count in total_registered_users.items():
        method = clean_registration_method(method)
        if method is None:
            continue
        metric = get_metric_func(organization_id="__all__", registration_method=method)
        metric_data.append((metric, {"value": count, "time": start_time}))
    return metric_data


def _write_user_signup_metrics_for_orgs(metric_key, start_time, end_time):
    metric_data = []
    if metric_key == "user_signups":
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric

    # Get registration data grouped by organization and registration method.
    # Scope OrganizationUser joins to the same organization as the
    # RegisteredUser to avoid memberships from other organizations affecting
    # this organization's signup metrics.
    registered_users_query = RegisteredUser.objects.exclude(
        method="pending_verification"
    ).exclude(
        user__openwisp_users_organizationuser__organization_id=F("organization_id"),
        user__openwisp_users_organizationuser__created__gte=end_time,
    )

    if metric_key == "user_signups":
        registered_users_query = registered_users_query.filter(
            user__openwisp_users_organizationuser__organization_id=F("organization_id"),
            user__openwisp_users_organizationuser__created__gte=start_time,
            user__openwisp_users_organizationuser__created__lt=end_time,
        )
    registered_users = registered_users_query.values_list(
        "organization_id",
        "method",
    ).annotate(count=Count("user_id", distinct=True))

    # Count users without a RegisteredUser for this organization.
    # A simple ``registered_users__isnull=True`` check would incorrectly
    # exclude users having RegisteredUser rows only in other organizations.
    users_without_registereduser_query = OrganizationUser.objects.exclude(
        user__registered_users__organization_id=F("organization_id")
    )
    if metric_key == "user_signups":
        users_without_registereduser_query = users_without_registereduser_query.filter(
            created__gte=start_time, created__lt=end_time
        )
    else:
        users_without_registereduser_query = users_without_registereduser_query.filter(
            created__lt=end_time
        )
    users_without_registereduser = dict(
        users_without_registereduser_query.values_list("organization_id").annotate(
            count=Count("user_id", distinct=True)
        )
    )

    for org_id, registration_method, count in registered_users:
        registration_method = clean_registration_method(registration_method)
        if registration_method == "unspecified":
            count += users_without_registereduser.pop(org_id, 0)
        metric = get_metric_func(
            organization_id=org_id, registration_method=registration_method
        )
        metric_data.append((metric, {"value": count, "time": start_time}))

    # Write metrics for organizations having only users without a
    # RegisteredUser for that organization. These organizations are not
    # present in ``registered_users`` because they have no matching
    # RegisteredUser rows.
    for org_id, count in users_without_registereduser.items():
        metric = get_metric_func(
            organization_id=org_id, registration_method="unspecified"
        )
        metric_data.append((metric, {"value": count, "time": start_time}))
    return metric_data


def _get_completion_metric():
    return Metric._get_or_create(
        configuration="reg_metrics_done",
        name="Registration metrics completion",
        key="radius_registration_metrics_completion",
        object_id=None,
        content_type=None,
    )[0]


def _get_completed_hour(value):
    return value.astimezone(datetime_timezone.utc).replace(
        minute=0, second=0, microsecond=0
    )


def _get_legacy_watermark():
    latest = None
    for key in ("user_signups", "tot_user_signups"):
        points = timeseries_db.read(
            key=key,
            fields="count",
            tags={"organization_id": "__all__"},
            order="-time",
            limit=1,
            precision="s",
        )
        if points:
            timestamp = timezone.datetime.fromtimestamp(
                points[0]["time"], datetime_timezone.utc
            )
            latest = max(latest, timestamp) if latest else timestamp
    if latest:
        watermark = _get_completed_hour(latest)
        if watermark < latest:
            watermark += timedelta(hours=1)
        return watermark


def _get_watermark(latest_completed_hour):
    value = cache.get(REGISTRATION_METRICS_WATERMARK)
    if value:
        try:
            watermark = timezone.datetime.fromisoformat(value)
        except (TypeError, ValueError):
            watermark = None
        if watermark and watermark.tzinfo and watermark <= latest_completed_hour:
            return watermark
        logger.warning("Ignoring invalid registration metrics watermark")
    points = _get_completion_metric().read(order="-time", limit=1, precision="s")
    if points:
        watermark = timezone.datetime.fromtimestamp(
            points[0]["time"], datetime_timezone.utc
        )
        if watermark <= latest_completed_hour:
            return watermark
    return _get_legacy_watermark() or (latest_completed_hour - timedelta(hours=1))


def _write_registration_metrics(start_time, end_time, write_completion=True):
    metric_data = []
    for metric_key in ("user_signups", "tot_user_signups"):
        metric_data.extend(
            _write_user_signup_metric_for_all(metric_key, start_time, end_time)
        )
        metric_data.extend(
            _write_user_signup_metrics_for_orgs(metric_key, start_time, end_time)
        )
    if metric_data:
        Metric.batch_write(metric_data, acknowledged=True)
    if write_completion:
        Metric.batch_write(
            [(_get_completion_metric(), {"value": 1, "time": end_time})],
            acknowledged=True,
        )


@shared_task
def write_user_registration_metrics(start_time=None, end_time=None):
    """Writes registration metrics for an explicit or missing hour interval.

    When start_time and end_time are provided, writes that interval directly.
    Otherwise, backfills up to 24 completed UTC hours and queues another task
    if more work remains.
    """
    if start_time is not None or end_time is not None:
        if start_time is None or end_time is None:
            raise ValueError("start_time and end_time must be provided together")
        if isinstance(start_time, str):
            start_time = datetime.fromisoformat(start_time)
        if isinstance(end_time, str):
            end_time = datetime.fromisoformat(end_time)
        _write_registration_metrics(start_time, end_time, write_completion=False)
        return
    lock = getattr(cache, "lock", None)
    if not lock:
        logger.error("Registration metrics require a cache backend with locks")
        return
    lock = lock(
        REGISTRATION_METRICS_LOCK,
        timeout=REGISTRATION_METRICS_LOCK_TIMEOUT,
        blocking_timeout=0,
    )
    if not lock.acquire(blocking=False):
        logger.info("Registration metrics task skipped because its lock is held")
        return
    schedule_continuation = False
    try:
        latest_completed_hour = _get_completed_hour(timezone.now())
        watermark = _get_watermark(latest_completed_hour)
        for _ in range(REGISTRATION_METRICS_MAX_HOURS):
            if watermark >= latest_completed_hour:
                break
            end_time = watermark + timedelta(hours=1)
            lock.extend(REGISTRATION_METRICS_LOCK_TIMEOUT, replace_ttl=True)
            _write_registration_metrics(watermark, end_time)
            cache.set(
                REGISTRATION_METRICS_WATERMARK, end_time.isoformat(), timeout=None
            )
            watermark = end_time
        schedule_continuation = watermark < latest_completed_hour
    finally:
        lock.release()
    if schedule_continuation:
        logger.info(
            "Scheduling registration metrics continuation from %s to %s",
            watermark,
            latest_completed_hour,
        )
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
