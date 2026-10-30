import hashlib
import logging
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Count, F
from django.utils import timezone
from openwisp_monitoring.db import timeseries_db
from swapper import load_model

local_timezone = timezone.get_current_timezone()

logger = logging.getLogger(__name__)

REGISTRATION_METRICS_WATERMARK = "openwisp-radius:registration-metrics:v1:watermark"
REGISTRATION_METRICS_LOCK = "openwisp-radius:registration-metrics:v1:lock"
REGISTRATION_METRICS_LOCK_TIMEOUT = 900
REGISTRATION_METRICS_MAX_HOURS = 24


def _get_metric_model():
    """Gets the monitoring Metric model after Django has started."""
    return load_model("monitoring", "Metric")


def _get_urlencoded_datetime(date_time):
    """Encodes a date and time value for use in a URL."""
    return urlencode({"": date_time}).split("=")[1]


def get_today_start_datetime():
    """Gets the start of the current day in the local time zone."""

    return timezone.make_aware(
        datetime.combine(timezone.localdate(), datetime.min.time())
    )


def get_utc_datetime_from_local_date():
    """Gets the start of the current local day in UTC."""
    return get_today_start_datetime().astimezone(dt_timezone.utc)


def get_datetime_filter_start_datetime():
    """Gets the encoded start time for date filters."""
    today = get_today_start_datetime()
    return _get_urlencoded_datetime(today)


def get_datetime_filter_stop_datetime():
    """Gets the encoded end time for date filters."""
    tomorrow = get_today_start_datetime() + timedelta(days=1)
    return _get_urlencoded_datetime(tomorrow)


def sha1_hash(input_string):
    """Returns the SHA-1 hash of a string."""
    sha1 = hashlib.sha1()
    sha1.update(input_string.encode("utf-8"))
    return sha1.hexdigest()


def clean_registration_method(method):
    """Normalizes registration method names used in metric tags."""
    if method == "":
        method = "unspecified"
    elif method == "pending_verification":
        return None
    return method


def _get_user_signup_metric(organization_id, registration_method):
    """Gets the hourly signup metric for an organization and method."""
    Metric = _get_metric_model()
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
    """Gets the total signup metric for an organization and method."""
    Metric = _get_metric_model()
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
    """Builds global signup data for one reporting period."""
    RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
    User = get_user_model()
    metric_data = []
    if metric_key == "user_signups":
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric
    # Count all registered users before the end of the reporting period.
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
    # Superusers and manually created users have no RegisteredUser row.
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
    # Include users without a registration method in the unspecified group.
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
    """Builds organization signup data for one reporting period."""
    RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
    OrganizationUser = load_model("openwisp_users", "OrganizationUser")
    metric_data = []
    if metric_key == "user_signups":
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric
    # Match OrganizationUser rows from the same organization only.
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
    # Do not exclude users with RegisteredUser rows in other organizations.
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
    # Include organizations with users but no RegisteredUser rows.
    for org_id, count in users_without_registereduser.items():
        metric = get_metric_func(
            organization_id=org_id, registration_method="unspecified"
        )
        metric_data.append((metric, {"value": count, "time": start_time}))
    return metric_data


def _get_completion_metric():
    """Gets the metric that records completed reporting periods."""
    Metric = _get_metric_model()
    return Metric._get_or_create(
        configuration="reg_metrics_done",
        name="Registration metrics completion",
        key="radius_registration_metrics_completion",
        object_id=None,
        content_type=None,
    )[0]


def _get_completed_hour(value):
    """Returns the UTC hour boundary for a time value."""
    return value.astimezone(dt_timezone.utc).replace(minute=0, second=0, microsecond=0)


def _get_legacy_watermark():
    """Finds the first missing hour after existing signup data."""
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
                points[0]["time"], dt_timezone.utc
            )
            latest = max(latest, timestamp) if latest else timestamp
    if latest:
        watermark = _get_completed_hour(latest)
        if watermark < latest:
            watermark += timedelta(hours=1)
        return watermark


def _get_watermark(latest_completed_hour):
    """Gets the saved reporting position or a safe starting point."""
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
        watermark = timezone.datetime.fromtimestamp(points[0]["time"], dt_timezone.utc)
        if watermark <= latest_completed_hour:
            return watermark
    return _get_legacy_watermark() or (latest_completed_hour - timedelta(hours=1))


def _write_registration_metrics(start_time, end_time, write_completion=True):
    """Writes signup metrics for one reporting period."""
    Metric = _get_metric_model()
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


def write_registration_metrics():
    """Writes missing hourly metrics and reports if more work remains."""
    lock = getattr(cache, "lock", None)
    if not lock:
        logger.error("Registration metrics require a cache backend with locks")
        return False
    lock = lock(
        REGISTRATION_METRICS_LOCK,
        timeout=REGISTRATION_METRICS_LOCK_TIMEOUT,
        blocking_timeout=0,
    )
    if not lock.acquire(blocking=False):
        logger.info("Registration metrics task skipped because its lock is held")
        return False
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
    finally:
        lock.release()
    if watermark < latest_completed_hour:
        logger.info(
            "Scheduling registration metrics continuation from %s to %s",
            watermark,
            latest_completed_hour,
        )
        return True
    return False
