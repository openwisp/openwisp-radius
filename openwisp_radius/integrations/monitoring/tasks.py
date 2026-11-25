import logging
from contextlib import contextmanager
from functools import partial
from itertools import islice
from uuid import uuid4

from celery import shared_task
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.management import CommandError
from django.db.models import Count, F, Q, Sum, Value
from django.db.models.functions import Coalesce, Lower, Replace
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
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
RECONCILIATION_LOCK_KEY = "openwisp_radius:traffic_reconciliation:lock"


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


def _write_user_signup_metric_for_all(metric_key):
    metric_data = []
    start_time = timezone.now() - timezone.timedelta(hours=1)
    end_time = timezone.now()
    if metric_key == "user_signups":
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric
    # Get the total number of registered users
    registered_user_query = RegisteredUser.objects.exclude(
        user__date_joined__gt=end_time,
    )
    if metric_key == "user_signups":
        registered_user_query = registered_user_query.filter(
            user__date_joined__gt=start_time,
            user__date_joined__lte=end_time,
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
            date_joined__gt=start_time,
            date_joined__lte=end_time,
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
        metric_data.append((metric, {"value": count}))
    Metric.batch_write(metric_data)


def _write_user_signup_metrics_for_orgs(metric_key):
    metric_data = []
    start_time = timezone.now() - timezone.timedelta(hours=1)
    end_time = timezone.now()
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
        user__openwisp_users_organizationuser__created__gt=end_time,
    )

    if metric_key == "user_signups":
        registered_users_query = registered_users_query.filter(
            user__openwisp_users_organizationuser__organization_id=F("organization_id"),
            user__openwisp_users_organizationuser__created__gt=start_time,
            user__openwisp_users_organizationuser__created__lte=end_time,
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
            created__gt=start_time, created__lte=end_time
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
        metric_data.append((metric, {"value": count}))

    # Write metrics for organizations having only users without a
    # RegisteredUser for that organization. These organizations are not
    # present in ``registered_users`` because they have no matching
    # RegisteredUser rows.
    for org_id, count in users_without_registereduser.items():
        metric = get_metric_func(
            organization_id=org_id, registration_method="unspecified"
        )
        metric_data.append((metric, {"value": count}))

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
    _write_user_signup_metric_for_all(metric_key="user_signups")
    _write_user_signup_metric_for_all(metric_key="tot_user_signups")
    _write_user_signup_metrics_for_orgs(metric_key="user_signups")
    _write_user_signup_metrics_for_orgs(metric_key="tot_user_signups")


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
    # Traffic is reported by reconciliation. Closure points only count users.
    return _write_radiusaccounting(
        username,
        organization_id,
        0,
        0,
        calling_station_id,
        called_station_id,
        time,
    )


def _write_radiusaccounting(
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
    extra_tags = {
        "method": registration_method,
        "organization_id": organization_id,
        "calling_station_id": sha1_hash(calling_station_id),
        "called_station_id": called_station_id,
    }
    metric = _accounting_metric(organization_id, called_station_id, extra_tags)
    metric.write(
        input_octets,
        extra_values={
            "output_octets": output_octets,
            "username": sha1_hash(username),
        },
        time=time,
        check=False,
    )


def _accounting_metric(organization_id, called_station_id, extra_tags):
    device_lookup = Q(mac_address__iexact=called_station_id.replace("-", ":"))
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
    if not object_id:
        # Adding a chart requires all parameters of extra_tags to be present.
        # A chart cannot be created without object_id and content_type.
        return metric
    if created:
        for configuration in metric.config_dict["charts"].keys():
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()
    return metric


def _accounting_totals(queryset):
    station = Lower(
        Replace(Coalesce("called_station_id", Value("")), Value("-"), Value(":"))
    )
    return (
        queryset.order_by()
        .annotate(station=station)
        .values("organization_id", "station")
        .annotate(
            input_total=Coalesce(Sum("input_octets"), 0),
            output_total=Coalesce(Sum("output_octets"), 0),
        )
        .iterator()
    )


def _traffic_delta(group, previous, current):
    previous_input, previous_output = previous
    current_input, current_output = current
    input_delta = current_input - previous_input
    output_delta = current_output - previous_output
    if input_delta < 0:
        logger.warning(
            "RADIUS accounting input counter decreased for group %s: %s to %s",
            group,
            previous_input,
            current_input,
        )
    if output_delta < 0:
        logger.warning(
            "RADIUS accounting output counter decreased for group %s: %s to %s",
            group,
            previous_output,
            current_output,
        )
    return max(input_delta, 0), max(output_delta, 0)


def _recover_baseline(organization_id, station):
    metric = Metric(key="radius_acc", configuration="radius_acc")
    points = metric.read(
        fields=["baseline_input", "baseline_output"],
        tags={
            "accounting_organization_id": str(organization_id),
            "called_station_id": station.replace("\\", "\\\\").replace("'", "\\'"),
        },
        order="-time",
        limit=1,
        where=[("baseline_input", ">=", -(2**63))],
    )
    if not points:
        return None
    # A location change creates another series, so InfluxDB can return one
    # latest point for each series even when the query uses LIMIT 1.
    latest = max(points, key=lambda point: point["time"])
    return latest["baseline_input"], latest["baseline_output"]


@contextmanager
def _reconciliation_lock():
    token = str(uuid4())
    acquired = cache.add(RECONCILIATION_LOCK_KEY, token, timeout=6 * 3600)
    try:
        yield acquired
    finally:
        if acquired and cache.get(RECONCILIATION_LOCK_KEY) == token:
            cache.delete(RECONCILIATION_LOCK_KEY)


RECONCILIATION_STATE_KEY = "openwisp_radius:traffic_reconciliation:state"


def _load_traffic_state():
    state = cache.get(RECONCILIATION_STATE_KEY)
    if state is not None:
        cleanup = state.get("cleanup")
        if cleanup is not None:
            # Cleanup deletes every selected row in one transaction. One saved
            # row ID distinguishes a committed deletion from a rollback without
            # caching all IDs. Old sessions must not change outside this path.
            if RadiusAccounting.objects.filter(pk=cleanup["session"]).exists():
                del state["cleanup"]
                _save_traffic_state(state)
            else:
                _submit_cleanup_checkpoint(state, cleanup["groups"], cleanup["points"])
        return state
    # A checkpoint anywhere establishes that activation already happened.
    # Read errors must propagate rather than silently reseeding live traffic.
    metric = Metric(key="radius_acc", configuration="radius_acc")
    checkpoints = metric.read(
        fields=["baseline_input", "baseline_output"],
        extra_fields=["accounting_organization_id", "called_station_id"],
        tags={},
        order="-time",
        where=[("baseline_input", ">=", -(2**63))],
    )
    groups = {}
    for point in checkpoints:
        group = (point["accounting_organization_id"], point["called_station_id"] or "")
        if group not in groups:
            groups[group] = (point["baseline_input"], point["baseline_output"])
    return {"active": bool(checkpoints), "groups": groups, "queued": None}


def _save_traffic_state(state):
    if cache.set(RECONCILIATION_STATE_KEY, state, timeout=None) is False:
        raise RuntimeError(_("Could not save RADIUS traffic state."))


def _submit_traffic(state, points):
    # Callers validate every point before changing observed totals or committing
    # deletion. Preserve this prepared payload on an uncertain queue submission.
    state["queued"] = points
    _save_traffic_state(state)
    _flush_traffic(state)


def _flush_traffic(state):
    if state["queued"] is not None:
        Metric.batch_write(state["queued"])
        state["queued"] = None
        _save_traffic_state(state)


def _traffic_point(group, total, delta, timestamp, check=True):
    organization_id, station = group
    input_total, output_total = total
    input_delta, output_delta = delta
    metric = _accounting_metric(
        organization_id,
        station,
        {
            "organization_id": organization_id,
            "accounting_organization_id": organization_id,
            "called_station_id": station,
        },
    )
    return metric, {
        "value": input_delta,
        "extra_values": {
            "output_octets": output_delta,
            "baseline_input": input_total,
            "baseline_output": output_total,
        },
        "time": timestamp,
        "check": check,
    }


@shared_task
def reconcile_radius_traffic(seed=False):
    """Submit hourly observations, not per-session or per-update traffic."""
    with _reconciliation_lock() as acquired:
        if not acquired:
            return False
        state = _load_traffic_state()
        # Exhaust the SQL observation before changing state. A failed query is
        # not an empty accounting table.
        totals = {
            (str(row["organization_id"]), row["station"]): (
                row["input_total"],
                row["output_total"],
            )
            for row in _accounting_totals(RadiusAccounting.objects.all())
        }
        _flush_traffic(state)
        initializing = not state["active"]
        if seed and not initializing:
            raise CommandError(_("Traffic baselines are already initialized."))
        if initializing and not totals:
            # An empty deployment still needs a recoverable activation checkpoint
            # so groups created later start from zero, including after cache loss.
            metric = Metric(
                key="radius_acc",
                configuration="radius_acc",
                field_name="input_octets",
                extra_tags={
                    "accounting_organization_id": "__all__",
                    "called_station_id": "",
                },
            )
            metric.full_clean()
            options = {
                "value": 0,
                "check": False,
                "time": timezone.now(),
                "extra_values": {
                    "output_octets": 0,
                    "baseline_input": 0,
                    "baseline_output": 0,
                },
            }
            metric.write(**options, write=False)
            _submit_traffic(state, [(metric, options)])
        groups_to_reconcile = set(totals)
        groups_to_reconcile.update(state["groups"])
        groups_to_reconcile.discard(("__all__", ""))
        remaining_groups = iter(groups_to_reconcile)
        # Bound prepared payloads and avoid queuing a Celery task or serializing
        # the whole baseline map separately for every accounting group.
        while True:
            batch = list(islice(remaining_groups, 1000))
            if not batch:
                break
            points = []
            observed = {}
            for group in batch:
                current = totals.get(group, (0, 0))
                previous = state["groups"].get(group)
                if previous is None:
                    previous = _recover_baseline(*group)
                if previous is None:
                    previous = current if initializing else (0, 0)
                delta = _traffic_delta(group, previous, current)
                metric, write_options = _traffic_point(
                    group, current, delta, timezone.now(), check=not initializing
                )
                # No group in this batch advances if local validation fails.
                metric.write(**write_options, write=False)
                observed[group] = current
                points.append((metric, write_options))
            state["groups"].update(observed)
            _submit_traffic(state, points)
        state["active"] = True
        _save_traffic_state(state)
        return True


@contextmanager
def _cleanup_coordination(queryset):
    with _reconciliation_lock() as acquired:
        if not acquired:
            raise CommandError(
                _("RADIUS traffic reconciliation is running; retry cleanup.")
            )
        state = _load_traffic_state()
        _flush_traffic(state)

        def prepare_cleanup(batch):
            if not state["active"]:
                return lambda: None
            session = batch.order_by("pk").values_list("pk", flat=True).first()
            if session is None:
                return lambda: None
            adjusted_totals = {}
            points = []
            for row in _accounting_totals(batch):
                group = (str(row["organization_id"]), row["station"])
                baseline = state["groups"].get(group)
                if baseline is None:
                    baseline = _recover_baseline(*group) or (0, 0)
                baseline_input, baseline_output = baseline
                adjusted = (
                    baseline_input - row["input_total"],
                    baseline_output - row["output_total"],
                )
                adjusted_totals[group] = adjusted
                metric, write_options = _traffic_point(
                    group, adjusted, (0, 0), timezone.now(), check=False
                )
                metric.write(**write_options, write=False)
                points.append((metric, write_options))
            # Save the prepared adjustment before SQL can discard its counters.
            # Keep it separate from queued writes until deletion is committed.
            state["cleanup"] = {
                "session": session,
                "groups": adjusted_totals,
                "points": points,
            }
            _save_traffic_state(state)
            return partial(
                _submit_cleanup_checkpoint,
                state=state,
                adjusted_totals=adjusted_totals,
                points=points,
            )

        yield prepare_cleanup


def coordinate_accounting_cleanup(sender, queryset, **kwargs):
    return _cleanup_coordination(queryset)


def _submit_cleanup_checkpoint(state, adjusted_totals, points):
    """Apply prepared baseline adjustments only after the SQL deletion commits."""
    # Negative baselines retain growth on rows deleted before observation.
    state["groups"].update(adjusted_totals)
    state.pop("cleanup", None)
    _submit_traffic(state, points)
