"""Write accounting metrics and keep traffic baselines consistent during cleanup."""

import logging
from contextlib import contextmanager
from functools import partial
from itertools import islice
from uuid import uuid4

from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.management import CommandError
from django.db.models import Q, Sum, Value
from django.db.models.functions import Coalesce, Lower, Replace
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from swapper import load_model

from .. import settings as app_settings
from ..utils import clean_registration_method, sha1_hash

Metric = load_model("monitoring", "Metric")
Chart = load_model("monitoring", "Chart")
RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
Device = load_model("config", "Device")
RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")

logger = logging.getLogger(__name__)
RECONCILIATION_LOCK_KEY = "openwisp_radius:traffic_reconciliation:lock"
RECONCILIATION_STATE_KEY = "openwisp_radius:traffic_reconciliation:state"


def write_session(
    username,
    organization_id,
    input_octets,
    output_octets,
    calling_station_id,
    called_station_id,
    time=None,
):
    registration_method = _get_registration_method(username, organization_id)
    extra_tags = {
        "method": registration_method,
        "organization_id": organization_id,
        "calling_station_id": sha1_hash(calling_station_id),
        "called_station_id": called_station_id,
    }
    metric = accounting_metric(organization_id, called_station_id, extra_tags)
    metric.write(
        input_octets,
        extra_values={
            "output_octets": output_octets,
            "username": sha1_hash(username),
        },
        time=time,
        check=False,
    )


def _get_registration_method(username, organization_id):
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
    return registration_method


def accounting_metric(organization_id, called_station_id, extra_tags):
    """Share metric and device-chart lookup between session and traffic writes."""
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
    # Unmatched identifiers still contribute to general metrics, but device
    # charts require an object_id and content_type.
    if object_id and created:
        for configuration in metric.config_dict["charts"].keys():
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()
    return metric


@contextmanager
def _reconciliation_lock():
    token = str(uuid4())
    acquired = cache.add(RECONCILIATION_LOCK_KEY, token, timeout=6 * 3600)
    try:
        yield acquired
    finally:
        if acquired and cache.get(RECONCILIATION_LOCK_KEY) == token:
            cache.delete(RECONCILIATION_LOCK_KEY)


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
                group = (str(row["organization_id"]), row["clean_called_station_id"])
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
            # Save the prepared adjustment before SQL can discard its traffic totals.
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


def _accounting_totals(queryset):
    """Sum retained session traffic by accounting organization and device MAC.

    Reconciliation compares these totals with previous observations to measure
    new traffic, including traffic from sessions that have not yet closed.
    """
    clean_called_station_id = Lower(
        Replace(Coalesce("called_station_id", Value("")), Value("-"), Value(":"))
    )
    return (
        queryset.order_by()
        .annotate(clean_called_station_id=clean_called_station_id)
        .values("organization_id", "clean_called_station_id")
        .annotate(
            input_total=Coalesce(Sum("input_octets"), 0),
            output_total=Coalesce(Sum("output_octets"), 0),
        )
        .iterator()
    )


def _traffic_delta(group, previous, current):
    """Calculate newly observed input and output traffic independently.

    Unexpected decreases are logged and clamped to zero so changed accounting
    totals cannot produce negative traffic in charts.
    """
    previous_input, previous_output = previous
    current_input, current_output = current
    input_delta = current_input - previous_input
    output_delta = current_output - previous_output
    if input_delta < 0:
        logger.error(
            "RADIUS accounting input total decreased for group %s: %s to %s",
            group,
            previous_input,
            current_input,
        )
    if output_delta < 0:
        logger.error(
            "RADIUS accounting output total decreased for group %s: %s to %s",
            group,
            previous_output,
            current_output,
        )
    return max(input_delta, 0), max(output_delta, 0)


def _recover_baseline(organization_id, called_station_id):
    """Recover a group's latest observed totals after its cached baseline is lost.

    Only aggregate checkpoints contain baseline fields. Session-closure points
    must not be used to decide which traffic has already been reported.
    """
    metric = Metric(key="radius_acc", configuration="radius_acc")
    points = metric.read(
        fields=["baseline_input", "baseline_output"],
        tags={
            "accounting_organization_id": str(organization_id),
            "called_station_id": called_station_id.replace("\\", "\\\\").replace(
                "'", "\\'"
            ),
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


def _load_traffic_state():
    """Restore baselines and finish or discard a pending cleanup adjustment.

    Prefer cached state, including pending writes. If it is missing, recover
    persisted checkpoints rather than treating known traffic as a fresh start.
    """
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
    organization_id, called_station_id = group
    input_total, output_total = total
    input_delta, output_delta = delta
    metric = accounting_metric(
        organization_id,
        called_station_id,
        {
            "organization_id": organization_id,
            "accounting_organization_id": organization_id,
            "called_station_id": called_station_id,
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


def reconcile(seed=False):
    """Submit scheduled observations, not per-session or per-update traffic."""
    with _reconciliation_lock() as acquired:
        if not acquired:
            return False
        state = _load_traffic_state()
        # Exhaust the SQL observation before changing state. A failed query is
        # not an empty accounting table.
        totals = {
            (str(row["organization_id"]), row["clean_called_station_id"]): (
                row["input_total"],
                row["output_total"],
            )
            for row in _accounting_totals(RadiusAccounting.objects.all())
        }
        _flush_traffic(state)
        initializing = not state["active"]
        if seed and not initializing:
            raise CommandError(_("Traffic baselines are already initialized."))
        if not totals:
            # Refresh activation while idle so cache recovery can still count a
            # first session after the original checkpoint expires.
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


def coordinate_accounting_cleanup(sender, queryset, **kwargs):
    return _cleanup_coordination(queryset)


def _submit_cleanup_checkpoint(state, adjusted_totals, points):
    """Apply prepared baseline adjustments only after the SQL deletion commits."""
    # Negative baselines retain growth on rows deleted before observation.
    state["groups"].update(adjusted_totals)
    state.pop("cleanup", None)
    _submit_traffic(state, points)
