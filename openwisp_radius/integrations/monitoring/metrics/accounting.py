"""Write RADIUS session metrics and track traffic between collections."""

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
    """Write a session point that can be used to count unique users.

    Session closures pass zero to avoid double counting scheduled traffic.
    Historical rebuilds pass the original session totals.
    """
    registration_method = _get_registration_method(username, organization_id)
    extra_tags = {
        "method": registration_method,
        "organization_id": organization_id,
        "calling_station_id": sha1_hash(calling_station_id),
        "called_station_id": called_station_id,
    }
    metric = accounting_metric(
        organization_id, called_station_id, extra_tags, create_charts=False
    )
    metric.write(
        input_octets,
        extra_values={
            "output_octets": output_octets,
            "username": sha1_hash(username),
        },
        time=time,
        check=False,
    )
    _ensure_device_charts(metric)


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


def accounting_metric(
    organization_id, called_station_id, extra_tags, create_charts=True
):
    """Get or create an accounting metric and its device charts.

    Unmatched devices still contribute to general charts. Add the device's
    location to ``extra_tags`` in place when available.
    """
    device_lookup = Q(mac_address__iexact=called_station_id.replace("-", ":"))
    devices = Device.objects.select_related("devicelocation").only(
        "id", "organization_id", "devicelocation__location_id"
    )
    try:
        try:
            device = devices.get(device_lookup, organization_id=organization_id)
        except Device.DoesNotExist:
            if not app_settings.SHARED_ACCOUNTING:
                raise
            # MAC addresses are unique per organization, not across tenants.
            # Only use a shared device when the match is unambiguous.
            device = devices.get(device_lookup)
    except (Device.DoesNotExist, Device.MultipleObjectsReturned):
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

    metric, _ = Metric._get_or_create(
        configuration="radius_acc",
        name="RADIUS Accounting",
        key="radius_acc",
        object_id=object_id,
        content_type=content_type,
        extra_tags=extra_tags,
    )
    if create_charts:
        _ensure_device_charts(metric)
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
def _prepare_accounting_cleanup(queryset):
    """Hold the collection lock through cleanup and its commit callback.

    Deleting sessions lowers the current totals. Subtract the same traffic
    from the baselines so cleanup doesn't hide traffic since the last run.
    """
    with _reconciliation_lock() as acquired:
        if not acquired:
            raise CommandError(
                _("RADIUS traffic reconciliation is running; retry cleanup.")
            )
        state = _load_traffic_state()
        _flush_traffic(state)
        if not state["active"] and state["groups"]:
            raise CommandError(
                _(
                    "RADIUS traffic initialization is incomplete; "
                    "retry collection first."
                )
            )

        def prepare_cleanup(batch):
            if not state["active"]:
                return lambda: None
            # Cleanup deletes the whole batch in one transaction, so one session
            # ID is enough to check whether it committed.
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
                # A negative baseline preserves unreported traffic even if
                # cleanup deletes the last session in the group.
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
            # Cache the adjustment before the deleted totals are lost. Keep it
            # out of the write queue until commit so a rollback can't apply it.
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


def _accounting_totals(queryset, include_open=False):
    """Sum session traffic by accounting organization and normalized device MAC.

    With ``include_open``, get open subtotals in the same query.
    """
    clean_called_station_id = Lower(
        Replace(Coalesce("called_station_id", Value("")), Value("-"), Value(":"))
    )
    totals = (
        queryset.order_by()
        .annotate(clean_called_station_id=clean_called_station_id)
        .values("organization_id", "clean_called_station_id")
        .annotate(
            input_total=Coalesce(Sum("input_octets"), 0),
            output_total=Coalesce(Sum("output_octets"), 0),
        )
    )
    if include_open:
        open_sessions = Q(stop_time__isnull=True)
        totals = totals.annotate(
            open_input=Coalesce(Sum("input_octets", filter=open_sessions), 0),
            open_output=Coalesce(Sum("output_octets", filter=open_sessions), 0),
        )
    return totals.iterator()


def _traffic_delta(group, previous, current):
    """Clamp decreases to zero so charts never show negative traffic."""
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


def _recover_baseline(organization_id, called_station_id, since=None):
    """Recover the group's latest checkpoint from InfluxDB.

    Session points share this measurement but have no baseline fields.
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
        since=since,
    )
    if not points:
        return None
    # InfluxDB applies LIMIT 1 per series. A device that moved can have
    # checkpoints in more than one series.
    latest = max(points, key=lambda point: point["time"])
    return latest["baseline_input"], latest["baseline_output"]


def _load_traffic_state():
    """Load traffic state and resolve any interrupted cleanup."""
    state = cache.get(RECONCILIATION_STATE_KEY)
    if state is not None:
        cleanup = state.get("cleanup")
        if cleanup is not None:
            # A missing row confirms cleanup committed only if no other path
            # can delete the saved row.
            if RadiusAccounting.objects.filter(pk=cleanup["session"]).exists():
                del state["cleanup"]
                _save_traffic_state(state)
            else:
                _submit_cleanup_checkpoint(state, cleanup["groups"], cleanup["points"])
        return state
    # One checkpoint is enough to tell that collection has started. Recover
    # group baselines as needed. Let read errors propagate rather than reseeding.
    metric = Metric(key="radius_acc", configuration="radius_acc")
    checkpoints = metric.read(
        fields=["baseline_input", "baseline_output"],
        tags={},
        order="-time",
        limit=1,
        where=[("baseline_input", ">=", -(2**63))],
    )
    return {"active": bool(checkpoints), "groups": {}, "queued": None}


def _save_traffic_state(state):
    state["revision"] = str(uuid4())
    saved = cache.set(RECONCILIATION_STATE_KEY, state, timeout=None)
    # Some cache backends silently discard oversized values. Confirm the
    # cleanup adjustment is retrievable before deleting its accounting rows.
    # Compare a revision because queued, unsaved metrics do not compare equal
    # after the cache serializes and reconstructs them.
    stored = cache.get(RECONCILIATION_STATE_KEY)
    if saved is False or stored is None or stored.get("revision") != state["revision"]:
        raise RuntimeError(_("Could not save RADIUS traffic state."))


def _submit_traffic(state, points):
    # If queue submission fails, retry the same points at the same timestamps.
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
    """Collect traffic from open and closed sessions by organization and device.

    Seed baselines on the first run without reporting earlier traffic.
    """
    with _reconciliation_lock() as acquired:
        if not acquired:
            return False
        state = _load_traffic_state()
        # If the SQL query fails, leave pending writes queued for the next run.
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
            # Refresh the checkpoint even with no sessions. If the cache is
            # lost and the old checkpoint expires, the next run would seed
            # rather than count the first session's traffic.
            _submit_traffic(state, [_activation_point(timezone.now())])
        retiring = state.get("retiring", {})
        for group, timestamp in list(retiring.items()):
            if group in totals:
                del retiring[group]
            elif _recover_baseline(*group, since=timestamp) == (0, 0):
                # Queue acceptance is not persistence. Keep the cached zero
                # until recovery can no longer return the old negative baseline.
                state["groups"].pop(group, None)
                del retiring[group]
        groups_to_reconcile = set(totals)
        groups_to_reconcile.update(state["groups"])
        groups_to_reconcile.difference_update(retiring)
        groups_to_reconcile.discard(("__all__", ""))
        remaining_groups = iter(groups_to_reconcile)
        # Batch submissions to limit payload size and avoid a separate task
        # and full baseline cache write for every group.
        while True:
            batch = list(islice(remaining_groups, 1000))
            if not batch:
                break
            points = []
            observed = {}
            absent = {}
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
                # Validate every point before advancing any baseline in the batch.
                metric.write(**write_options, write=False)
                observed[group] = current
                points.append((metric, write_options))
                if group not in totals:
                    absent[group] = write_options["time"]
            state["groups"].update(observed)
            retiring.update(absent)
            if retiring:
                state["retiring"] = retiring
            _submit_traffic(state, points)
        if not retiring:
            state.pop("retiring", None)
        state["active"] = True
        _save_traffic_state(state)
        return True


def coordinate_accounting_cleanup(sender, queryset, **kwargs):
    return _prepare_accounting_cleanup(queryset)


def _submit_cleanup_checkpoint(state, adjusted_totals, points):
    state["groups"].update(adjusted_totals)
    # Rows can return and expire between observations. Their cleanup adjustment
    # must be collected even if the previous zero checkpoint is already stored.
    retiring = state.get("retiring", {})
    for group in adjusted_totals:
        retiring.pop(group, None)
    state.pop("cleanup", None)
    _submit_traffic(state, points)


def initialize_traffic(queryset):
    """Report open-session traffic when upgrading to scheduled collection.

    Seed baselines for all sessions in that snapshot. The old collector
    was responsible for reporting traffic from closed sessions.
    """
    snapshot_time = timezone.now()
    groups = {}
    submitted_input = submitted_output = 0
    try:
        with _reconciliation_lock() as acquired:
            if not acquired:
                raise RuntimeError(
                    _("RADIUS traffic reconciliation or cleanup is running.")
                )
            snapshot_time = timezone.now()
            logger.info("Taking RADIUS traffic cutover snapshot at %s", snapshot_time)
            # Sessions that close between the legacy queue drain and this
            # snapshot can be missed. Already reported sessions that reopen
            # before the snapshot can count twice.
            rows = _accounting_totals(queryset, include_open=True)
            while batch := list(islice(rows, 100)):
                points = []
                for row in batch:
                    group = (
                        str(row["organization_id"]),
                        row["clean_called_station_id"],
                    )
                    total = (row["input_total"], row["output_total"])
                    opening_traffic = (row["open_input"], row["open_output"])
                    groups[group] = total
                    points.append(
                        _traffic_point(
                            group, total, opening_traffic, snapshot_time, check=False
                        )
                    )
                # Monitoring can submit part of a batch before raising. Keep
                # cutover writes out of the scheduled collector's retry queue.
                Metric.batch_write(points)
                submitted_input += sum(row["open_input"] for row in batch)
                submitted_output += sum(row["open_output"] for row in batch)
            if groups:
                _save_traffic_state({"active": True, "groups": groups, "queued": None})
            else:
                # Persist activation even without sessions so the first hourly
                # run counts traffic that arrived after this cutover.
                Metric.batch_write([_activation_point(snapshot_time)])
                _save_traffic_state({"active": True, "groups": {}, "queued": None})
    except Exception:
        logger.exception(
            "RADIUS traffic cutover at %s failed after submitting %s input and %s "
            "output octets in successful batches. Other points may have been "
            "submitted. Do not retry with a fresh snapshot without checking.",
            snapshot_time,
            submitted_input,
            submitted_output,
        )
        raise
    logger.info(
        "RADIUS traffic cutover at %s submitted %s input and %s output octets "
        "across %s groups. Submission does not confirm persistence.",
        snapshot_time,
        submitted_input,
        submitted_output,
        len(groups),
    )


def _ensure_device_charts(metric):
    if not metric.object_id:
        return
    existing = set(metric.chart_set.values_list("configuration", flat=True))
    # A validation failure can leave a saved metric with only some charts.
    # Retry only the missing charts rather than relying on metric creation.
    for configuration in metric.config_dict["charts"]:
        if configuration not in existing:
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()


def _activation_point(timestamp):
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
        "time": timestamp,
        "extra_values": {
            "output_octets": 0,
            "baseline_input": 0,
            "baseline_output": 0,
        },
    }
    metric.write(**options, write=False)
    return metric, options
