"""Keep stable Celery entry points separate from metric collection logic."""

from celery import shared_task

from .metrics import accounting, registration


@shared_task
def write_user_registration_metrics():
    registration.collect()


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
    # Preserve the task payload for queued jobs. Reconciliation reports traffic;
    # closure points retain only the information needed to count unique users.
    return accounting.write_session(
        username,
        organization_id,
        0,
        0,
        calling_station_id,
        called_station_id,
        time,
    )


@shared_task
def reconcile_radius_traffic(seed=False):
    return accounting.reconcile(seed=seed)
