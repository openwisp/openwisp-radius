from django.db import transaction
from django.utils import timezone

from . import tasks


def _enqueue_radiusaccounting_metric(instance):
    if instance.stop_time is None:
        return
    metric_time = instance.stop_time
    if timezone.is_naive(metric_time):
        metric_time = timezone.make_aware(metric_time)
    transaction.on_commit(
        lambda: tasks.post_save_radiusaccounting.delay(
            username=instance.username,
            organization_id=str(instance.organization_id),
            input_octets=instance.input_octets,
            output_octets=instance.output_octets,
            calling_station_id=instance.calling_station_id,
            called_station_id=instance.called_station_id,
            time=metric_time,
        )
    )


def radius_accounting_closed_handler(instance, *args, **kwargs):
    _enqueue_radiusaccounting_metric(instance)
