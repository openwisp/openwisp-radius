from django.db import transaction

from . import tasks


def post_save_radiusaccounting(instance, *args, **kwargs):
    if instance.stop_time is None:
        return
    transaction.on_commit(
        lambda: tasks.post_save_radiusaccounting.delay(
            username=instance.username,
            organization_id=str(instance.organization_id),
            input_octets=instance.input_octets,
            output_octets=instance.output_octets,
            calling_station_id=instance.calling_station_id,
            called_station_id=instance.called_station_id,
        )
    )
