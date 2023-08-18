from django.db import transaction

from . import tasks


def post_save_registereduser(instance, created, *args, **kwargs):
    if not created:
        return
    transaction.on_commit(
        lambda: tasks.post_save_registereduser.delay(
            user_id=str(instance.user_id), registration_method=instance.method
        )
    )


def post_save_organizationuser(instance, created, *args, **kwargs):
    if not created:
        return
    transaction.on_commit(
        lambda: tasks.post_save_organizationuser.delay(
            user_id=str(instance.user_id), organization_id=str(instance.organization_id)
        )
    )


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
