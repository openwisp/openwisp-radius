from contextlib import ExitStack
from datetime import timedelta

from django.core.management import BaseCommand
from django.db import transaction
from django.utils.timezone import now

from .... import settings as app_settings
from ....signals import radius_accounting_cleanup
from ....utils import load_model

RadiusAccounting = load_model("RadiusAccounting")


class BaseDeleteOldRadacctCommand(BaseCommand):
    help = "Delete accounting sessions older than <days>"

    def add_arguments(self, parser):
        parser.add_argument("number_of_days", type=int, nargs="?")

    def handle(self, *args, **options):
        number_of_days = options["number_of_days"]
        if number_of_days is None:
            number_of_days = app_settings.ACCOUNTING_RETENTION_DAYS
        if not number_of_days:
            return
        days = now() - timedelta(days=number_of_days)
        queryset = RadiusAccounting.objects.filter(stop_time__lt=days)
        # Optional integrations hold coordination locks through deletion and
        # commit callbacks so reconciliation cannot observe a partial cleanup.
        with ExitStack() as stack:
            cleanup_preparers = [
                stack.enter_context(coordination)
                for _, coordination in radius_accounting_cleanup.send(
                    sender=RadiusAccounting, queryset=queryset
                )
            ]
            # Own the commit so an outer transaction cannot delay callbacks
            # until after the integration coordination locks are released.
            with transaction.atomic(durable=bool(cleanup_preparers)):
                # Sessions past retention (normally months or a year) are assumed
                # to receive no more accounting updates. Aggregate and delete the
                # queryset directly, without loading all IDs or locking rows.
                after_commit_callbacks = [
                    prepare_cleanup(queryset) for prepare_cleanup in cleanup_preparers
                ]
                queryset.delete()
                for callback in after_commit_callbacks:
                    transaction.on_commit(callback)
        self.stdout.write(f"Deleted sessions older than {number_of_days} days")
