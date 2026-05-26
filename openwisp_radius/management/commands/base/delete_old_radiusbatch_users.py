from datetime import timedelta

from django.core.management import BaseCommand
from django.utils.timezone import now

from ....settings import BATCH_DELETE_EXPIRED
from ....utils import load_model

RadiusBatch = load_model("RadiusBatch")


class BaseDeleteOldRadiusBatchUsersCommand(BaseCommand):
    help = "Deletes users added in batches which have expired"

    def add_arguments(self, parser):
        parser.add_argument(
            "--older-than-days",
            action="store",
            type=int,
            help="Delete RADIUS batch users that are older than days provided",
        )
        parser.add_argument(
            "--older-than-months",
            action="store",
            type=int,
            help="Delete RADIUS batch users that are older than months provided",
        )

    def handle(self, *args, **options):
        if options.get("older_than_days"):
            days = options["older_than_days"]
        elif options.get("older_than_months"):
            days = 30 * options["older_than_months"]
        else:
            days = BATCH_DELETE_EXPIRED
        threshold_date = (now() - timedelta(days=days)).date()
        batches = RadiusBatch.objects.filter(expiration_date__lt=threshold_date)
        for batch in batches.iterator():
            # Delete only users whose own expiration is older than the threshold,
            # then remove empty batches that no longer reference any users.
            expired_users = batch.users.filter(
                expiration_date__isnull=False,
                expiration_date__lt=threshold_date,
            )
            expired_users.delete()
            if not batch.users.exists():
                batch.delete()
        time_period = threshold_date.strftime("%Y-%m-%d %H:%M:%S")
        self.stdout.write(f"Deleted accounts older than {time_period}")
