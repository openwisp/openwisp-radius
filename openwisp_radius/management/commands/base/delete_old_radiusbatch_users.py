from datetime import timedelta

from django.core.management import BaseCommand
from django.utils.timezone import now

from ....settings import BATCH_DELETE_EXPIRED
from ....utils import load_model

RadiusBatch = load_model('RadiusBatch')


class BaseDeleteOldRadiusBatchUsersCommand(BaseCommand):
    help = 'Deactivating users added in batches which have expired'

    def add_arguments(self, parser):
        parser.add_argument(
            '--older-than-days',
            action='store',
            default=BATCH_DELETE_EXPIRED,
            help='delete users which have expired before this time',
        )

    def handle(self, *args, **options):
        days = now() - timedelta(days=int(options['older_than_days']))
        batches = RadiusBatch.objects.filter(expiration_date__lt=days)
        for b in batches:
            b.delete()
        self.stdout.write(
            f'Deleted accounts older than {options["older_than_days"]} days'
        )
