from datetime import timedelta

from django.core.management import BaseCommand
from django.utils.timezone import now

from ....utils import load_model

RadiusAccounting = load_model('RadiusAccounting')


class BaseDeleteOldRadacctCommand(BaseCommand):
    help = 'Delete accounting sessions older than <days>'

    def add_arguments(self, parser):
        parser.add_argument('number_of_days', type=int)

    def handle(self, *args, **options):
        if options['number_of_days']:
            days = now() - timedelta(days=options['number_of_days'])
            RadiusAccounting.objects.filter(stop_time__lt=days).delete()
            self.stdout.write(
                f'Deleted sessions older than {options["number_of_days"]} days'
            )
