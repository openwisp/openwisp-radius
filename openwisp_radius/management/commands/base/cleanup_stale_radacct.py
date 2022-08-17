from django.core.management import BaseCommand

from ....utils import load_model

RadiusAccounting = load_model('RadiusAccounting')


class BaseCleanupRadacctCommand(BaseCommand):
    help = 'Closes active accounting sessions older than <days>'

    def add_arguments(self, parser):
        parser.add_argument('number_of_days', type=int, nargs='?', default=15)

    def handle(self, *args, **options):
        RadiusAccounting.close_stale_sessions(days=options['number_of_days'])
        self.stdout.write(
            f'Closed active sessions older than {options["number_of_days"]} days'
        )
