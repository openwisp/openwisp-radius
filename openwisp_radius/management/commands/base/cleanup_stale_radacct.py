from datetime import timedelta

from django.core.management import BaseCommand
from django.utils.timezone import now

from ....utils import load_model

RadiusAccounting = load_model('RadiusAccounting')


class BaseCleanupRadacctCommand(BaseCommand):
    help = 'Closes active accounting sessions older than <days>'

    def add_arguments(self, parser):
        parser.add_argument('number_of_days', type=int, nargs='?', default=15)

    def handle(self, *args, **options):
        days = now() - timedelta(days=options['number_of_days'])
        sessions = RadiusAccounting.objects.filter(start_time__lt=days, stop_time=None)
        for session in sessions:
            # calculate seconds in between two dates
            session.session_time = (now() - session.start_time).total_seconds()
            session.stop_time = now()
            session.update_time = session.stop_time
            session.save()
        self.stdout.write(
            f'Closed active sessions older than {options["number_of_days"]} days'
        )
