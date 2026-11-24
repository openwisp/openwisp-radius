from datetime import timedelta

from django.core.management import BaseCommand
from django.utils.timezone import now

from .... import settings as app_settings
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
        if number_of_days:
            days = now() - timedelta(days=number_of_days)
            RadiusAccounting.objects.filter(stop_time__lt=days).delete()
            self.stdout.write(f"Deleted sessions older than {number_of_days} days")
