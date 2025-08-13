from django.core.management import BaseCommand

from ....utils import load_model

RadiusAccounting = load_model("RadiusAccounting")


class BaseCleanupRadacctCommand(BaseCommand):
    help = "Closes active accounting sessions older than <days>"

    def add_arguments(self, parser):
        parser.add_argument("number_of_days", type=int, nargs="?", default=15)
        parser.add_argument("number_of_hours", type=int, nargs="?", default=0)

    def handle(self, *args, **options):
        RadiusAccounting.close_stale_sessions(
            days=options["number_of_days"],
            # defaults to zero
            hours=options["number_of_hours"],
        )
        if options["number_of_hours"]:
            time_output = f"{options['number_of_hours']} hours"
        else:
            time_output = f"{options['number_of_days']} days"
        self.stdout.write(f"Closed active sessions older than {time_output}")
