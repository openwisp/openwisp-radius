from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management import BaseCommand
from django.utils.timezone import now

from openwisp_radius.utils import load_model

User = get_user_model()
RadiusAccounting = load_model('RadiusAccounting')


class BaseDeleteUnverifiedUsersCommand(BaseCommand):
    help = 'Delete unverified users older than <days>'

    def add_arguments(self, parser):
        parser.add_argument(
            '--older-than-days',
            action='store',
            default=1,
            help='delete unverified users which registered days before this',
        )
        parser.add_argument(
            '--exclude-methods',
            action='store',
            default='',
            help='list of registration methods to skip',
        )

    def handle(self, *args, **options):
        days = now() - timedelta(days=int(options['older_than_days']))
        exclude_methods = str(options['exclude_methods']).split(',')
        for user in (
            User.objects.filter(
                date_joined__lt=days,
                registered_user__isnull=False,
                registered_user__is_verified=False,
                is_staff=False,
            )
            .exclude(registered_user__method__in=exclude_methods)
            .iterator()
        ):
            if not RadiusAccounting.objects.filter(username=user.username).exists():
                user.delete()

        self.stdout.write(
            'Deleted unverified accounts older than '
            f'{options["older_than_days"]} day(s) with registration method '
            f'other than {options["exclude_methods"]}'
        )
