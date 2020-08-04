import sys
from datetime import datetime

from django.core.management import BaseCommand

from ....settings import BATCH_DEFAULT_PASSWORD_LENGTH
from ....utils import generate_pdf, load_model

RadiusBatch = load_model('RadiusBatch')


class BasePrefixAddUsersCommand(BaseCommand):
    help = 'Generate a batch of users with usernames starting with a prefix'

    def add_arguments(self, parser):
        parser.add_argument(
            '--name', action='store', help='Name of the event of batch addition'
        )
        parser.add_argument(
            '--prefix', action='store', help='Will generate users using this prefix'
        )
        parser.add_argument(
            '--output',
            action='store',
            default=None,
            help='Location of the output PDF file (example: /home/user/my_output.pdf)',
        )
        parser.add_argument(
            '--n', action='store', help='Number of users to be generated', type=int
        )
        parser.add_argument(
            '--expiration',
            action='store',
            default=None,
            help='Will deactivate users after this date',
        )
        parser.add_argument(
            '--password-length',
            action='store',
            default=BATCH_DEFAULT_PASSWORD_LENGTH,
            type=int,
        )

    def handle(self, *args, **options):
        prefix = options['prefix']
        expiration_date = options['expiration']
        number_of_users = options['n']
        if expiration_date:
            expiration_date = datetime.strptime(expiration_date, '%d-%m-%Y')
        if number_of_users < 1:
            self.stdout.write(
                'The number of users to be generated should be '
                'greater than or equal to 1'
            )
            sys.exit(1)
        batch = self._create_batch(**options)
        batch.expiration_date = expiration_date
        batch.full_clean()
        batch.save()
        batch.prefix_add(prefix, number_of_users, options['password_length'])
        if options['output']:
            pdf = generate_pdf(batch.pk)
            with open(options['output'], 'wb') as file:
                file.write(pdf)
        self.stdout.write(f'Generated a batch of users with prefix {prefix}')

    def _create_batch(self, **options):
        batch = RadiusBatch(
            name=options['name'], strategy='prefix', prefix=options['prefix']
        )
        return batch
