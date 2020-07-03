import sys

import swapper

Organization = swapper.load_model('openwisp_users', 'Organization')


class BatchAddMixin(object):
    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            '--organization', action='store', help='Organization the users belong to'
        )

    def _create_batch(self, **options):
        slug = options['organization']
        try:
            org = Organization.objects.get(slug=slug)
        except Organization.DoesNotExist:
            sys.stdout.write('The organization supplied was not found\n')
            sys.exit(1)
        batch = super()._create_batch(**options)
        batch.organization = org
        return batch
