import sys
from openwisp_users.models import Organization


class BatchAddMixin(object):
    def add_arguments(self, parser):
        super(BatchAddMixin, self).add_arguments(parser)
        parser.add_argument('--organization',
                            action='store',
                            help='Organization the users belong to')

    def _create_batch(self, **options):
        org_name = options['organization']
        try:
            org = Organization.objects.get(name=org_name)
        except Organization.DoesNotExist:
            sys.stdout.write("Incorrect organization name provided\n")
            sys.exit(1)
        batch = super(BatchAddMixin, self)._create_batch(**options)
        batch.organization = org
        return batch 
