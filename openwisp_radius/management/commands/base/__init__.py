import sys

import swapper
from django.core.exceptions import ValidationError
from django.core.management import CommandError
from django.utils.translation import gettext_lazy as _

Organization = swapper.load_model("openwisp_users", "Organization")
RadiusGroup = swapper.load_model("openwisp_radius", "RadiusGroup")


class BatchAddMixin(object):
    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--organization", action="store", help=_("Organization the users belong to")
        )
        parser.add_argument(
            "--group",
            action="store",
            default=None,
            help=_("RADIUS group for the users"),
        )
        parser.add_argument(
            "--notes",
            action="store",
            default="",
            help=_("Internal notes for the batch"),
        )

    def _create_batch(self, **options):
        slug = options["organization"]
        try:
            org = Organization.objects.get(slug=slug)
        except Organization.DoesNotExist:
            sys.stdout.write("The organization supplied was not found\n")
            sys.exit(1)
        batch = super()._create_batch(**options)
        batch.organization = org
        batch.notes = options["notes"]
        if options["group"]:
            try:
                batch.group = RadiusGroup.objects.get(
                    pk=options["group"], organization=org
                )
            except (RadiusGroup.DoesNotExist, ValidationError, ValueError):
                raise CommandError(_("The RADIUS group supplied was not found"))
        return batch
