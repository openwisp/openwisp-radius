"""Seed hourly traffic baselines during the operator-managed cutover."""

from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import gettext_lazy as _

from ...tasks import reconcile_radius_traffic


class Command(BaseCommand):
    help = _("Seed retained accounting totals without reporting historical traffic.")

    def handle(self, *args, **options):
        if not reconcile_radius_traffic(seed=True):
            raise CommandError(
                _("RADIUS traffic reconciliation is running; retry seeding.")
            )
        self.stdout.write(_("RADIUS traffic baselines initialized."))
