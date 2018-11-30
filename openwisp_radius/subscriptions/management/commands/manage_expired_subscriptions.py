from django.core.management.base import BaseCommand

from ...utils import manage_expired_subscriptions


class Command(BaseCommand):
    help = "Manages expired subscriptions"

    def handle(self, *args, **options):
        manage_expired_subscriptions()
