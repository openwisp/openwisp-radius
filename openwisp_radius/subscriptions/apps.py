from django.apps import AppConfig
from payments.signals import status_changed


class SubscriptionsConfig(AppConfig):
    name = 'openwisp_radius.subscriptions'

    def ready(self):
        from .models import Payment
        status_changed.connect(Payment.payment_status_changed)
