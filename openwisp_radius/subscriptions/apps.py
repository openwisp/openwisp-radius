from django.apps import AppConfig
from django.db.models.signals import post_save, pre_save
from payments.signals import status_changed


class SubscriptionsConfig(AppConfig):
    name = 'openwisp_radius.subscriptions'

    def ready(self):
        self.connect_signals()

    def connect_signals(self):
        from .models import Payment
        from .receivers import (auto_radius_groups_on_plan_creation,
                                auto_radius_groups_on_org_creation,
                                auto_rename_radius_groups)
        from plans.models import PlanPricing, Plan
        from openwisp_users.models import Organization
        status_changed.connect(Payment.payment_status_changed)
        post_save.connect(auto_radius_groups_on_plan_creation,
                          sender=PlanPricing)
        post_save.connect(auto_radius_groups_on_org_creation,
                          sender=Organization)
        pre_save.connect(auto_rename_radius_groups,
                         sender=Plan)
