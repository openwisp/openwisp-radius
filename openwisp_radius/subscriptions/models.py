import uuid

from django.db import models
from django.utils.text import slugify
from payments import PurchasedItem
from payments.models import BasePayment, PaymentStatus

from openwisp_users.mixins import OrgMixin

from . import settings as app_settings
from ..models import RadiusGroup, RadiusUserGroup


class Payment(BasePayment, OrgMixin):
    id = models.UUIDField(primary_key=True,
                          default=uuid.uuid4,
                          editable=False)
    variant = models.CharField(max_length=255,
                               default='default',
                               choices=app_settings.PAYMENT_VARIANT_CHOICES)
    order = models.ForeignKey('plans.Order',
                              on_delete=models.CASCADE)

    @property
    def plan_slug(self):
        if not self.order:
            return None
        return slugify(self.order.plan.name)

    @classmethod
    def payment_status_changed(cls, instance, **kwargs):
        if instance.status == PaymentStatus.CONFIRMED:
            instance.order.complete_order()
            user = instance.order.user
            user.is_active = True
            user.save()
            org = instance.organization
            group_name = '{}-{}'.format(org.slug, slugify(instance.order.plan.name))
            try:
                group = RadiusGroup.objects.get(organization=org,
                                                name=group_name)
            except RadiusGroup.DoesNotExist:
                # TODO: Che famo quà??
                pass
            user.radiususergroup_set.all().delete()
            RadiusUserGroup.objects.create(user=user, group=group)

    def get_success_url(self):
        return app_settings.PAYMENT_SUCCESS_URL

    def get_failure_url(self):
        return app_settings.PAYMENT_FAILURE_URL

    def get_purchased_items(self):
        order = self.order
        yield PurchasedItem(name=str(order.plan),
                            sku=str(order.plan.id),
                            quantity=1,
                            price=order.amount,
                            currency=order.currency)
