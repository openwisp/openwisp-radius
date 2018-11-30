import uuid
from datetime import date, timedelta
from io import BytesIO

from django.conf import settings
from django.db import models
from django.template.loader import get_template
from django.utils import translation
from django.utils.text import slugify
from django.utils.timezone import now
from payments import PurchasedItem
from payments.models import BasePayment, PaymentStatus
from plans.contrib import get_user_language
from plans.models import Invoice, Order
from plans.signals import order_completed
from xhtml2pdf import pisa

from openwisp_users.mixins import OrgMixin

from . import settings as app_settings
from .mail import send_template_email


class Payment(BasePayment, OrgMixin):
    id = models.UUIDField(primary_key=True,
                          default=uuid.uuid4,
                          editable=False)
    variant = models.CharField(max_length=255,
                               default='default',
                               choices=app_settings.PAYMENT_VARIANT_CHOICES)
    order = models.ForeignKey('plans.Order',
                              on_delete=models.CASCADE)

    class Meta:
        app_label = 'plans'

    @property
    def plan_slug(self):
        if not self.order:
            return None
        return slugify(self.order.plan.name)

    @classmethod
    def payment_status_changed(cls, instance, **kwargs):
        if instance.status == PaymentStatus.CONFIRMED:
            user = instance.order.user
            days = instance.order.pricing.period
            user.userplan.expire = date.today() + timedelta(days=days)
            user.userplan.active = True
            user.userplan.save()
            # complete order (skip django-plans logic)
            order = instance.order
            order.completed = now()
            order.status = Order.STATUS.COMPLETED
            order.full_clean()
            order.save()
            order_completed.send(order)
            org = instance.organization
            from .utils import (get_or_create_paid_plan_radius_group,
                                get_or_create_temporary_radius_group)
            paid_group = get_or_create_paid_plan_radius_group(org, user.userplan.plan)
            temp_group = get_or_create_temporary_radius_group(org)
            RadiusUserGroup = user.radiususergroup_set.model
            try:
                rug = user.radiususergroup_set.get(group=temp_group)
            except RadiusUserGroup.DoesNotExist:
                user.radiususergroup_set.all().delete()
                RadiusUserGroup.objects.create(user=user, group=paid_group)
            else:
                rug.group = paid_group
                rug.full_clean()
                rug.save()

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


def send_invoice_by_email(self):
    if self.type != self.INVOICE_TYPES.INVOICE:
        return
    language_code = get_user_language(self.user)
    if language_code is not None:
        translation.activate(language_code)
    mail_context = {'user': self.user,
                    'invoice_type': self.get_type_display(),
                    'invoice_number': self.get_full_number(),
                    'order': self.order.id}
    if language_code is not None:
        translation.deactivate()
    attachments = [
        [self.get_invoice_pdf_filename(),
         self.generate_invoice_pdf().getvalue(),
         'application/pdf']
    ]
    send_template_email([self.user.email],
                        'mail/invoice_created_title.txt',
                        'mail/invoice_created_body.txt',
                        mail_context,
                        language_code,
                        attachments=attachments)


def get_invoice_pdf_filename(self):
    return 'invoice-{}.pdf'.format(self.full_number.replace('/', '-'))


def generate_invoice_pdf(self):
    template_path = 'invoice.html'
    context = {
        'logo_url': getattr(settings, 'PLANS_INVOICE_LOGO_URL', None),
        'invoice': self,
        'pdf': True
    }
    template = get_template(template_path)
    html = template.render(context)
    stream = BytesIO()
    pisa.CreatePDF(html, dest=stream)
    return stream


Invoice.send_invoice_by_email = send_invoice_by_email
Invoice.generate_invoice_pdf = generate_invoice_pdf
Invoice.get_invoice_pdf_filename = get_invoice_pdf_filename
