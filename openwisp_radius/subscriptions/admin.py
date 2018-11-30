from django.contrib import admin
from django.forms.models import BaseInlineFormSet
from django.urls import reverse
from django_freeradius.base.admin import ReadOnlyAdmin
from plans.admin import OrderAdmin, PlanAdmin, PlanPricingInline
from plans.models import BillingInfo, Invoice, Pricing, Quota, UserPlan

from openwisp_users.admin import UserAdmin
from openwisp_utils.admin import MultitenantAdminMixin

from . import settings as app_settings
from .models import Payment

BasePayment = ReadOnlyAdmin if not app_settings.PAYMENT_ADMIN_EDITABLE else admin.ModelAdmin


@admin.register(Payment)
class PaymentAdmin(MultitenantAdminMixin, BasePayment):
    list_display = ('id', 'status',
                    'currency', 'total', 'tax',
                    'created', 'modified')
    list_filter = ('organization', 'status')
    fields = ('organization',
              'variant',
              'order',
              'status',
              'transaction_id',
              'currency',
              'total',
              'delivery',
              'tax',
              'captured_amount',
              'description',
              'message',
              'customer_ip_address',
              'extra_data',
              'token',
              'created',
              'modified')
    readonly_fields = ('created', 'modified')

    class Media:
        css = {'all': ('subscriptions/css/payment.css',)}


class UserPlanInline(admin.StackedInline):
    model = UserPlan


class BillingInfoInline(admin.StackedInline):
    model = BillingInfo
    fields = ('name',
              'street',
              'zipcode',
              'city',
              'country',
              'tax_number')


UserAdmin.inlines += [UserPlanInline, BillingInfoInline]
PlanPricingInline.extra = 0
PlanAdmin.inlines = (PlanPricingInline,)
PlanAdmin.readonly_fields = ('created',)
PlanAdmin.exclude = ('customized', 'url')


class PricingAdmin(admin.ModelAdmin):
    model = Pricing
    exclude = ('url', )


class InvoiceInlineFormSet(BaseInlineFormSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        invoice_type = self.model.INVOICE_TYPES.INVOICE
        self.queryset = self.model.objects.filter(type=invoice_type)


class InvoiceInline(admin.StackedInline):
    model = Invoice
    formset = InvoiceInlineFormSet
    extra = 0
    exclude = ('rebate',
               'shipping_name',
               'shipping_street',
               'shipping_zipcode',
               'shipping_city',
               'shipping_country',
               'require_shipment',)

    def get_readonly_fields(self, request, obj):
        if obj:
            return [f.name for f in Invoice._meta.get_fields() if f.name not in self.exclude]
        return tuple()

    def view_on_site(self, obj):
        return reverse('subscriptions:download_invoice', args=[obj.pk])


def order_get_readonly_fields(self, request, obj):
    if obj:
        return self.fields
    return tuple()


OrderAdmin.get_readonly_fields = order_get_readonly_fields
OrderAdmin.inlines = (InvoiceInline,)
OrderAdmin.fields = ('user',
                     'status',
                     'plan',
                     'pricing',
                     'amount',
                     'tax',
                     'currency',
                     'created',
                     'completed')
OrderAdmin.list_display = (
    'user', 'plan', 'pricing',
    'status', 'created', 'completed',
)
OrderAdmin.list_display_links = OrderAdmin.list_display
PricingAdmin.exclude = ('url',)


admin.site.unregister(BillingInfo)
admin.site.unregister(Quota)
admin.site.unregister(UserPlan)
admin.site.unregister(Invoice)
admin.site.unregister(Pricing)
admin.site.register(Pricing, PricingAdmin)
