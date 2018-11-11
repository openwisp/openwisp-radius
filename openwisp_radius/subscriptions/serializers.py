from django.utils.translation import ugettext_lazy as _
from payments import PaymentStatus
from plans.models import BillingInfo, Order, PlanPricing, UserPlan
from rest_auth.registration.serializers import RegisterSerializer as BaseRegisterSerializer
from rest_auth.serializers import TokenSerializer as BaseTokenSerializer
from rest_framework import serializers
from rest_framework.reverse import reverse

from openwisp_radius.models import RadiusGroup, RadiusUserGroup

from . import settings as app_settings

from .models import Payment


class TokenSerializer(BaseTokenSerializer):
    payment_url = serializers.SerializerMethodField()

    class Meta(BaseTokenSerializer.Meta):
        pass

    Meta.fields = Meta.fields + ('payment_url',)

    def get_payment_url(self, obj):
        order = obj.user.order_set.filter(status=Order.STATUS.NEW) \
                                  .first()  # default ordering is created DESC
        if not order:
            return None
        payment = order.payment_set.filter(status=PaymentStatus.WAITING) \
                                   .order_by('-created') \
                                   .first()
        return reverse('process_payment',
                       args=[payment.pk],
                       request=self.context['request'])


class BillingInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = BillingInfo
        fields = ('name',
                  'street',
                  'city',
                  'zipcode',
                  'country',
                  'tax_number')


def get_plan_pricing_queryset():
    return PlanPricing.objects.select_related('plan', 'pricing') \
                              .filter(plan__available=True,
                                      plan__visible=True)


class RegisterSerializer(BaseRegisterSerializer):
    plan_pricing = serializers.PrimaryKeyRelatedField(
        write_only=True,
        queryset=get_plan_pricing_queryset()
    )
    billing_info = BillingInfoSerializer(many=False,
                                         required=False,
                                         allow_null=True)

    def validate(self, data):
        plan_pricing = data['plan_pricing']
        if not self._is_free(plan_pricing) and 'billing_info' not in data:
            raise serializers.ValidationError({
                'billing_info': _('paid plans require billing information')
            })
        return data

    def _is_free(self, plan_pricing):
        return not plan_pricing or plan_pricing.price <= 0

    def custom_signup(self, request, user):
        plan_pricing = self.validated_data['plan_pricing']
        UserPlan.objects.filter(user=user).delete()
        userplan = UserPlan(user=user,
                            plan=plan_pricing.plan,
                            active=False)
        if self._is_free(plan_pricing):
            userplan.active = True
        else:
            self._create_premium_subscription(user, plan_pricing)
        # save user plan
        userplan.full_clean()
        userplan.save()

    def _create_premium_subscription(self, user, plan_pricing):
        user.radiususergroup_set.all().delete()
        organization = self.context['view'].organization
        group_name = '{}-temporary'.format(organization.slug)
        try:
            group = RadiusGroup.objects.get(name=group_name)
        except RadiusGroup.DoesNotExist as e:
            # TODO: log
            raise e
        ug = RadiusUserGroup(user=user,
                             group=group)
        ug.full_clean()
        ug.save()
        # billing info
        billing_info_data = self.validated_data['billing_info']
        billing_info_data['user'] = user
        billing_info = BillingInfo(**billing_info_data)
        billing_info.full_clean()
        billing_info.save()
        order = Order(user=user,
                      plan=plan_pricing.plan,
                      pricing=plan_pricing.pricing,
                      created=user.date_joined,
                      amount=plan_pricing.price,
                      tax=app_settings.TAX,
                      currency=app_settings.CURRENCY)
        order.full_clean()
        order.save()
        ip_address = self.context['request'].META['REMOTE_ADDR']
        payment = Payment(organization=organization,
                          order=order,
                          currency=order.currency,
                          total=order.total(),
                          tax=order.tax_total(),
                          customer_ip_address=ip_address)
        payment.full_clean()
        payment.save()


class PlanPricingSerializer(serializers.ModelSerializer):
    plan = serializers.StringRelatedField()
    pricing = serializers.StringRelatedField()
    plan_description = serializers.SerializerMethodField()
    currency = serializers.SerializerMethodField()

    def get_plan_description(self, obj):
        return obj.plan.description

    def get_currency(self, obj):
        return app_settings.CURRENCY

    class Meta:
        model = PlanPricing
        fields = '__all__'
