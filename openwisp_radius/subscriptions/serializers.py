from django.utils.translation import ugettext_lazy as _
from plans.models import BillingInfo, PlanPricing, UserPlan
from rest_auth.registration.serializers import RegisterSerializer as BaseRegisterSerializer
from rest_auth.serializers import TokenSerializer as BaseTokenSerializer
from rest_framework import serializers
from rest_framework.reverse import reverse

from openwisp_radius.utils import load_model

from . import settings as app_settings
from .utils import create_order, get_or_create_temporary_radius_group

RadiusGroup = load_model('RadiusGroup')
RadiusUserGroup = load_model('RadiusUserGroup')


class TokenSerializer(BaseTokenSerializer):
    payment_url = serializers.SerializerMethodField()

    class Meta(BaseTokenSerializer.Meta):
        pass

    Meta.fields = Meta.fields + ('payment_url',)

    def get_payment_url(self, obj):
        view = self.context['view']
        if not hasattr(view, 'payment'):
            return
        return reverse('subscriptions:process_payment',
                       args=[view.payment.pk],
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
        group = get_or_create_temporary_radius_group(organization)
        rug = RadiusUserGroup(user=user,
                              group=group)
        rug.full_clean()
        rug.save()
        # billing info
        billing_info_data = self.validated_data['billing_info']
        billing_info_data['user'] = user
        billing_info = BillingInfo(**billing_info_data)
        billing_info.full_clean()
        billing_info.save()
        payment = create_order(user,
                               plan_pricing,
                               self.context['request'].META['REMOTE_ADDR'],
                               organization)
        # will be used in TokenSerializer.get_payment_url
        self.context['view'].payment = payment


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
