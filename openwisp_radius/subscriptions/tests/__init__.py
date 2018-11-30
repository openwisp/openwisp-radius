import json
from datetime import datetime
from payments import PaymentStatus
from plans.models import Plan, PlanPricing, Pricing

from openwisp_radius.utils import load_model

from openwisp_users.models import Organization
from ..models import Payment
from django.urls import reverse

RadiusGroup = load_model('RadiusGroup')


class CreatePlansMixin(object):
    def setUp(self):
        Plan.objects.all().delete()
        RadiusGroup.objects.filter(name__endswith='temporary').delete()
        RadiusGroup.objects.filter(name__endswith='premium').delete()

    def _create_plan(self, **kwargs):
        opts = {'name': 'test-plan',
                'available': True,
                'visible': True,
                'created': datetime.now()}
        opts.update(kwargs)
        p = Plan(**opts)
        p.full_clean()
        p.save()
        return p

    def _create_pricing(self, **kwargs):
        opts = {'name': 'yearly',
                'period': 365}
        opts.update(kwargs)
        p = Pricing(**opts)
        p.full_clean()
        p.save()
        return p

    def _create_planpricing(self, **kwargs):
        p = PlanPricing(**kwargs)
        p.full_clean()
        p.save()
        return p

    def _create_free_plan(self):
        plan = self._create_plan(name='free')
        pricing = self._create_pricing()
        plan_pricing = self._create_planpricing(plan=plan,
                                                pricing=pricing,
                                                price='0.00')
        return plan_pricing

    def _create_premium_plan(self, name='premium', price='9.99'):
        plan = self._create_plan(name=name)
        pricing = self._create_pricing()
        plan_pricing = self._create_planpricing(plan=plan,
                                                pricing=pricing,
                                                price=price)
        return plan_pricing

    # API methods

    def _register_premium(self, plan_pricing=None):
        if not plan_pricing:
            plan_pricing = self._create_premium_plan()
        params = {
            'username': 'test@test.com',
            'email': 'test@test.com',
            'password1': 'tester123',
            'password2': 'tester123',
            'plan_pricing': plan_pricing.pk,
            'billing_info': {
                'tax_number': 'EE123456789',
                'name': 'Joe Boe',
                'street': 'Test street 123',
                'city': 'Tallinn',
                'zipcode': '00071',
                'country': 'EE'
            }
        }
        r = self.client.post(self.get_register_url(),
                             json.dumps(params),
                             content_type='application/json')
        return r, params, plan_pricing.plan

    def _pay_premium_user(self):
        payment = Payment.objects.first()
        payment.change_status(PaymentStatus.CONFIRMED)
        return payment

    def get_register_url(self, organization=None):
        if not organization:
            org = Organization.objects.first()
        return reverse('freeradius:rest_register', args=[org.slug])
