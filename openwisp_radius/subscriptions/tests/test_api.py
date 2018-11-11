import json
from datetime import datetime

from django.urls import reverse
from payments import PaymentStatus
from plans.models import BillingInfo, Invoice, Order, Plan, PlanPricing, Pricing

from openwisp_radius.models import RadiusGroup
from openwisp_radius.tests.tests import BaseTestCase
from openwisp_users.models import Organization, User

from .. import settings as app_settings

from ..models import Payment


class TestApi(BaseTestCase):
    def setUp(self):
        # TODO: move this to datamigration
        g = RadiusGroup(name='default-temporary',
                        organization=Organization.objects.first())
        g.full_clean()
        g.save()
        p = RadiusGroup(name='default-premium',
                        organization=Organization.objects.first())
        p.full_clean()
        p.save()

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

    def _create_premium_plan(self):
        plan = self._create_plan(name='premium')
        pricing = self._create_pricing()
        plan_pricing = self._create_planpricing(plan=plan,
                                                pricing=pricing,
                                                price='9.99')

        return plan_pricing

    def get_register_url(self, organization=None):
        if not organization:
            org = Organization.objects.first()
        return reverse('freeradius:rest_register', args=[org.slug])

    def test_register_free(self):
        plan = self._create_plan(name='free')
        pricing = self._create_pricing()
        plan_pricing = self._create_planpricing(plan=plan,
                                                pricing=pricing,
                                                price='0.00')
        plan_pricing = self._create_free_plan()
        params = {'username': 'test@test.com',
                  'email': 'test@test.com',
                  'password1': 'tester123',
                  'password2': 'tester123',
                  'plan_pricing': plan_pricing.pk}
        r = self.client.post(self.get_register_url(),
                             json.dumps(params),
                             content_type='application/json')
        self.assertEqual(r.status_code, 201)
        self.assertIn('key', r.data)
        self.assertIn('payment_url', r.data)
        self.assertIsNone(r.data['payment_url'])
        user = User.objects.get(username=params['username'])
        self.assertTrue(user.is_active)
        self.assertTrue(hasattr(user, 'userplan'))
        self.assertEqual(user.userplan.plan, plan_pricing.plan)
        ug = user.radiususergroup_set.first()
        self.assertIsNotNone(ug)
        self.assertEqual(ug.group.name, 'default-users')

    def _register_premium(self):
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

    def test_register_premium(self):
        r, params, plan = self._register_premium()
        self.assertEqual(r.status_code, 201)
        user = User.objects.get(username=params['username'])
        self.assertTrue(user.is_active)
        self.assertTrue(hasattr(user, 'userplan'))
        self.assertEqual(user.userplan.plan, plan)
        ug = user.radiususergroup_set.first()
        self.assertIsNotNone(ug)
        self.assertEqual(ug.group.name, 'default-temporary')
        bi = BillingInfo.objects.first()
        self.assertIsNotNone(bi)
        self.assertEqual(bi.user, user)
        bi_params = set(params['billing_info'].items())
        bi_dict = set(bi.__dict__.items())
        self.assertTrue(bi_params.issubset(bi_dict))
        inv = Invoice.objects.first()
        self.assertIsNotNone(inv)
        payment = Payment.objects.first()
        self.assertIsNotNone(payment)
        self.assertIn('key', r.data)
        self.assertIn('payment_url', r.data)
        self.assertIn(str(payment.pk), r.data['payment_url'])

    def test_register_premium_400_billing_null(self):
        plan_pricing = self._create_premium_plan()
        params = {'username': 'test@test.com',
                  'email': 'test@test.com',
                  'password1': 'tester123',
                  'password2': 'tester123',
                  'plan_pricing': plan_pricing.pk}
        r = self.client.post(self.get_register_url(),
                             json.dumps(params),
                             content_type='application/json')
        self.assertEqual(r.status_code, 400)
        self.assertIn('billing_info', r.json())

    def test_register_premium_400_billing_empty(self):
        plan_pricing = self._create_premium_plan()
        params = {
            'username': 'test@test.com',
            'email': 'test@test.com',
            'password1': 'tester123',
            'password2': 'tester123',
            'plan_pricing': plan_pricing.pk,
            'billing_info': {
                'tax_number': '',
                'name': '',
                'street': '',
                'city': '',
                'zipcode': '',
                'country': ''
            }
        }
        r = self.client.post(self.get_register_url(),
                             json.dumps(params),
                             content_type='application/json')
        self.assertEqual(r.status_code, 400)
        data = r.json()
        self.assertIn('billing_info', data)
        self.assertIn('name', data['billing_info'])
        self.assertIn('street', data['billing_info'])
        self.assertIn('city', data['billing_info'])
        self.assertIn('zipcode', data['billing_info'])
        self.assertIn('country', data['billing_info'])

    def test_register_premium_pay(self):
        self.assertEqual(Payment.objects.count(), 0)
        r, params, plan = self._register_premium()
        payment = Payment.objects.first()
        payment.change_status(PaymentStatus.CONFIRMED)
        user = payment.order.user
        self.assertEqual(payment.order.status, Order.STATUS.COMPLETED)
        self.assertEqual(payment.organization, Organization.objects.first())
        self.assertTrue(user.is_active)
        ug = user.radiususergroup_set.first()
        self.assertIsNotNone(ug)
        self.assertEqual(ug.group.name, 'default-premium')
        userplan = user.userplan
        self.assertTrue(userplan.is_active())
        inv = payment.order.invoice_set.filter(type=Invoice.INVOICE_TYPES.INVOICE).first()
        self.assertIsNotNone(inv)
        order = payment.order
        self.assertIsNotNone(order.tax)
        self.assertEqual(order.tax, app_settings.TAX)
        self.assertEqual(order.currency, app_settings.CURRENCY)

    def test_plans_200(self):
        self._create_free_plan()
        self._create_premium_plan()
        r = self.client.get(reverse('api_plan_pricing'))
        self.assertEqual(len(r.data), 2)
