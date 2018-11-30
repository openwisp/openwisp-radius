import json
from datetime import date, timedelta
from decimal import Decimal

from django.conf import settings
from django.core import mail
from django.urls import reverse
from plans.models import BillingInfo, Invoice, Order

from openwisp_radius.tests.tests import BaseTestCase
from openwisp_radius.utils import load_model
from openwisp_users.models import Organization, User

from . import CreatePlansMixin
from .. import settings as app_settings
from ..models import Payment

RadiusGroup = load_model('RadiusGroup')


class TestApi(CreatePlansMixin, BaseTestCase):
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
        self.assertTrue(user.userplan.is_active())
        self.assertIsNone(user.userplan.expire)
        ug = user.radiususergroup_set.first()
        self.assertIsNotNone(ug)
        self.assertEqual(ug.group.name, 'default-users')
        self.assertEqual(len(mail.outbox), 1)

    def test_register_premium(self):
        r, params, plan = self._register_premium()
        self.assertEqual(r.status_code, 201)
        user = User.objects.get(username=params['username'])
        self.assertTrue(user.is_active)
        self.assertTrue(hasattr(user, 'userplan'))
        self.assertEqual(user.userplan.plan, plan)
        self.assertFalse(user.userplan.is_active())
        self.assertIsNone(user.userplan.expire)
        self.assertEqual(user.radiususergroup_set.count(), 1)
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
        self.assertEqual(inv.buyer_name, 'Joe Boe')
        self.assertEqual(inv.buyer_street, 'Test street 123')
        self.assertEqual(inv.buyer_city, 'Tallinn')
        self.assertEqual(inv.buyer_zipcode, '00071')
        self.assertEqual(str(inv.buyer_country), 'EE')
        self.assertEqual(inv.buyer_tax_number, 'EE123456789')
        issuer = settings.PLANS_INVOICE_ISSUER
        self.assertEqual(inv.issuer_name, issuer['issuer_name'])
        self.assertEqual(inv.issuer_street, issuer['issuer_street'])
        self.assertEqual(inv.issuer_city, issuer['issuer_city'])
        self.assertEqual(inv.issuer_zipcode, issuer['issuer_zipcode'])
        self.assertEqual(str(inv.issuer_country), issuer['issuer_country'])
        self.assertEqual(inv.issuer_tax_number, issuer['issuer_tax_number'])
        self.assertEqual(inv.issued, date.today())
        self.assertEqual(inv.user.username, 'test@test.com')
        self.assertEqual(inv.quantity, 1)
        self.assertEqual(inv.currency, settings.PLANS_CURRENCY)
        self.assertEqual(inv.tax, settings.PLANS_TAX)
        self.assertEqual(str(inv.total_net), '9.99')
        expected_total = (Decimal('9.99') * (settings.PLANS_TAX / 100 + 1)).quantize(Decimal('0.01'))
        self.assertEqual(inv.total, expected_total)
        payment = Payment.objects.first()
        self.assertIsNotNone(payment)
        self.assertIn('key', r.data)
        self.assertIn('payment_url', r.data)
        self.assertIn(str(payment.pk), r.data['payment_url'])
        self.assertEqual(len(mail.outbox), 1)

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
        payment = self._pay_premium_user()
        user = payment.order.user
        self.assertEqual(payment.order.status, Order.STATUS.COMPLETED)
        self.assertEqual(payment.organization, Organization.objects.first())
        self.assertTrue(user.is_active)
        ug = user.radiususergroup_set.first()
        self.assertIsNotNone(ug)
        self.assertEqual(ug.group.name, 'default-premium')
        self.assertEqual(user.radiususergroup_set.count(), 1)
        userplan = user.userplan
        self.assertTrue(userplan.is_active())
        self.assertIsNotNone(userplan.expire)
        self.assertEqual(userplan.expire, date.today() + timedelta(days=365))
        inv = payment.order.invoice_set.filter(type=Invoice.INVOICE_TYPES.INVOICE).first()
        self.assertIsNotNone(inv)
        self.assertEqual(inv.payment_date, date.today())
        self.assertEqual(inv.selling_date, inv.payment_date)
        order = payment.order
        self.assertIsNotNone(order.tax)
        self.assertEqual(order.tax, app_settings.TAX)
        self.assertEqual(order.currency, app_settings.CURRENCY)
        # expect 1 confirmation email and 1 email with attached invoice
        self.assertEqual(len(mail.outbox), 2)
        # ensure invoice sent as attachment
        invoice_email_text = str(mail.outbox[1].message())
        self.assertIn('Content-Type: application/pdf', invoice_email_text)
        self.assertIn('Content-Disposition: attachment; filename=', invoice_email_text)
        invoice_file_name = inv.full_number.replace('/', '-')
        self.assertIn('{}.pdf'.format(invoice_file_name), invoice_email_text)
        # ensure text is taken from our template
        self.assertIn('attached to this email', invoice_email_text)

    def test_plans_200(self):
        self._create_free_plan()
        self._create_premium_plan()
        r = self.client.get(reverse('subscriptions:api_plan_pricing'))
        self.assertEqual(len(r.data), 2)
