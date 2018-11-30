from django.urls import reverse
from plans.models import Invoice

from openwisp_radius.tests.tests import BaseTestCase
from openwisp_users.models import User

from . import CreatePlansMixin


class TestViews(CreatePlansMixin, BaseTestCase):
    user_model = User

    def test_payment_view(self):
        r, params, plan = self._register_premium()
        payment = self._pay_premium_user()
        url = reverse('subscriptions:process_payment', args=[payment.pk])
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)

    def test_download_invoice(self):
        r, params, plan = self._register_premium()
        self._pay_premium_user()
        admin = self._create_user(username='admin',
                                  password='test',
                                  is_staff=True,
                                  is_superuser=True)
        self.client.force_login(admin)
        inv = Invoice.objects.filter(type=Invoice.INVOICE_TYPES.INVOICE).first()
        response = self.client.get(reverse('subscriptions:download_invoice', args=[inv.pk]))
        self.assertEqual(response.status_code, 200)
        expected = 'attachment; filename={}'.format(inv.get_invoice_pdf_filename())
        self.assertEqual(response['content-disposition'], expected)

    def test_download_invoice_404(self):
        admin = self._create_user(username='admin',
                                  password='test',
                                  is_staff=True,
                                  is_superuser=True)
        self.client.force_login(admin)
        response = self.client.get(reverse('subscriptions:download_invoice', args=[999]))
        self.assertEqual(response.status_code, 404)

    def test_download_invoice_not_staff(self):
        user = self._create_user(username='admin',
                                 password='test',
                                 is_staff=False,
                                 is_superuser=False)
        self.client.force_login(user)
        response = self.client.get(reverse('subscriptions:download_invoice', args=[999]))
        self.assertEqual(response.status_code, 302)
