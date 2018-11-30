from datetime import date, timedelta

from django.core import mail
from django.core.management import call_command
from payments import PaymentStatus
from plans.models import Order

from openwisp_radius.tests.tests import BaseTestCase
from openwisp_radius.utils import load_model
from openwisp_users.models import Organization, User

from . import CreatePlansMixin
from .. import settings as app_settings
from ..models import Payment
from ..utils import get_or_create_temporary_radius_group, manage_expired_subscriptions

RadiusGroup = load_model('RadiusGroup')
RadiusUserGroup = load_model('RadiusUserGroup')
RadiusGroupCheck = load_model('RadiusGroupCheck')
RadiusGroupReply = load_model('RadiusGroupReply')


class TestUtils(CreatePlansMixin, BaseTestCase):
    def setUp(self):
        pass

    def _create_premium_user(self, expired=True):
        r, params, plan = self._register_premium()
        self._pay_premium_user()
        u = User.objects.get(username=params['username'])
        if expired:
            u.userplan.expire = date.today() - timedelta(days=10)
            u.userplan.save()
        return u

    def test_manage_expired_subscriptions_expired(self):
        u = self._create_premium_user(expired=True)
        mails_sent = len(mail.outbox)
        manage_expired_subscriptions()
        u.refresh_from_db()
        self.assertEqual(u.userplan.active, False)
        rug = u.radiususergroup_set.first()
        self.assertEqual(rug.groupname, 'default-temporary')
        pending_payments = Payment.objects.filter(status=PaymentStatus.WAITING).count()
        self.assertEqual(pending_payments, 1)
        pending_orders = Order.objects.filter(status=Order.STATUS.NEW).count()
        self.assertEqual(pending_orders, 1)
        self.assertEqual(len(mail.outbox), mails_sent + 1)

    def test_manage_expired_subscriptions_not_expired(self):
        u = self._create_premium_user(expired=False)
        manage_expired_subscriptions()
        u.refresh_from_db()
        self.assertEqual(u.userplan.active, True)
        rug = u.radiususergroup_set.first()
        self.assertEqual(rug.groupname, 'default-premium')

    def test_manage_expired_subscriptions_command(self, user=None,
                                                  expected_email=None):
        if not user:
            user = self._create_premium_user(expired=True)
        if not expected_email:
            expected_email = len(mail.outbox) + 1
        call_command('manage_expired_subscriptions')
        user.refresh_from_db()
        self.assertEqual(user.userplan.active, False)
        rug = user.radiususergroup_set.first()
        self.assertEqual(rug.groupname, 'default-temporary')
        pending_payments = Payment.objects.filter(status=PaymentStatus.WAITING).count()
        self.assertEqual(pending_payments, 1)
        pending_orders = Order.objects.filter(status=Order.STATUS.NEW).count()
        self.assertEqual(pending_orders, 1)
        self.assertEqual(len(mail.outbox), expected_email)
        renew_mail_text = str(mail.outbox[-1].message())
        self.assertIn('Subject: premium plan expired at', renew_mail_text)
        self.assertIn('your subscription to our "premium" plan has expired',
                      renew_mail_text)
        return user, len(mail.outbox)

    def test_manage_expired_subscriptions_command_idempotent(self):
        user, expected_email = self.test_manage_expired_subscriptions_command()
        self.test_manage_expired_subscriptions_command(user, expected_email)

    def test_temporary_radius_group(self):
        t = RadiusGroup.objects.get(name='default-temporary')
        self.assertEqual(t.radiusgroupcheck_set.count(), 3)
        self.assertEqual(t.radiusgroupreply_set.count(), 2)
        for check in app_settings.TEMP_GROUP_CHECKS:
            self.assertEqual(RadiusGroupCheck.objects.filter(**check).count(), 1)
        for reply in app_settings.TEMP_GROUP_REPLIES:
            self.assertEqual(RadiusGroupReply.objects.filter(**reply).count(), 1)

    def test_temporary_radius_group_idempotent(self):
        organization = Organization.objects.first()
        get_or_create_temporary_radius_group(organization)
        self.test_temporary_radius_group()

    def test_temporary_radius_group_create_again(self):
        organization = Organization.objects.first()
        RadiusGroup.objects.all().delete()
        get_or_create_temporary_radius_group(organization)
        self.test_temporary_radius_group()
