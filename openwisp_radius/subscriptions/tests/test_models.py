from io import BytesIO

from plans.models import Invoice, Plan

from openwisp_radius.tests.tests import BaseTestCase
from openwisp_radius.utils import load_model
from openwisp_users.models import Organization, User

from . import CreatePlansMixin

RadiusGroup = load_model('RadiusGroup')


class TestModels(CreatePlansMixin, BaseTestCase):
    def test_auto_radius_groups_on_paid_plan_creation(self):
        rg_filter = RadiusGroup.objects.filter
        Organization.objects.create(name='test org', slug='testorg')
        self.assertEqual(Organization.objects.count(), 2)
        self.assertEqual(rg_filter().count(), 4)
        premium = self._create_premium_plan()
        self.assertEqual(rg_filter().count(), 8)
        self._create_premium_plan(name='Unlimited', price='19.99')
        self.assertEqual(rg_filter().count(), 10)
        self.assertEqual(rg_filter(name='default-premium').count(), 1)
        self.assertEqual(rg_filter(name='default-unlimited').count(), 1)
        self.assertEqual(rg_filter(name='default-temporary').count(), 1)
        self.assertEqual(rg_filter(name='test-org-premium').count(), 1)
        self.assertEqual(rg_filter(name='test-org-unlimited').count(), 1)
        self.assertEqual(rg_filter(name='test-org-temporary').count(), 1)
        premium.plan.name = 'plus'
        premium.plan.full_clean()
        premium.plan.save()
        self.assertEqual(rg_filter(name='default-plus').count(), 1)
        self.assertEqual(rg_filter(name='test-org-plus').count(), 1)
        self.assertEqual(rg_filter(name='default-premium').count(), 0)
        self.assertEqual(rg_filter(name='test-org-premium').count(), 0)

    def test_duplicate_plan(self):
        self.assertEqual(Organization.objects.count(), 1)
        self.assertEqual(RadiusGroup.objects.count(), 2)
        self._create_premium_plan()
        self.assertEqual(RadiusGroup.objects.count(), 4)
        self._create_premium_plan()
        self.assertEqual(RadiusGroup.objects.count(), 4)

    def test_free_plan_doesnt_create_radiusgroups(self):
        self.assertEqual(RadiusGroup.objects.count(), 2)
        plan_pricing = self._create_free_plan()
        self.assertEqual(RadiusGroup.objects.count(), 2)
        plan_pricing.plan.delete()
        plan_pricing.pricing.delete()
        plan_pricing.delete()

    def test_auto_radius_groups_on_org_creation(self):
        rg_filter = RadiusGroup.objects.filter
        self.assertEqual(Organization.objects.count(), 1)
        self._create_free_plan()
        self._create_premium_plan()
        self._create_premium_plan(name='Unlimited', price='19.99')
        self.assertEqual(rg_filter().count(), 5)
        Organization.objects.create(name='test org',
                                    slug='testorg')
        self.assertEqual(rg_filter().count(), 10)
        self.assertEqual(rg_filter(name='default-premium').count(), 1)
        self.assertEqual(rg_filter(name='default-unlimited').count(), 1)
        self.assertEqual(rg_filter(name='default-temporary').count(), 1)
        self.assertEqual(rg_filter(name='test-org-premium').count(), 1)
        self.assertEqual(rg_filter(name='test-org-unlimited').count(), 1)
        self.assertEqual(rg_filter(name='test-org-temporary').count(), 1)

    def test_generate_invoice_pdf(self):
        r, params, plan = self._register_premium()
        self._pay_premium_user()
        inv = Invoice.objects.first()
        pdf = inv.generate_invoice_pdf()
        self.assertIsInstance(pdf, BytesIO)

    def test_temporary_group_missing(self):
        plan_pricing = self._create_premium_plan()
        RadiusGroup.objects.all().delete()
        self.assertEqual(User.objects.count(), 0)
        r, params, plan = self._register_premium(plan_pricing)
        self.assertEqual(User.objects.count(), 1)
        user = User.objects.first()
        self.assertEqual(user.radiususergroup_set.count(), 1)
        rug = user.radiususergroup_set.first()
        self.assertEqual(rug.group.name, 'default-temporary')

    def test_premium_group_missing(self):
        plan_pricing = self._create_premium_plan()
        RadiusGroup.objects.all().delete()
        self.assertEqual(User.objects.count(), 0)
        r, params, plan = self._register_premium(plan_pricing)
        self._pay_premium_user()
        self.assertEqual(User.objects.count(), 1)
        user = User.objects.first()
        self.assertEqual(user.radiususergroup_set.count(), 1)
        rug = user.radiususergroup_set.first()
        self.assertEqual(rug.group.name, 'default-premium')


class TestDefaultModelInstances(BaseTestCase):
    def test_default_plans(self):
        self.assertEqual(Plan.objects.filter(name='Free').count(), 1)
        self.assertEqual(Plan.objects.filter(name='Premium').count(), 1)
        self.assertEqual(RadiusGroup.objects.count(), 4)
