from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django_freeradius.tests import FileMixin
from django_freeradius.tests import PostParamsMixin as BasePostParamsMixin
from django_freeradius.tests.base.test_admin import BaseTestAdmin
from django_freeradius.tests.base.test_api import BaseTestApi, BaseTestApiReject
from django_freeradius.tests.base.test_batch_add_users import BaseTestCSVUpload
from django_freeradius.tests.base.test_commands import BaseTestCommands
from django_freeradius.tests.base.test_models import (BaseTestNas, BaseTestRadiusAccounting,
                                                      BaseTestRadiusBatch, BaseTestRadiusCheck,
                                                      BaseTestRadiusGroup, BaseTestRadiusPostAuth,
                                                      BaseTestRadiusReply)
from django_freeradius.tests.base.test_social import BaseTestSocial
from django_freeradius.tests.base.test_utils import BaseTestUtils

from openwisp_users.models import OrganizationUser

from .mixins import CallCommandMixin, CreateRadiusObjectsMixin, PostParamsMixin
from .models import (Nas, OrganizationRadiusSettings, RadiusAccounting, RadiusBatch, RadiusCheck, RadiusGroup,
                     RadiusGroupCheck, RadiusGroupReply, RadiusPostAuth, RadiusReply, RadiusUserGroup)

_SUPERUSER = {'username': 'gino', 'password': 'cic', 'email': 'giggi_vv@gmail.it'}
_RADCHECK_ENTRY = {'username': 'Monica', 'value': 'Cam0_liX',
                   'attribute': 'NT-Password'}
_RADCHECK_ENTRY_PW_UPDATE = {'username': 'Monica', 'new_value': 'Cam0_liX',
                             'attribute': 'NT-Password'}

User = get_user_model()


class BaseTestCase(CreateRadiusObjectsMixin, TestCase):
    pass


class TestNas(BaseTestNas, BaseTestCase):
    nas_model = Nas


class TestRadiusAccounting(BaseTestRadiusAccounting, BaseTestCase):
    radius_accounting_model = RadiusAccounting


class TestRadiusCheck(BaseTestRadiusCheck, BaseTestCase):
    radius_check_model = RadiusCheck


class TestRadiusReply(BaseTestRadiusReply, BaseTestCase):
    radius_reply_model = RadiusReply


class TestRadiusGroup(BaseTestRadiusGroup, BaseTestCase):
    radius_group_model = RadiusGroup
    radius_groupreply_model = RadiusGroupReply
    radius_groupcheck_model = RadiusGroupCheck
    radius_usergroup_model = RadiusUserGroup


class TestRadiusPostAuth(BaseTestRadiusPostAuth, BaseTestCase):
    radius_postauth_model = RadiusPostAuth


class TestRadiusBatch(BaseTestRadiusBatch, BaseTestCase):
    radius_batch_model = RadiusBatch


class TestAdmin(FileMixin, CallCommandMixin, PostParamsMixin,
                BaseTestAdmin, BaseTestCase):
    app_name = 'openwisp_radius'
    nas_model = Nas
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    radius_check_model = RadiusCheck
    radius_groupcheck_model = RadiusGroupCheck
    radius_groupreply_model = RadiusGroupReply
    radius_postauth_model = RadiusPostAuth
    radius_reply_model = RadiusReply
    radius_usergroup_model = RadiusUserGroup
    radius_group_model = RadiusGroup

    def setUp(self):
        self.default_org = self._create_org()
        super(TestAdmin, self).setUp()

    def _get_csv_post_data(self):
        data = super(TestAdmin, self)._get_csv_post_data()
        data['organization'] = self.default_org.pk
        return data

    def _get_prefix_post_data(self):
        data = super(TestAdmin, self)._get_prefix_post_data()
        data['organization'] = self.default_org.pk
        return data

    def test_radiusbatch_org_user(self):
        self.assertEqual(self.radius_batch_model.objects.count(), 0)
        add_url = reverse('admin:{0}_radiusbatch_add'.format(self.app_name))
        data = self._get_csv_post_data()
        self.client.post(add_url, data, follow=True)
        self.assertEqual(OrganizationUser.objects.all().count(), 3)
        for u in OrganizationUser.objects.all():
            self.assertEqual(u.organization,
                             self.radius_batch_model.objects.first().organization)


class ApiTokenMixin(BasePostParamsMixin):
    """
    we don't automatically set the organization
    in this mixin, because it must be inferred
    from the token authentication
    """
    def setUp(self):
        org = self._create_org()
        rad = OrganizationRadiusSettings.objects.create(token='asdfghjklqwerty',
                                                        organization=org)
        self.auth_header = 'Bearer {0} {1}'.format(org.pk, rad.token)
        self.token_querystring = '?token={0}&uuid={1}'.format(rad.token, str(org.pk))
        self.default_org = org


class TestApi(ApiTokenMixin, BaseTestApi, BaseTestCase):
    radius_postauth_model = RadiusPostAuth
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    user_model = User

    def assertAcctData(self, ra, data):
        # we don't expect the organization field
        # because it will be inferred from the auth token
        self.assertNotIn('organization', data)
        # but we still want to ensure the
        # organization is filled correctly
        data['organization'] = self.default_org
        return super().assertAcctData(ra, data)

    def test_accounting_start_201(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        data['organization'] = str(self.default_org.pk)
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 403)
        self.assertIn('setting the organization', response.data['detail'])

    def test_register_201(self):
        self.assertEqual(User.objects.count(), 0)
        url = reverse('freeradius:rest_register', args=[self.default_org.slug])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 201)
        self.assertIn('key', r.data)
        self.assertEqual(User.objects.count(), 1)
        user = User.objects.first()
        self.assertIn((self.default_org.pk,), user.organizations_pk)

    def test_register_404(self):
        url = reverse('freeradius:rest_register', args=['madeup'])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 404)


class TestApiReject(ApiTokenMixin, BaseTestApiReject, BaseTestCase):
    pass


class TestCommands(FileMixin, CallCommandMixin,
                   BaseTestCommands, BaseTestCase):
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    radius_postauth_model = RadiusPostAuth


class TestCSVUpload(FileMixin, BaseTestCSVUpload, BaseTestCase):
    radius_batch_model = RadiusBatch


class TestUtils(FileMixin, BaseTestUtils, BaseTestCase):
    pass


class TestSocial(ApiTokenMixin, BaseTestSocial, BaseTestCase):
    def get_url(self):
        return reverse(self.view_name, args=[self.default_org.slug])

    def test_redirect_cp_404(self):
        u = self._create_social_user()
        self.client.force_login(u)
        r = self.client.get(reverse(self.view_name, args=['wrong']), {'cp': 'test'})
        self.assertEqual(r.status_code, 404)

    def test_redirect_cp_suspicious_400(self):
        u = self._create_social_user()
        u.is_staff = True
        u.save()
        self.client.force_login(u)
        r = self.client.get(self.get_url(), {'cp': 'test'})
        self.assertEqual(r.status_code, 400)

    def test_redirect_cp_301(self):
        super().test_redirect_cp_301()
        u = User.objects.filter(username='socialuser').first()
        self.assertIn((self.default_org.pk, ), u.organizations_pk)


class TestOgranizationRadiusSettings(BaseTestCase):
    user_model = User

    def setUp(self):
        self.org = self._create_org()

    def test_default_token(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(32, len(rad.token))

    def test_bad_token(self):
        try:
            rad = OrganizationRadiusSettings(token='bad.t.o.k.e.n', organization=self.org)
            rad.full_clean()
        except ValidationError as e:
            self.assertEqual(e.message_dict['token'][0],
                             'Key must not contain spaces, dots or slashes.')

    def test_cache(self):
        # clear cache set from previous tests
        cache.clear()
        rad = OrganizationRadiusSettings.objects.create(token='12345', organization=self.org)
        options = dict(username='molly', password='barbar')
        self._create_user(**options)
        token_querystring = '?token={0}&uuid={1}'.format(rad.token, str(self.org.pk))
        post_url = '{}{}'.format(reverse('freeradius:authorize'), token_querystring)
        self.client.post(post_url, {'username': 'molly', 'password': 'barbar'})
        self.assertEqual(rad.token, cache.get(rad.pk))
        # test update
        rad.token = '1234567'
        rad.save()
        self.assertEqual(rad.token, cache.get(rad.pk))
        # test delete
        rad.delete()
        self.assertEqual(None, cache.get(rad.pk))
