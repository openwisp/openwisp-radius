from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse
from django_freeradius.migrations import (DEFAULT_SESSION_TIME_LIMIT, DEFAULT_SESSION_TRAFFIC_LIMIT,
                                          SESSION_TIME_ATTRIBUTE, SESSION_TRAFFIC_ATTRIBUTE)
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

from openwisp_users.models import Organization, OrganizationUser

from ..models import (Nas, OrganizationRadiusSettings, RadiusAccounting, RadiusBatch, RadiusCheck,
                      RadiusGroup, RadiusGroupCheck, RadiusGroupReply, RadiusPostAuth, RadiusReply,
                      RadiusUserGroup)
from .mixins import CallCommandMixin, CreateRadiusObjectsMixin, PostParamsMixin

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
    test_create_radius_check_model = None


class TestRadiusReply(BaseTestRadiusReply, BaseTestCase):
    radius_reply_model = RadiusReply


class TestRadiusGroup(BaseTestRadiusGroup, BaseTestCase):
    radius_group_model = RadiusGroup
    radius_groupreply_model = RadiusGroupReply
    radius_groupcheck_model = RadiusGroupCheck
    radius_usergroup_model = RadiusUserGroup

    def test_default_groups(self):
        default_org = Organization.objects.first()
        queryset = self.radius_group_model.objects.filter(organization=default_org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name='default-users').count(), 1)
        self.assertEqual(queryset.filter(name='default-power-users').count(), 1)
        self.assertEqual(queryset.filter(default=True).count(), 1)
        users = queryset.get(name='default-users')
        self.assertTrue(users.default)
        self.assertEqual(users.radiusgroupcheck_set.count(), 2)
        check = users.radiusgroupcheck_set.get(attribute=SESSION_TIME_ATTRIBUTE)
        self.assertEqual(check.value, DEFAULT_SESSION_TIME_LIMIT)
        check = users.radiusgroupcheck_set.get(attribute=SESSION_TRAFFIC_ATTRIBUTE)
        self.assertEqual(check.value, DEFAULT_SESSION_TRAFFIC_LIMIT)
        power_users = queryset.get(name='default-power-users')
        self.assertEqual(power_users.radiusgroupcheck_set.count(), 0)

    def test_create_organization_default_group(self):
        new_org = self._create_org(name='new org', slug='new-org')
        queryset = self.radius_group_model.objects.filter(organization=new_org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name='new-org-users').count(), 1)
        self.assertEqual(queryset.filter(name='new-org-power-users').count(), 1)
        self.assertEqual(queryset.filter(default=True).count(), 1)
        group = queryset.filter(default=True).first()
        self.assertEqual(group.radiusgroupcheck_set.count(), 2)
        self.assertEqual(group.radiusgroupreply_set.count(), 0)

    def test_change_default_group(self):
        org1 = self._create_org(name='org1', slug='org1')
        org2 = self._create_org(name='org2', slug='org2')
        new_default_org1 = self.radius_group_model(name='org1-new',
                                                   organization=org1,
                                                   description='test',
                                                   default=True)
        new_default_org1.full_clean()
        new_default_org1.save()
        new_default_org2 = self.radius_group_model(name='org2-new',
                                                   organization=org2,
                                                   description='test',
                                                   default=True)
        new_default_org2.full_clean()
        new_default_org2.save()
        queryset = self.radius_group_model.objects.filter(default=True,
                                                          organization=org1)
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.filter(name='org1-new').count(), 1)
        # org2
        queryset = self.radius_group_model.objects.filter(default=True,
                                                          organization=org2)
        self.assertEqual(queryset.count(), 1)
        self.assertEqual(queryset.filter(name='org2-new').count(), 1)

    def test_rename_organization(self):
        default_org = Organization.objects.first()
        default_org.name = 'renamed'
        default_org.slug = default_org.name
        default_org.full_clean()
        default_org.save()
        queryset = self.radius_group_model.objects.filter(organization=default_org)
        self.assertEqual(queryset.count(), 2)
        self.assertEqual(queryset.filter(name='renamed-users').count(), 1)
        self.assertEqual(queryset.filter(name='renamed-power-users').count(), 1)

    def test_new_user_default_group(self):
        org = Organization.objects.get(slug='default')
        u = get_user_model()(username='test',
                             email='test@test.org',
                             password='test')
        u.full_clean()
        u.save()
        org.add_user(u)
        u.refresh_from_db()
        usergroup_set = u.radiususergroup_set.all()
        self.assertEqual(usergroup_set.count(), 1)
        ug = usergroup_set.first()
        self.assertTrue(ug.group.default)

    def test_auto_prefix(self):
        org = self._create_org(name='Cool WiFi', slug='cool-wifi')
        rg = self.radius_group_model(name='guests',
                                     organization=org)
        rg.full_clean()
        self.assertEqual(rg.name, '{}-guests'.format(org.slug))

    def test_org_none(self):
        rg = self.radius_group_model(name='guests')
        try:
            rg.full_clean()
        except ValidationError as e:
            self.assertIn('organization', e.message_dict)
        except Exception as e:
            name = e.__class__.__name__
            self.fail('ValidationError not raised, '
                      'got "{}: {}" instead'.format(name, e))
        else:
            self.fail('ValidationError not raised')


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
        self.default_org = Organization.objects.get(slug='default')
        super(TestAdmin, self).setUp()

    @property
    def _RADCHECK_ENTRY_PW_UPDATE(self):  # noqa
        data = BaseTestAdmin._RADCHECK_ENTRY_PW_UPDATE
        data['organization'] = str(self.default_org.pk)
        return data

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

    @override_settings(
        ACCOUNT_EMAIL_VERIFICATION='mandatory',
        ACCOUNT_EMAIL_REQUIRED=True
    )
    def test_email_verification_sent(self):
        self.assertEqual(User.objects.count(), 0)
        url = reverse('freeradius:rest_register', args=[self.default_org.slug])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.data['detail'], "Verification e-mail sent.")

    @override_settings(REST_USE_JWT=True)
    def test_registration_with_jwt(self):
        user_count = User.objects.all().count()
        url = reverse('freeradius:rest_register', args=[self.default_org.slug])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 201)
        self.assertIn('token', r.data)
        self.assertEqual(User.objects.all().count(), user_count + 1)

    def test_api_show_only_token_org(self):
        org = Organization.objects.create(name='org1')
        self.assertEqual(self.radius_accounting_model.objects.count(), 0)
        nas_ip = '127.0.0.1'
        test1 = self.radius_accounting_model(session_id='asd1',
                                             organization=org,
                                             nas_ip_address=nas_ip,
                                             unique_id='123')
        test1.full_clean()
        test1.save()
        test2 = self.radius_accounting_model(session_id='asd2',
                                             organization=self.default_org,
                                             nas_ip_address=nas_ip,
                                             unique_id='1234')
        test2.full_clean()
        test2.save()
        data = self.client.get(self._acct_url,
                               HTTP_AUTHORIZATION=self.auth_header)
        self.assertEqual(len(data.json()), 1)
        self.assertEqual(data.json()[0]['organization'], str(self.default_org.pk))


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

    def test_string_representation(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(str(rad), rad.organization.name)

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

    def test_no_org_radius_setting(self):
        cache.clear()
        options = dict(username='molly', password='barbar')
        self._create_user(**options)
        token_querystring = '?token={0}&uuid={1}'.format('12345', str(self.org.pk))
        post_url = '{}{}'.format(reverse('freeradius:authorize'), token_querystring)
        r = self.client.post(post_url, {'username': 'molly', 'password': 'barbar'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data, {'detail': 'Token authentication failed'})

    def test_uuid_in_cache(self):
        rad = OrganizationRadiusSettings.objects.create(token='12345', organization=self.org)
        cache.set('uuid', str(self.org.pk), 30)
        options = dict(username='molly', password='barbar')
        self._create_user(**options)
        token_querystring = '?token={0}&uuid={1}'.format(rad.token, str(self.org.pk))
        post_url = '{}{}'.format(reverse('freeradius:authorize'), token_querystring)
        r = self.client.post(post_url, {'username': 'molly', 'password': 'barbar'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data, {'detail': 'Token authentication failed'})
        cache.clear()
