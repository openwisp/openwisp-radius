from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.urls import reverse
from django_freeradius.migrations import (DEFAULT_SESSION_TIME_LIMIT, DEFAULT_SESSION_TRAFFIC_LIMIT,
                                          SESSION_TIME_ATTRIBUTE, SESSION_TRAFFIC_ATTRIBUTE)
from django_freeradius.tests import FileMixin
from django_freeradius.tests.base.test_admin import BaseTestAdmin
from django_freeradius.tests.base.test_api import BaseTestAutoGroupname, BaseTestAutoGroupnameDisabled
from django_freeradius.tests.base.test_batch_add_users import BaseTestCSVUpload
from django_freeradius.tests.base.test_commands import BaseTestCommands
from django_freeradius.tests.base.test_models import (BaseTestNas, BaseTestRadiusAccounting,
                                                      BaseTestRadiusBatch, BaseTestRadiusCheck,
                                                      BaseTestRadiusGroup, BaseTestRadiusPostAuth,
                                                      BaseTestRadiusReply, BaseTestRadiusToken)
from django_freeradius.tests.base.test_social import BaseTestSocial
from django_freeradius.tests.base.test_utils import BaseTestUtils

from openwisp_users.models import Organization, OrganizationUser
from openwisp_utils.tests.utils import TestMultitenantAdminMixin

from ..models import (Nas, OrganizationRadiusSettings, RadiusAccounting, RadiusBatch, RadiusCheck,
                      RadiusGroup, RadiusGroupCheck, RadiusGroupReply, RadiusPostAuth, RadiusReply,
                      RadiusToken, RadiusUserGroup)
from .mixins import ApiTokenMixin, BaseTestCase, CallCommandMixin, PostParamsMixin

_SUPERUSER = {'username': 'gino', 'password': 'cic', 'email': 'giggi_vv@gmail.it'}
_RADCHECK_ENTRY = {'username': 'Monica', 'value': 'Cam0_liX',
                   'attribute': 'NT-Password'}
_RADCHECK_ENTRY_PW_UPDATE = {'username': 'Monica', 'new_value': 'Cam0_liX',
                             'attribute': 'NT-Password'}

User = get_user_model()


class TestNas(BaseTestNas, BaseTestCase):
    nas_model = Nas


class TestRadiusAccounting(BaseTestRadiusAccounting, BaseTestCase):
    radius_accounting_model = RadiusAccounting

    # no need to repeat this test here
    test_ipv6_validator = None


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


class TestAdmin(BaseTestCase, FileMixin, CallCommandMixin, PostParamsMixin,
                BaseTestAdmin, TestMultitenantAdminMixin):
    app_name = 'openwisp_radius'
    nas_model = Nas
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    radius_token_model = RadiusToken
    radius_check_model = RadiusCheck
    radius_groupcheck_model = RadiusGroupCheck
    radius_groupreply_model = RadiusGroupReply
    radius_postauth_model = RadiusPostAuth
    radius_reply_model = RadiusReply
    radius_usergroup_model = RadiusUserGroup
    radius_group_model = RadiusGroup
    user_model = User
    operator_permission_filters = [
        {'codename__endswith': 'nas'},
        {'codename__endswith': 'accounting'},
        {'codename__endswith': 'batch'},
        {'codename__endswith': 'check'},
        {'codename__endswith': 'reply'},
        {'codename__endswith': 'group'},
        {'codename__endswith': 'user'},
    ]

    def setUp(self):
        super().setUp()
        self._superuser_login()

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

    def _login(self, username='admin', password='tester'):
        self.client.force_login(self.user_model.objects.get(username=username))

    def _get_url(self, url, user=False, group=False):
        response = self.client.get(url)
        user_url = '/admin/openwisp_users/user/autocomplete/'
        group_url = '/admin/openwisp_radius/radiusgroup/autocomplete/'
        if user_url in str(response.content) and user:
            return user_url
        if group_url in str(response.content) and group:
            return group_url

    def test_radiusbatch_org_user(self):
        self.assertEqual(self.radius_batch_model.objects.count(), 0)
        add_url = reverse('admin:{0}_radiusbatch_add'.format(self.app_name))
        data = self._get_csv_post_data()
        self.client.post(add_url, data, follow=True)
        self.assertEqual(OrganizationUser.objects.all().count(), 3)
        for u in OrganizationUser.objects.all():
            self.assertEqual(u.organization,
                             self.radius_batch_model.objects.first().organization)

    def _create_multitenancy_test_env(self,
                                      usergroup=False,
                                      groupcheck=False,
                                      groupreply=False):
        org1 = self._create_org(name='testorg1',
                                is_active=True,
                                slug='testorg1')
        org2 = self._create_org(name='testorg2',
                                is_active=True,
                                slug='testorg2')
        inactive = self._create_org(name='inactive org',
                                    is_active=False,
                                    slug='inactive-org')
        operator = self._create_operator()
        org1.add_user(operator, is_admin=True)
        inactive.add_user(operator)
        user11 = User.objects.create(username='user11',
                                     password='User_11',
                                     email='user11@g.com',)
        user22 = User.objects.create(username='user22',
                                     password='User_22',
                                     email='user22@g.com')
        user33 = User.objects.create(username='user33',
                                     password='User_33',
                                     email='user33@g.com')
        org1.add_user(user11)
        org2.add_user(user22)
        inactive.add_user(user33)
        rc1 = RadiusCheck.objects.create(username='user1',
                                         attribute='NT-Password',
                                         value='User_1',
                                         organization=org1)
        rc2 = RadiusCheck.objects.create(username='user2',
                                         attribute='NT-Password',
                                         value='User_2',
                                         organization=org2)
        rc3 = RadiusCheck.objects.create(username='user3',
                                         attribute='NT-Password',
                                         value='User_3',
                                         organization=inactive)
        rr1 = RadiusReply.objects.create(username='user1',
                                         attribute='NT-Password',
                                         value='User_1',
                                         organization=org1)
        rr2 = RadiusReply.objects.create(username='user2',
                                         attribute='NT-Password',
                                         value='User_2',
                                         organization=org2)
        rr3 = RadiusReply.objects.create(username='user3',
                                         attribute='NT-Password',
                                         value='User_3',
                                         organization=inactive)
        rg1 = RadiusGroup.objects.create(name='radiusgroup1org', organization=org1)
        rg2 = RadiusGroup.objects.create(name='radiusgroup2org', organization=org2)
        rg3 = RadiusGroup.objects.create(name='radiusgroup3-inactive', organization=inactive)
        nas1 = Nas.objects.create(name='nas1org',
                                  short_name='nas1org',
                                  secret='nas1-secret',
                                  type='Other',
                                  organization=org1)
        nas2 = Nas.objects.create(name='nas2org',
                                  short_name='nas2org',
                                  secret='nas2-secret',
                                  type='Other',
                                  organization=org2)
        nas3 = Nas.objects.create(name='nas3-inactive',
                                  short_name='nas3org',
                                  secret='nas3-secret',
                                  type='Other',
                                  organization=inactive)
        ra1 = RadiusAccounting.objects.create(username='user1',
                                              nas_ip_address='172.16.64.92',
                                              unique_id='001',
                                              session_id='001',
                                              organization=org1)
        ra2 = RadiusAccounting.objects.create(username='user2',
                                              nas_ip_address='172.16.64.93',
                                              unique_id='002',
                                              session_id='002',
                                              organization=org2)
        ra3 = RadiusAccounting.objects.create(username='user3',
                                              nas_ip_address='172.16.64.95',
                                              unique_id='003',
                                              session_id='003',
                                              organization=inactive)
        rb1 = RadiusBatch.objects.create(name='radiusbacth1org',
                                         organization=org1,
                                         strategy='prefix',
                                         prefix='test-prefix1')
        rb2 = RadiusBatch.objects.create(name='radiusbacth2org',
                                         organization=org2,
                                         strategy='prefix',
                                         prefix='test-prefix2')
        rb3 = RadiusBatch.objects.create(name='radiusbacth3-inactive',
                                         organization=inactive,
                                         strategy='prefix',
                                         prefix='test-prefix3')
        data = dict(rb1=rb1, rb2=rb2, rb3=rb3,
                    nas1=nas1, nas2=nas2, nas3=nas3,
                    rg1=rg1, rg2=rg2, rg3=rg3,
                    rr1=rr1, rr2=rr2, rr3=rr3,
                    rc1=rc1, rc2=rc2, rc3=rc3,
                    ra1=ra1, ra2=ra2, ra3=ra3,
                    org1=org1, org2=org2,
                    inactive=inactive,
                    user11=user11, user22=user22, user33=user33,
                    operator=operator)
        if usergroup:
            ug1 = self._create_radius_usergroup(user=user11, group=rg1)
            ug2 = self._create_radius_usergroup(user=user22, group=rg2)
            ug3 = self._create_radius_usergroup(user=user33, group=rg3)
            data.update(dict(ug1=ug1, ug2=ug2, ug3=ug3))
        if groupcheck:
            gc1 = self._create_radius_groupcheck(group=rg1,
                                                 attribute='test-attr1',
                                                 value='1')
            gc2 = self._create_radius_groupcheck(group=rg2,
                                                 attribute='test-attr2',
                                                 value='2')
            gc3 = self._create_radius_groupcheck(group=rg3,
                                                 attribute='test-attr3',
                                                 value='3')
            data.update(dict(gc1=gc1, gc2=gc2, gc3=gc3))
        if groupreply:
            gr1 = self._create_radius_groupreply(group=rg1,
                                                 attribute='test-attr1',
                                                 value='1')
            gr2 = self._create_radius_groupreply(group=rg2,
                                                 attribute='test-attr2',
                                                 value='2')
            gr3 = self._create_radius_groupreply(group=rg3,
                                                 attribute='test-attr3',
                                                 value='3')
            data.update(dict(gr1=gr1, gr2=gr2, gr3=gr3))
        return data

    def test_radiuscheck_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiuscheck_changelist'.format(self.app_name)),
            visible=[data['rc1'].username, data['org1'].name],
            hidden=[data['rc2'].username, data['org2'].name,
                    data['rc3'].username]
        )

    def test_radiuscheck_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiuscheck_add'.format(self.app_name)),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True
        )

    def test_radiuscheck_user_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=self._get_url(reverse('admin:{0}_radiuscheck_add'.format(self.app_name)), user=True),
            visible=[data['user11']],
            hidden=[data['user22']],
        )

    def test_radiusreply_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusreply_changelist'.format(self.app_name)),
            visible=[data['rr1'].username, data['org1'].name],
            hidden=[data['rr2'].username, data['org2'],
                    data['rr3'].username]
        )

    def test_radiusreply_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusreply_add'.format(self.app_name)),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True
        )

    def test_radiusreply_user_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=self._get_url(reverse('admin:{0}_radiusreply_add'.format(self.app_name)), user=True),
            visible=[data['user11']],
            hidden=[data['user22']],
        )

    def test_radiusgroup_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusgroup_changelist'.format(self.app_name)),
            visible=[data['rg1'].name, data['org1'].name],
            hidden=[data['org2'].name, data['rg2'].name,
                    data['rg3'].name]
        )

    def test_radiusgroup_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=(reverse('admin:{0}_radiusgroup_add'.format(self.app_name))),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True
        )

    def test_nas_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_nas_changelist'.format(self.app_name)),
            visible=[data['nas1'].name, data['org1'].name],
            hidden=[data['nas2'].name, data['org2'].name,
                    data['nas3'].name]
        )

    def test_nas_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_nas_add'.format(self.app_name)),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True
        )

    def test_radiusaccounting_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusaccounting_changelist'.format(self.app_name)),
            visible=[data['ra1'].username, data['org1'].name],
            hidden=[data['ra2'].username, data['org2'].name,
                    data['ra3'].username]
        )

    def test_radiusbatch_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusbatch_changelist'.format(self.app_name)),
            visible=[data['rb1'].name, data['org1'].name],
            hidden=[data['rb2'].name, data['org2'].name,
                    data['rb3'].name]
        )

    def test_radiusbatch_organization_fk_queryset(self):
        data = self._create_multitenancy_test_env()
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusbatch_add'.format(self.app_name)),
            visible=[data['org1'].name],
            hidden=[data['org2'].name, data['inactive']],
            select_widget=True
        )

    def test_radius_usergroup_queryset(self):
        data = self._create_multitenancy_test_env(usergroup=True)
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiususergroup_changelist'.format(self.app_name)),
            visible=[data['ug1'].group, data['ug1'].user],
            hidden=[data['ug2'].group, data['ug2'].user,
                    data['ug3'].user]
        )

    def test_radius_usergroup_group_fk_queryset(self):
        data = self._create_multitenancy_test_env(usergroup=True)
        self._test_multitenant_admin(
            url=self._get_url(reverse('admin:{0}_radiususergroup_add'.format(self.app_name)),
                              group=True),
            visible=[data['rg1']],
            hidden=[data['rg2']]
        )

    def test_radius_usergroup_user_fk_queryset(self):
        data = self._create_multitenancy_test_env(usergroup=True)
        self._test_multitenant_admin(
            url=self._get_url(reverse('admin:{0}_radiususergroup_add'.format(self.app_name)),
                              user=True),
            visible=[data['user11']],
            hidden=[data['user22']]
        )

    def test_radius_groupcheck_queryset(self):
        data = self._create_multitenancy_test_env(groupcheck=True)
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusgroupcheck_changelist'.format(self.app_name)),
            visible=[data['gc1'].group, data['gc1'].attribute],
            hidden=[data['gc2']. group, data['gc2'].attribute,
                    data['gc3']]
        )

    def test_radius_groupcheck_group_fk_queryset(self):
        data = self._create_multitenancy_test_env(groupcheck=True)
        self._test_multitenant_admin(
            url=self._get_url(reverse('admin:{0}_radiusgroupcheck_add'.format(self.app_name)),
                              group=True),
            visible=[data['rg1']],
            hidden=[data['rg2']]
        )

    def test_radius_groupreply_queryset(self):
        data = self._create_multitenancy_test_env(groupreply=True)
        self._test_multitenant_admin(
            url=reverse('admin:{0}_radiusgroupreply_changelist'.format(self.app_name)),
            visible=[data['gr1'].group, data['gr1'].attribute],
            hidden=[data['gr2'].group, data['gr2'].attribute,
                    data['gr3']]
        )

    def test_radius_groupreply_group_fk_queryset(self):
        data = self._create_multitenancy_test_env(groupreply=True)
        self._test_multitenant_admin(
            url=self._get_url(reverse('admin:{0}_radiusgroupreply_add'.format(self.app_name)),
                              group=True),
            visible=[data['rg1']],
            hidden=[data['rg2']]
        )

    def test_radius_token_creation_form(self):
        pass

    def test_radius_token_change(self):
        pass

    def test_radius_token_delete_selected(self):
        pass


class TestAutoGroupname(ApiTokenMixin,
                        BaseTestAutoGroupname,
                        BaseTestCase):
    radius_accounting_model = RadiusAccounting
    radius_usergroup_model = RadiusUserGroup
    user_model = get_user_model()


class TestAutoGroupnameDisabled(ApiTokenMixin,
                                BaseTestAutoGroupnameDisabled,
                                BaseTestCase):
    radius_accounting_model = RadiusAccounting
    radius_usergroup_model = RadiusUserGroup
    user_model = get_user_model()


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
    radius_token_model = RadiusToken

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


class TestOgranizationRadiusSettings(ApiTokenMixin, BaseTestCase):
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


class TestRadiusToken(BaseTestRadiusToken, BaseTestCase):
    radius_token_model = RadiusToken
