from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django_freeradius.tests import FileMixin
from django_freeradius.tests.base.test_admin import BaseTestAdmin
from django_freeradius.tests.base.test_api import BaseTestApi, BaseTestApiReject
from django_freeradius.tests.base.test_batch_add_users import BaseTestCSVUpload
from django_freeradius.tests.base.test_commands import BaseTestCommands
from django_freeradius.tests.base.test_models import (BaseTestNas, BaseTestRadiusAccounting,
                                                      BaseTestRadiusBatch, BaseTestRadiusCheck,
                                                      BaseTestRadiusGroup, BaseTestRadiusPostAuth,
                                                      BaseTestRadiusReply)
from django_freeradius.tests.base.test_utils import BaseTestUtils

from openwisp_users.models import Organization

from .mixins import CallCommandMixin, CreateRadiusObjectsMixin, PostParamsMixin
from .models import (Nas, OrganizationRadiusSettings, RadiusAccounting, RadiusBatch, RadiusCheck, RadiusGroup,
                     RadiusGroupCheck, RadiusGroupReply, RadiusPostAuth, RadiusReply, RadiusUserGroup)

_SUPERUSER = {'username': 'gino', 'password': 'cic', 'email': 'giggi_vv@gmail.it'}
_RADCHECK_ENTRY = {'username': 'Monica', 'value': 'Cam0_liX',
                   'attribute': 'NT-Password'}
_RADCHECK_ENTRY_PW_UPDATE = {'username': 'Monica', 'new_value': 'Cam0_liX',
                             'attribute': 'NT-Password'}


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
        self._create_org()
        super(TestAdmin, self).setUp()

    def _get_csv_post_data(self):
        data = super(TestAdmin, self)._get_csv_post_data()
        org = Organization.objects.first()
        data['organization'] = org.pk
        return data

    def _get_prefix_post_data(self):
        data = super(TestAdmin, self)._get_prefix_post_data()
        org = Organization.objects.first()
        data['organization'] = org.pk
        return data


class TestApi(BaseTestApi, PostParamsMixin, BaseTestCase):
    radius_postauth_model = RadiusPostAuth
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    user_model = get_user_model()

    def setUp(self):
        org = self._create_org()
        rad = OrganizationRadiusSettings.objects.create(token='asdfghjklqwerty',
                                                        organization=org)
        self.auth_header = 'Bearer {0} {1}'.format(org.pk, rad.token)
        self.token_querystring = '?token={0}&uuid={1}'.format(rad.token, str(org.pk))


class TestApiReject(BaseTestApiReject, BaseTestCase):

    def setUp(self):
        org = self._create_org()
        rad = OrganizationRadiusSettings.objects.create(token='asdfghjklqwerty',
                                                        organization=org)
        self.auth_header = 'Bearer {0} {1}'.format(org.pk, rad.token)
        self.token_querystring = '?token={0}&uuid={1}'.format(rad.token, str(org.pk))


class TestCommands(BaseTestCommands, BaseTestCase,
                   FileMixin, CallCommandMixin):
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    radius_postauth_model = RadiusPostAuth


class TestCSVUpload(BaseTestCSVUpload, CreateRadiusObjectsMixin,
                    FileMixin, TestCase):
    radius_batch_model = RadiusBatch


class TestUtils(BaseTestUtils, FileMixin, BaseTestCase):
    pass


class TestOgranizationRadiusSettings(BaseTestCase):
    user_model = get_user_model()

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
