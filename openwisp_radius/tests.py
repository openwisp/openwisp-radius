from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django_freeradius.tests import FileMixin
from django_freeradius.tests.base.test_admin import BaseTestAdmin
from django_freeradius.tests.base.test_api import BaseTestApi, BaseTestApiReject
from django_freeradius.tests.base.test_batch_add_users import BaseTestCSVUpload
from django_freeradius.tests.base.test_commands import BaseTestCommands
from django_freeradius.tests.base.test_models import (BaseTestNas, BaseTestRadiusAccounting,
                                                      BaseTestRadiusBatch, BaseTestRadiusCheck,
                                                      BaseTestRadiusGroupCheck, BaseTestRadiusGroupReply,
                                                      BaseTestRadiusPostAuth, BaseTestRadiusProfile,
                                                      BaseTestRadiusReply, BaseTestRadiusUserGroup,
                                                      BaseTestRadiusUserProfile)
from django_freeradius.tests.base.test_utils import BaseTestUtils

from openwisp_users.models import Organization

from .mixins import ApiParamsMixin, CallCommandMixin, CreateRadiusObjectsMixin
from .models import (Nas, RadiusAccounting, RadiusBatch, RadiusCheck, RadiusGroupCheck, RadiusGroupReply,
                     RadiusPostAuth, RadiusProfile, RadiusReply, RadiusUserGroup, RadiusUserProfile)

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


class TestRadiusGroupReply(BaseTestRadiusGroupReply, BaseTestCase):
    radius_groupreply_model = RadiusGroupReply


class TestRadiusGroupCheck(BaseTestRadiusGroupCheck, BaseTestCase):
    radius_groupcheck_model = RadiusGroupCheck


class TestRadiusUserGroup(BaseTestRadiusUserGroup, BaseTestCase):
    radius_usergroup_model = RadiusUserGroup


class TestRadiusPostAuth(BaseTestRadiusPostAuth, BaseTestCase):
    radius_postauth_model = RadiusPostAuth


class TestRadiusBatch(BaseTestRadiusBatch, BaseTestCase):
    radius_batch_model = RadiusBatch


class TestRadiusProfile(BaseTestRadiusProfile, BaseTestCase):
    radius_profile_model = RadiusProfile


class TestRadiusUserProfile(BaseTestRadiusUserProfile, BaseTestCase):
    radius_profile_model = RadiusProfile
    radius_userprofile_model = RadiusUserProfile
    radius_check_model = RadiusCheck


class TestAdmin(BaseTestAdmin, BaseTestCase,
                FileMixin, CallCommandMixin):
    app_name = "openwisp_radius"
    nas_model = Nas
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    radius_check_model = RadiusCheck
    radius_groupcheck_model = RadiusGroupCheck
    radius_groupreply_model = RadiusGroupReply
    radius_postauth_model = RadiusPostAuth
    radius_reply_model = RadiusReply
    radius_usergroup_model = RadiusUserGroup
    radius_profile_model = RadiusProfile

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


auth_header = 'Bearer {}'.format(settings.DJANGO_FREERADIUS_API_TOKEN)


class TestApi(BaseTestApi, ApiParamsMixin, BaseTestCase):
    radius_postauth_model = RadiusPostAuth
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    user_model = get_user_model()
    auth_header = auth_header

    def setUp(self):
        self._create_org()


class TestApiReject(BaseTestApiReject, BaseTestCase):
    auth_header = auth_header


class TestCommands(BaseTestCommands, BaseTestCase,
                   FileMixin, CallCommandMixin):
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    radius_postauth_model = RadiusPostAuth


class TestCSVUpload(BaseTestCSVUpload, TestCase,
                    CreateRadiusObjectsMixin, FileMixin):
    radius_batch_model = RadiusBatch


class TestUtils(BaseTestUtils, FileMixin, BaseTestCase):
    pass
