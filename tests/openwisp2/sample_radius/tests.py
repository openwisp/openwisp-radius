from openwisp_radius.tests.test_admin import TestAdmin as BaseTestAdmin
from openwisp_radius.tests.test_api.test_api import TestApi as BaseTestApi
from openwisp_radius.tests.test_api.test_freeradius_api import (
    TestApiReject as BaseTestApiReject,
)
from openwisp_radius.tests.test_api.test_freeradius_api import (
    TestAutoGroupname as BaseTestAutoGroupname,
)
from openwisp_radius.tests.test_api.test_freeradius_api import (
    TestAutoGroupnameDisabled as BaseTestAutoGroupnameDisabled,
)
from openwisp_radius.tests.test_api.test_freeradius_api import (
    TestFreeradiusApi as BaseTestFreeradiusApi,
)
from openwisp_radius.tests.test_api.test_freeradius_api import (
    TestOgranizationRadiusSettings as BaseTestOgranizationRadiusSettings,
)
from openwisp_radius.tests.test_api.test_phone_verification import (
    TestIsSmsVerificationEnabled as BaseTestIsSmsVerificationEnabled,
)
from openwisp_radius.tests.test_api.test_phone_verification import (
    TestPhoneVerification as BaseTestPhoneVerification,
)
from openwisp_radius.tests.test_api.test_rest_token import (
    TestApiUserToken as BaseTestApiUserToken,
)
from openwisp_radius.tests.test_api.test_rest_token import (
    TestApiValidateToken as BaseTestApiValidateToken,
)
from openwisp_radius.tests.test_batch_add_users import (
    TestCSVUpload as BaseTestCSVUpload,
)
from openwisp_radius.tests.test_commands import TestCommands as BaseTestCommands
from openwisp_radius.tests.test_models import TestNas as BaseTestNas
from openwisp_radius.tests.test_models import (
    TestOrganizationRadiusSettings as BaseTestOrganizationRadiusSettings,
)
from openwisp_radius.tests.test_models import (
    TestPrivateCsvFile as BaseTestPrivateCsvFile,
)
from openwisp_radius.tests.test_models import (
    TestRadiusAccounting as BaseTestRadiusAccounting,
)
from openwisp_radius.tests.test_models import TestRadiusBatch as BaseTestRadiusBatch
from openwisp_radius.tests.test_models import TestRadiusCheck as BaseTestRadiusCheck
from openwisp_radius.tests.test_models import TestRadiusGroup as BaseTestRadiusGroup
from openwisp_radius.tests.test_models import (
    TestRadiusPostAuth as BaseTestRadiusPostAuth,
)
from openwisp_radius.tests.test_models import TestRadiusReply as BaseTestRadiusReply
from openwisp_radius.tests.test_saml.test_views import (
    TestAssertionConsumerServiceView as BaseTestAssertionConsumerServiceView,
)
from openwisp_radius.tests.test_saml.test_views import (
    TestLoginView as BaseTestLoginView,
)
from openwisp_radius.tests.test_social import TestSocial as BaseTestSocial
from openwisp_radius.tests.test_token import TestPhoneToken as BaseTestPhoneToken
from openwisp_radius.tests.test_token import TestRadiusToken as BaseTestRadiusToken
from openwisp_radius.tests.test_upgrader_script import (
    TestUpgradeFromDjangoFreeradius as BaseTestUpgradeFromDjangoFreeradius,
)
from openwisp_radius.tests.test_users_integration import (
    TestUsersIntegration as BaseTestUsersIntegration,
)
from openwisp_radius.tests.test_utils import TestUtils as BaseTestUtils

additional_fields = [
    ('social_security_number', '123-45-6789'),
]


class TestAdmin(BaseTestAdmin):
    app_label_users = 'sample_users'
    app_label = 'sample_radius'


class TestApi(BaseTestApi):
    pass


class TestFreeradiusApi(BaseTestFreeradiusApi):
    pass


class TestApiReject(BaseTestApiReject):
    pass


class TestAutoGroupname(BaseTestAutoGroupname):
    pass


class TestAutoGroupnameDisabled(BaseTestAutoGroupnameDisabled):
    pass


class TestOgranizationRadiusSettings(BaseTestOgranizationRadiusSettings):
    pass


class TestPhoneVerification(BaseTestPhoneVerification):
    pass


class TestIsSmsVerificationEnabled(BaseTestIsSmsVerificationEnabled):
    pass


class TestCSVUpload(BaseTestCSVUpload):
    pass


class TestCommands(BaseTestCommands):
    pass


class TestNas(BaseTestNas):
    pass


class TestUpgradeFromDjangoFreeradius(BaseTestUpgradeFromDjangoFreeradius):
    pass


class TestRadiusAccounting(BaseTestRadiusAccounting):
    pass


class TestRadiusCheck(BaseTestRadiusCheck):
    pass


class TestRadiusReply(BaseTestRadiusReply):
    pass


class TestRadiusPostAuth(BaseTestRadiusPostAuth):
    pass


class TestPrivateCsvFile(BaseTestPrivateCsvFile):
    pass


class TestRadiusGroup(BaseTestRadiusGroup):
    pass


class TestRadiusBatch(BaseTestRadiusBatch):
    pass


class TestUtils(BaseTestUtils):
    pass


class TestUsersIntegration(BaseTestUsersIntegration):
    app_label = 'sample_users'
    _additional_user_fields = additional_fields


class TestRadiusToken(BaseTestRadiusToken):
    pass


class TestPhoneToken(BaseTestPhoneToken):
    pass


class TestSocial(BaseTestSocial):
    pass


class TestApiUserToken(BaseTestApiUserToken):
    pass


class TestApiValidateToken(BaseTestApiValidateToken):
    pass


class TestOrganizationRadiusSettings(BaseTestOrganizationRadiusSettings):
    pass


class TestAssertionConsumerServiceView(BaseTestAssertionConsumerServiceView):
    pass


class TestLoginView(BaseTestLoginView):
    pass


del BaseTestAdmin
del BaseTestApi
del BaseTestFreeradiusApi
del BaseTestApiReject
del BaseTestAutoGroupname
del BaseTestAutoGroupnameDisabled
del BaseTestApiUserToken
del BaseTestApiValidateToken
del BaseTestOgranizationRadiusSettings
del BaseTestPhoneVerification
del BaseTestIsSmsVerificationEnabled
del BaseTestCSVUpload
del BaseTestCommands
del BaseTestNas
del BaseTestRadiusAccounting
del BaseTestRadiusCheck
del BaseTestRadiusReply
del BaseTestRadiusPostAuth
del BaseTestPrivateCsvFile
del BaseTestRadiusGroup
del BaseTestRadiusBatch
del BaseTestSocial
del BaseTestRadiusToken
del BaseTestPhoneToken
del BaseTestUsersIntegration
del BaseTestUtils
del BaseTestUpgradeFromDjangoFreeradius
del BaseTestOrganizationRadiusSettings
del BaseTestAssertionConsumerServiceView
del BaseTestLoginView
