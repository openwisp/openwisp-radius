from rest_framework.exceptions import APIException

from openwisp_utils.tests import capture_any_output

from ... import settings as app_settings
from ...api.utils import is_registration_enabled, is_sms_verification_enabled
from ...utils import load_model
from ..mixins import BaseTestCase

OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')


class TestUtils(BaseTestCase):
    @capture_any_output()
    def test_is_registration_enabled(self):
        org = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=org)

        with self.subTest('Test registration enabled set to True'):
            org.radius_settings.registration_enabled = True
            self.assertEqual(is_registration_enabled(org), True)

        with self.subTest('Test registration enabled set to False'):
            org.radius_settings.registration_enabled = False
            self.assertEqual(is_registration_enabled(org), False)

        with self.subTest('Test registration enabled set to None'):
            org.radius_settings.registration_enabled = None
            self.assertEqual(
                is_registration_enabled(org),
                app_settings.REGISTRATION_API_ENABLED,
            )

        with self.subTest('Test related radius setting does not exist'):
            org.radius_settings = None
            with self.assertRaises(APIException) as context_manager:
                is_registration_enabled(org)
            self.assertEqual(
                str(context_manager.exception),
                'Could not complete operation because of an internal misconfiguration',
            )

    def test_is_sms_verification_enabled(self):
        org = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=org)

        with self.subTest('Test sms verification enabled set to True'):
            org.radius_settings.sms_verification = True
            self.assertEqual(is_sms_verification_enabled(org), True)

        with self.subTest('Test sms verification enabled set to False'):
            org.radius_settings.sms_verification = False
            self.assertEqual(is_sms_verification_enabled(org), False)

        with self.subTest('Test sms verification enabled set to None'):
            org.radius_settings.sms_verification = None
            self.assertEqual(
                is_sms_verification_enabled(org),
                app_settings.SMS_VERIFICATION_ENABLED,
            )

        with self.subTest('Test related radius setting does not exist'):
            org.radius_settings = None
            with self.assertRaises(APIException) as context_manager:
                is_sms_verification_enabled(org)
            self.assertEqual(
                str(context_manager.exception),
                'Could not complete operation because of an internal misconfiguration',
            )
