from rest_framework.exceptions import APIException

from openwisp_utils.tests import capture_any_output

from ... import settings as app_settings
from ...utils import get_organization_radius_settings, load_model
from ..mixins import BaseTestCase

OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')


class TestUtils(BaseTestCase):
    @capture_any_output()
    def test_is_registration_enabled(self):
        org = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=org)

        with self.subTest('Test registration enabled set to True'):
            org.radius_settings.registration_enabled = True
            self.assertEqual(
                get_organization_radius_settings(org, 'registration_enabled'), True
            )

        with self.subTest('Test registration enabled set to False'):
            org.radius_settings.registration_enabled = False
            self.assertEqual(
                get_organization_radius_settings(org, 'registration_enabled'), False
            )

        with self.subTest('Test registration enabled set to None'):
            org.radius_settings.registration_enabled = None
            self.assertEqual(
                get_organization_radius_settings(org, 'registration_enabled'),
                app_settings.REGISTRATION_API_ENABLED,
            )

        with self.subTest('Test related radius setting does not exist'):
            org.radius_settings = None
            with self.assertRaises(APIException) as context_manager:
                get_organization_radius_settings(org, 'registration_enabled')
            self.assertEqual(
                str(context_manager.exception),
                'Could not complete operation because of an internal misconfiguration',
            )

    @capture_any_output()
    def test_is_sms_verification_enabled(self):
        org = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=org)

        with self.subTest('Test sms verification enabled set to True'):
            org.radius_settings.sms_verification = True
            self.assertEqual(
                get_organization_radius_settings(org, 'sms_verification'), True
            )

        with self.subTest('Test sms verification enabled set to False'):
            org.radius_settings.sms_verification = False
            self.assertEqual(
                get_organization_radius_settings(org, 'sms_verification'), False
            )

        with self.subTest('Test sms verification enabled set to None'):
            org.radius_settings.sms_verification = None
            self.assertEqual(
                get_organization_radius_settings(org, 'sms_verification'),
                app_settings.SMS_VERIFICATION_ENABLED,
            )

        with self.subTest('Test related radius setting does not exist'):
            org.radius_settings = None
            with self.assertRaises(APIException) as context_manager:
                get_organization_radius_settings(org, 'sms_verification')
            self.assertEqual(
                str(context_manager.exception),
                'Could not complete operation because of an internal misconfiguration',
            )
