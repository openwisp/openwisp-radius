from openwisp_radius import settings as app_settings
from openwisp_utils.tests import capture_any_output

from ...utils import get_organization_radius_settings, load_model
from ..mixins import BaseTestCase

OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')


class TestUtils(BaseTestCase):
    @capture_any_output()
    def test_is_saml_authentication_enabled(self):
        org = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=org)

        with self.subTest('Test saml_registration_enabled set to True'):
            org.radius_settings.saml_registration_enabled = True
            self.assertEqual(
                get_organization_radius_settings(org, 'saml_registration_enabled'), True
            )

        with self.subTest('Test saml_registration_enabled set to False'):
            org.radius_settings.saml_registration_enabled = False
            self.assertEqual(
                get_organization_radius_settings(org, 'saml_registration_enabled'),
                False,
            )

        with self.subTest('Test saml_registration_enabled set to None'):
            org.radius_settings.saml_registration_enabled = None
            self.assertEqual(
                get_organization_radius_settings(org, 'saml_registration_enabled'),
                app_settings.SAML_REGISTRATION_ENABLED,
            )

        with self.subTest('Test related radius setting does not exist'):
            org.radius_settings = None
            with self.assertRaises(Exception) as context_manager:
                get_organization_radius_settings(org, 'saml_registration_enabled')
            self.assertEqual(
                str(context_manager.exception),
                'Could not complete operation because of an internal misconfiguration',
            )
