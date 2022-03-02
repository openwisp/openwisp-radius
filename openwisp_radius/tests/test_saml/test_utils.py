from openwisp_radius import settings as app_settings
from openwisp_radius.saml.utils import is_saml_authentication_enabled

from ...utils import load_model
from ..mixins import BaseTestCase

OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')


class TestUtils(BaseTestCase):
    def test_is_saml_authentication_enabled(self):
        org = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=org)

        with self.subTest('Test saml_registration_enabled set to True'):
            org.radius_settings.saml_registration_enabled = True
            self.assertEqual(is_saml_authentication_enabled(org), True)

        with self.subTest('Test saml_registration_enabled set to False'):
            org.radius_settings.saml_registration_enabled = False
            self.assertEqual(is_saml_authentication_enabled(org), False)

        with self.subTest('Test saml_registration_enabled set to None'):
            org.radius_settings.saml_registration_enabled = None
            self.assertEqual(
                is_saml_authentication_enabled(org),
                app_settings.SAML_REGISTRATION_ENABLED,
            )

        with self.subTest('Test related radius setting does not exist'):
            org.radius_settings = None
            with self.assertRaises(Exception) as context_manager:
                is_saml_authentication_enabled(org)
            self.assertEqual(
                str(context_manager.exception),
                'Could not complete operation because of an internal misconfiguration',
            )
