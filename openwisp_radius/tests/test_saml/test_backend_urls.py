from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import resolve
from djangosaml2.views import LoginView

from openwisp_radius.saml.backends import OpenwispRadiusSaml2Backend
from openwisp_radius.saml.urls import get_saml_urls
from openwisp_radius.tests.test_saml.test_views import TestSamlMixin


class TestSamlBackendUrls(TestSamlMixin, TestCase):
    def test_update_user_skip_non_saml(self):
        user = self._create_user(username="test-user")
        backend = OpenwispRadiusSaml2Backend()

        import swapper

        RegisteredUser = swapper.load_model("openwisp_radius", "RegisteredUser")
        RegisteredUser.objects.create(user=user, method="manual")

        attributes = {"uid": ["new-username"]}
        attribute_mapping = {"username": ("uid",)}

        with patch(
            "openwisp_radius.settings.SAML_UPDATES_PRE_EXISTING_USERNAME", False
        ):
            with patch(
                "djangosaml2.backends.Saml2Backend._update_user"
            ) as mock_super_update:
                backend._update_user(user, attributes, attribute_mapping)

                args, _ = mock_super_update.call_args
                passed_mapping = args[2]
                self.assertNotIn("username", passed_mapping)

    def test_update_user_complex_mapping(self):
        user = self._create_user(username="test-user")
        backend = OpenwispRadiusSaml2Backend()

        import swapper

        RegisteredUser = swapper.load_model("openwisp_radius", "RegisteredUser")
        RegisteredUser.objects.create(user=user, method="manual")

        attributes = {"uid": ["new-username"], "email": ["test@example.com"]}
        attribute_mapping = {"user_data": ("username", "email")}

        with patch(
            "openwisp_radius.settings.SAML_UPDATES_PRE_EXISTING_USERNAME", False
        ):
            with patch(
                "djangosaml2.backends.Saml2Backend._update_user"
            ) as mock_super_update:
                backend._update_user(user, attributes, attribute_mapping)

                args, _ = mock_super_update.call_args
                passed_mapping = args[2]
                self.assertIn("user_data", passed_mapping)
                self.assertEqual(passed_mapping["user_data"], ["email"])

    def test_update_user_exception_handling(self):
        user = self._create_user(username="test-user")
        backend = OpenwispRadiusSaml2Backend()

        attributes = {"uid": ["new-username"]}
        attribute_mapping = {"username": ("uid",)}

        with patch(
            "openwisp_radius.settings.SAML_UPDATES_PRE_EXISTING_USERNAME", False
        ):
            with patch(
                "djangosaml2.backends.Saml2Backend._update_user"
            ) as mock_super_update:
                backend._update_user(user, attributes, attribute_mapping)

                mock_super_update.assert_called_once()

    def test_get_saml_urls_not_configured(self):
        with patch("openwisp_radius.settings.SAML_REGISTRATION_CONFIGURED", False):
            urls = get_saml_urls()
            self.assertEqual(urls, [])

    @override_settings(ROOT_URLCONF=__name__)
    def test_get_saml_urls_configured(self):
        with patch("openwisp_radius.settings.SAML_REGISTRATION_CONFIGURED", True):
            urls = get_saml_urls()
            self.assertTrue(len(urls) > 0)
            login_url_found = any(p.name == "saml2_login" for p in urls)
            self.assertTrue(login_url_found)

    def test_import_views_inside_function(self):
        with patch("openwisp_radius.settings.SAML_REGISTRATION_CONFIGURED", True):
            urls = get_saml_urls(saml_views=None)
            self.assertTrue(len(urls) > 0)
