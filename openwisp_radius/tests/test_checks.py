from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase

from openwisp_radius import checks
from openwisp_radius.registration import (
    register_registration_method,
    unregister_registration_method,
    validate_user_settable_registration_methods,
)


class TestChecks(TestCase):
    @patch("openwisp_radius.settings.SOCIAL_REGISTRATION_CONFIGURED", False)
    def test_check_social_registration_enabled(self):
        with patch("openwisp_radius.settings.SOCIAL_REGISTRATION_ENABLED", False):
            error_list = checks.check_social_registration_enabled(None)
            self.assertEqual(len(error_list), 0)

        with patch("openwisp_radius.settings.SOCIAL_REGISTRATION_ENABLED", True):
            error_list = checks.check_social_registration_enabled(None)
            self.assertEqual(len(error_list), 1)
            error = error_list.pop()
            self.assertEqual(error.msg, "Improperly Configured")
            self.assertIn("OPENWISP_RADIUS_SOCIAL_REGISTRATION_ENABLED", error.hint)

    @patch("openwisp_radius.settings.SAML_REGISTRATION_CONFIGURED", False)
    def test_check_saml_registration_enabled(self):
        with patch("openwisp_radius.settings.SAML_REGISTRATION_ENABLED", False):
            error_list = checks.check_saml_registration_enabled(None)
            self.assertEqual(len(error_list), 0)

        with patch("openwisp_radius.settings.SAML_REGISTRATION_ENABLED", True):
            error_list = checks.check_saml_registration_enabled(None)
            self.assertEqual(len(error_list), 1)
            error = error_list.pop()
            self.assertEqual(error.msg, "Improperly Configured")
            self.assertIn("OPENWISP_RADIUS_SAML_REGISTRATION_ENABLED", error.hint)

    def test_check_user_settable_registration_methods(self):
        with self.subTest("default methods are valid and preserve order"):
            choices = validate_user_settable_registration_methods(
                ["", "email", "mobile_phone"]
            )
            self.assertEqual(
                choices,
                [
                    ("", "Unspecified"),
                    ("email", "Email"),
                    ("mobile_phone", "Mobile phone"),
                ],
            )
            with patch(
                "openwisp_radius.settings.USER_SETTABLE_REGISTRATION_METHODS",
                ["", "email", "mobile_phone"],
            ):
                error_list = checks.check_user_settable_registration_methods(None)
                self.assertEqual(len(error_list), 0)

        with self.subTest("non list or tuple is rejected"):
            with self.assertRaises(ImproperlyConfigured) as error:
                validate_user_settable_registration_methods("email")
            self.assertEqual("list or tuple" in str(error.exception), True)
            with patch(
                "openwisp_radius.settings.USER_SETTABLE_REGISTRATION_METHODS",
                "email",
            ):
                error_list = checks.check_user_settable_registration_methods(None)
                self.assertEqual(len(error_list), 1)
                self.assertEqual(error_list[0].msg, "Improperly Configured")
                self.assertEqual(
                    "list or tuple" in error_list[0].hint,
                    True,
                )

        with self.subTest("duplicate methods are rejected"):
            with self.assertRaises(ImproperlyConfigured) as error:
                validate_user_settable_registration_methods(["email", "email"])
            self.assertEqual("duplicate" in str(error.exception), True)
            with patch(
                "openwisp_radius.settings.USER_SETTABLE_REGISTRATION_METHODS",
                ["email", "email"],
            ):
                error_list = checks.check_user_settable_registration_methods(None)
                self.assertEqual(len(error_list), 1)
                self.assertEqual(error_list[0].msg, "Improperly Configured")
                self.assertEqual("duplicate" in error_list[0].hint, True)

        with self.subTest("unknown methods are rejected"):
            with self.assertRaises(ImproperlyConfigured) as error:
                validate_user_settable_registration_methods(["not_registered_method"])
            self.assertEqual("unknown" in str(error.exception), True)
            with patch(
                "openwisp_radius.settings.USER_SETTABLE_REGISTRATION_METHODS",
                ["not_registered_method"],
            ):
                error_list = checks.check_user_settable_registration_methods(None)
                self.assertEqual(len(error_list), 1)
                self.assertEqual(error_list[0].msg, "Improperly Configured")
                self.assertEqual("unknown" in error_list[0].hint, True)

        custom_method = "custom_identity"
        register_registration_method(custom_method, "Custom Identity", fail_loud=False)
        try:
            with self.subTest("custom registered methods are accepted"):
                choices = validate_user_settable_registration_methods(
                    ["", custom_method, "email"]
                )
                self.assertEqual(
                    choices,
                    [
                        ("", "Unspecified"),
                        (custom_method, "Custom Identity"),
                        ("email", "Email"),
                    ],
                )
                with patch(
                    "openwisp_radius.settings.USER_SETTABLE_REGISTRATION_METHODS",
                    [custom_method],
                ):
                    error_list = checks.check_user_settable_registration_methods(None)
                    self.assertEqual(len(error_list), 0)
        finally:
            unregister_registration_method(custom_method, fail_loud=False)
