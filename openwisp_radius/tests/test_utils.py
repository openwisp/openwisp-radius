from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.test import override_settings

from ..registration import (
    register_registration_method,
    unregister_registration_method,
    validate_user_settable_registration_methods,
)
from ..utils import find_available_username, get_one_time_login_url, validate_csvfile
from . import FileMixin
from .mixins import BaseTestCase


class TestUtils(FileMixin, BaseTestCase):
    def test_find_available_username(self):
        User = get_user_model()
        User.objects.create(username="rohith", password="password")
        self.assertEqual(find_available_username("rohith", []), "rohith1")
        User.objects.create(username="rohith1", password="password")
        self.assertEqual(find_available_username("rohith", []), "rohith2")

    def test_validate_file_format(self):
        invalid_format_path = self._get_path("static/test_batch_invalid_format.pdf")
        with self.assertRaises(ValidationError) as error:
            validate_csvfile(open(invalid_format_path, "rb"))
        self.assertTrue(
            "Unrecognized file format, the supplied file does not look like a CSV file."
            in error.exception.message
        )

    def test_validate_utf16_file_format(self):
        utf_16_file_1_format_path = self._get_path("static/test_batch_utf16_file1.csv")
        assert validate_csvfile(open(utf_16_file_1_format_path, "rb")) is None

        utf_16_file_2_format_path = self._get_path("static/test_batch_utf16_file2.csv")
        assert validate_csvfile(open(utf_16_file_2_format_path, "rb")) is None

    def test_validate_utf8Sig_file_format(self):
        utf_16_file_2_format_path = self._get_path(
            "static/test_batch_utf8Sig_file2.csv"
        )
        assert validate_csvfile(open(utf_16_file_2_format_path, "rb")) is None

    def test_validate_csvfile(self):
        invalid_csv_path = self._get_path("static/test_batch_invalid.csv")
        improper_csv_path = self._get_path("static/test_batch_improper.csv")
        with self.assertRaises(ValidationError) as error:
            validate_csvfile(open(invalid_csv_path, "rt"))
        self.assertTrue("Enter a valid email address" in error.exception.message)
        with self.assertRaises(ValidationError) as error:
            validate_csvfile(open(improper_csv_path, "rt"))
        self.assertTrue("Improper CSV format" in error.exception.message)

    @override_settings(AUTHENTICATION_BACKENDS=[])
    def test_get_one_time_login_url(self):
        login_url = get_one_time_login_url(None, None)
        self.assertEqual(login_url, None)

    def test_validate_user_settable_registration_methods(self):
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

        with self.subTest("non list or tuple is rejected"):
            with self.assertRaises(ImproperlyConfigured) as error:
                validate_user_settable_registration_methods("email")
            self.assertEqual(
                "list or tuple" in str(error.exception),
                True,
            )

        with self.subTest("duplicate methods are rejected"):
            with self.assertRaises(ImproperlyConfigured) as error:
                validate_user_settable_registration_methods(["email", "email"])
            self.assertEqual("duplicate" in str(error.exception), True)

        with self.subTest("unknown methods are rejected"):
            with self.assertRaises(ImproperlyConfigured) as error:
                validate_user_settable_registration_methods(["not_registered_method"])
            self.assertEqual("unknown" in str(error.exception), True)

        custom_method = "custom_identity"
        register_registration_method(custom_method, "Custom Identity")
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
        finally:
            unregister_registration_method(custom_method)
