from io import StringIO
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import override_settings

from .. import settings as app_settings
from ..utils import (
    MAC_ADDRESS_FORMATS,
    find_available_username,
    format_mac_address,
    get_one_time_login_url,
    mac_address_variants,
    mask_phone_number,
    normalize_mac_address,
    validate_csvfile,
)
from . import FileMixin
from .mixins import BaseTestCase


class TestUtils(FileMixin, BaseTestCase):
    def test_format_mac_address(self):
        for mac_format, expected in (
            ("colon", "00:27:22:f3:fa:f1"),
            ("hyphen", "00-27-22-f3-fa-f1"),
            ("dotted", "0027.22f3.faf1"),
            ("plain", "002722f3faf1"),
        ):
            with self.subTest(mac_format=mac_format):
                for value in (
                    "00:27:22:F3:FA:F1",
                    "00-27-22-F3-FA-F1",
                    "0027.22F3.FAF1",
                    "002722F3FAF1",
                ):
                    with self.subTest(value=value):
                        self.assertEqual(
                            format_mac_address(value, mac_format), expected
                        )

    def test_format_mac_address_preserves_suffix(self):
        self.assertEqual(
            format_mac_address("00-27-22-F3-FA-F1:hostname", "colon"),
            "00:27:22:f3:fa:f1:hostname",
        )
        self.assertEqual(
            format_mac_address("0027.22F3.FAF1:SSID", "dotted"),
            "0027.22f3.faf1:SSID",
        )
        self.assertEqual(
            format_mac_address(
                "00-27-22-F3-FA-F1:hostname", "colon", keep_suffix=False
            ),
            "00:27:22:f3:fa:f1",
        )

    def test_format_mac_address_returns_invalid_values_unchanged(self):
        for value in (
            None,
            "",
            "not-a-mac",
            "192.168.1.1",
            "fe80::1",
            "002722F3FAF1AABB",
            "00-27-22-F3-FA-F1-hostname",
            "00:27:22:ff:fe:f3:fa:f1",
        ):
            for mac_format in MAC_ADDRESS_FORMATS:
                with self.subTest(value=value, mac_format=mac_format):
                    self.assertEqual(format_mac_address(value, mac_format), value)
        with self.assertRaises(ValueError):
            format_mac_address("00:27:22:F3:FA:F1", "invalid")
        with self.assertRaises(ValueError):
            format_mac_address("00:27:22:F3:FA:F1", ["colon"])

    def test_normalize_mac_address(self):
        with self.subTest("configured format"):
            with mock.patch.object(app_settings, "MAC_ADDRESS_FORMAT", "colon"):
                self.assertEqual(
                    normalize_mac_address("00-27-22-F3-FA-F1"),
                    "00:27:22:f3:fa:f1",
                )

        with self.subTest("disabled"):
            with mock.patch.object(app_settings, "MAC_ADDRESS_FORMAT", None):
                self.assertEqual(
                    normalize_mac_address("00-27-22-F3-FA-F1"),
                    "00-27-22-F3-FA-F1",
                )

        with self.subTest("invalid format"):
            with mock.patch.object(app_settings, "MAC_ADDRESS_FORMAT", "invalid"):
                self.assertEqual(
                    normalize_mac_address("00-27-22-F3-FA-F1"),
                    "00-27-22-F3-FA-F1",
                )

        with self.subTest("unhashable format"):
            with mock.patch.object(app_settings, "MAC_ADDRESS_FORMAT", ["colon"]):
                self.assertEqual(
                    normalize_mac_address("00-27-22-F3-FA-F1"),
                    "00-27-22-F3-FA-F1",
                )

    def test_normalize_mac_address_is_idempotent(self):
        with mock.patch.object(app_settings, "MAC_ADDRESS_FORMAT", "dotted"):
            normalized = normalize_mac_address("AA:BB:CC:DD:EE:FF:SSID")
            self.assertEqual(normalized, "aabb.ccdd.eeff:SSID")
            self.assertEqual(normalize_mac_address(normalized), normalized)

    def test_mac_address_variants(self):
        self.assertEqual(
            mac_address_variants("00-27-22-F3-FA-F1"),
            {
                "00-27-22-F3-FA-F1",
                "00:27:22:f3:fa:f1",
                "00-27-22-f3-fa-f1",
                "0027.22f3.faf1",
                "002722f3faf1",
                "00:27:22:F3:FA:F1",
                "0027.22F3.FAF1",
                "002722F3FAF1",
            },
        )
        self.assertIn(
            "00:27:22:F3:FA:F1:hostname",
            mac_address_variants("00-27-22-F3-FA-F1:hostname"),
        )
        self.assertEqual(mac_address_variants("not-a-mac"), {"not-a-mac"})
        self.assertEqual(mac_address_variants(None), {None})

    def test_mask_phone_number(self):
        for phone_number, expected in (
            ("+39 366 435 1808", "+39******1808"),
            ("+1 202 555 1234", "+1******1234"),
        ):
            with self.subTest(phone_number=phone_number):
                self.assertEqual(mask_phone_number(phone_number), expected)

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

    def test_validate_csvfile_rejects_radius_group_column(self):
        csvfile = StringIO("user,password,user@example.com,First,Last,radius-group")
        with self.assertRaises(ValidationError) as error:
            validate_csvfile(csvfile)
        self.assertIn("Improper CSV format", error.exception.message)

    @override_settings(AUTHENTICATION_BACKENDS=[])
    def test_get_one_time_login_url(self):
        login_url = get_one_time_login_url(None, None)
        self.assertEqual(login_url, None)
