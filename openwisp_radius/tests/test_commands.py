import os
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.utils.timezone import get_default_timezone, now
from netaddr import EUI, mac_unix
from openvpn_status.models import Routing

from openwisp_utils.tests import capture_any_output, capture_stdout

from .. import settings as app_settings
from ..utils import load_model
from . import _RADACCT, CallCommandMixin, FileMixin
from .mixins import BaseTestCase

User = get_user_model()
RadiusAccounting = load_model("RadiusAccounting")
RadiusBatch = load_model("RadiusBatch")
RadiusPostAuth = load_model("RadiusPostAuth")
RegisteredUser = load_model("RegisteredUser")


class TestCommands(FileMixin, CallCommandMixin, BaseTestCase):
    @capture_any_output()
    def test_cleanup_stale_radacct_command(self):
        options = _RADACCT.copy()

        with self.subTest(
            "Test update_time unset and start_time older than specified time"
        ):
            options["unique_id"] = "117"
            options["update_time"] = None
            options["start_time"] = "2017-06-10 10:50:00"
            self._create_radius_accounting(**options)
            call_command("cleanup_stale_radacct", 1)
            session = RadiusAccounting.objects.get(unique_id="117")
            self.assertNotEqual(session.stop_time, None)
            self.assertNotEqual(session.session_time, None)
            self.assertEqual(session.update_time, session.stop_time)
            self.assertEqual(session.terminate_cause, "Session Timeout")

        with self.subTest(
            "Test start_time older than specified time but update_time is recent"
        ):
            update_time = now()
            options["unique_id"] = "118"
            options["start_time"] = "2017-06-10 10:50:00"
            options["update_time"] = str(update_time)
            self._create_radius_accounting(**options)
            call_command("cleanup_stale_radacct", 1)
            session = RadiusAccounting.objects.get(unique_id="118")
            self.assertEqual(session.stop_time, None)
            self.assertEqual(session.session_time, None)
            self.assertEqual(session.update_time, update_time)
            self.assertEqual(session.terminate_cause, None)

        with self.subTest("Test start_time and update_time older than specified time"):
            options["unique_id"] = "119"
            options["update_time"] = "2017-06-10 10:50:00"
            options["start_time"] = "2017-06-10 10:50:00"
            self._create_radius_accounting(**options)
            call_command("cleanup_stale_radacct", 1)
            session = RadiusAccounting.objects.get(unique_id="119")
            self.assertNotEqual(session.stop_time, None)
            self.assertNotEqual(session.session_time, None)
            self.assertEqual(session.update_time, session.stop_time)
            self.assertEqual(session.terminate_cause, "Session Timeout")

        with self.subTest("Test does not affect closed session"):
            options["unique_id"] = "120"
            options["start_time"] = "2017-06-10 10:50:00"
            options["update_time"] = "2017-06-10 10:55:00"
            options["stop_time"] = "2017-06-10 10:55:00"
            self._create_radius_accounting(**options)
            call_command("cleanup_stale_radacct", 1)
            session = RadiusAccounting.objects.get(unique_id="120")
            self.assertEqual(
                session.stop_time.astimezone(get_default_timezone()).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "2017-06-10 10:55:00",
            )
            self.assertEqual(session.update_time, session.stop_time)
            self.assertNotEqual(session.terminate_cause, "Session Timeout")

    @capture_any_output()
    def test_delete_old_postauth_command(self):
        options = dict(username="steve", password="jones", reply="value1")
        self._create_radius_postauth(**options)
        RadiusPostAuth.objects.filter(username="steve").update(date="2017-06-10")
        call_command("delete_old_postauth", 3)
        self.assertEqual(RadiusPostAuth.objects.filter(username="steve").count(), 0)

    @capture_any_output()
    def test_delete_old_radacct_command(self):
        options = _RADACCT.copy()
        options["stop_time"] = "2017-06-10 11:50:00"
        options["update_time"] = "2017-03-10 11:50:00"
        options["unique_id"] = "666"
        self._create_radius_accounting(**options)
        call_command("delete_old_radacct", 3)
        self.assertEqual(RadiusAccounting.objects.filter(unique_id="666").count(), 0)

    @capture_stdout()
    def test_batch_add_users_command(self):
        self.assertEqual(RadiusBatch.objects.all().count(), 0)
        path = self._get_path("static/test_batch.csv")
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration="28-01-2018",
            name="test",
        )
        self._call_command("batch_add_users", **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        radiusbatch = RadiusBatch.objects.first()
        self.assertEqual(get_user_model().objects.all().count(), 3)
        self.assertEqual(radiusbatch.expiration_date.strftime("%d-%m-%y"), "28-01-18")
        path = self._get_path("static/test_batch_new.csv")
        options = dict(organization=self.default_org.slug, file=path, name="test1")
        self._call_command("batch_add_users", **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 2)
        self.assertEqual(get_user_model().objects.all().count(), 6)
        invalid_csv_path = self._get_path("static/test_batch_invalid.csv")
        with self.assertRaises(CommandError):
            options = dict(
                organization=self.default_org.slug,
                file="doesnotexist.csv",
                name="test3",
            )
            self._call_command("batch_add_users", **options)
        with self.assertRaises(SystemExit):
            options = dict(
                organization=self.default_org.slug, file=invalid_csv_path, name="test4"
            )
            self._call_command("batch_add_users", **options)

    @capture_stdout()
    def test_deactivate_expired_users_command(self):
        path = self._get_path("static/test_batch.csv")
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration="28-01-1970",
            name="test",
        )
        self._call_command("batch_add_users", **options)
        self.assertEqual(get_user_model().objects.filter(is_active=True).count(), 3)
        call_command("deactivate_expired_users")
        self.assertEqual(get_user_model().objects.filter(is_active=True).count(), 0)

    @capture_stdout()
    def test_delete_old_radiusbatch_users_command(self):
        # Create RadiusBatch users that expired more than 18 months ago
        path = self._get_path("static/test_batch.csv")
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration="28-01-1970",
            name="test",
        )
        self._call_command("batch_add_users", **options)
        # Create RadiusBatch users that expired 15 months ago
        expiration_date = (now() - timedelta(days=30 * 15)).strftime("%d-%m-%Y")
        path = self._get_path("static/test_batch_new.csv")
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration=expiration_date,
            name="test1",
        )
        self._call_command("batch_add_users", **options)
        # Create RadiusBatch users that expired 10 days ago
        path = self._get_path("static/test_batch_users.csv")
        expiration_date = (now() - timedelta(days=10)).strftime("%d-%m-%Y")
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration=expiration_date,
            name="test2",
        )
        self._call_command("batch_add_users", **options)
        self.assertEqual(get_user_model().objects.all().count(), 9)

        with self.subTest("Test executing command without arguments"):
            call_command("delete_old_radiusbatch_users")
            # Only users that expired more than 18 months ago should be deleted
            self.assertEqual(get_user_model().objects.all().count(), 6)

        with self.subTest("Test executing command with older_than_months argument"):
            call_command("delete_old_radiusbatch_users", older_than_months=12)
            # Users that expired more than 12 months ago should be deleted
            self.assertEqual(get_user_model().objects.all().count(), 3)

        with self.subTest("Test executing command with older_than_days argument"):
            call_command("delete_old_radiusbatch_users", older_than_days=9)
            # Users that expired more than 9 days ago should be deleted
            self.assertEqual(get_user_model().objects.all().count(), 0)

        with self.subTest("Test executing command with both arguments"):
            options["name"] = "test3"
            call_command("batch_add_users", **options)
            call_command(
                "delete_old_radiusbatch_users", older_than_days=9, older_than_months=12
            )
            # Users that expired more than 9 days ago should be deleted
            self.assertEqual(get_user_model().objects.all().count(), 0)

    @capture_stdout()
    def test_prefix_add_users_command(self):
        self.assertEqual(RadiusBatch.objects.all().count(), 0)
        output_pdf = os.path.join(settings.MEDIA_ROOT, "test_prefix10.pdf")
        options = dict(
            organization=self.default_org.slug,
            prefix="test-prefix7",
            n=10,
            name="test",
            expiration="28-01-2018",
            output=output_pdf,
        )
        self._call_command("prefix_add_users", **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertTrue(os.path.isfile(output_pdf))
        os.remove(output_pdf)
        radiusbatch = RadiusBatch.objects.first()
        users = get_user_model().objects.all()
        self.assertEqual(users.count(), 10)
        for u in users:
            self.assertTrue("test-prefix7" in u.username)
        self.assertEqual(radiusbatch.expiration_date.strftime("%d-%m-%y"), "28-01-18")
        options = dict(
            organization=self.default_org.slug, prefix="test-prefix8", n=5, name="test1"
        )
        self._call_command("prefix_add_users", **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 2)
        self.assertEqual(get_user_model().objects.all().count(), 15)
        options = dict(
            organization=self.default_org.slug,
            prefix="test-prefix9",
            n=-5,
            name="test2",
        )
        with self.assertRaises(SystemExit):
            self._call_command("prefix_add_users", **options)

    @capture_stdout()
    def test_unverified_users_command(self):
        def _create_old_users():
            User.objects.all().delete()
            RadiusBatch.objects.all().delete()
            path = self._get_path("static/test_batch.csv")
            options = dict(
                organization=self.default_org.slug,
                file=path,
                name="test",
            )
            self._call_command("batch_add_users", **options)
            User.objects.update(date_joined=now() - timedelta(days=3))
            for user in User.objects.all():
                user.registered_user.is_verified = False
                user.registered_user.method = "email"
                user.registered_user.save(update_fields=["is_verified", "method"])

        with self.subTest("Delete unverified users older than 2 days"):
            _create_old_users()
            # This user should not be deleted
            RegisteredUser.objects.create(
                user=self._create_user(), method="mobile_phone", is_verified=False
            )

            self.assertEqual(User.objects.count(), 4)
            call_command("delete_unverified_users", older_than_days=2)
            self.assertEqual(User.objects.count(), 1)

        with self.subTest(
            "Delete unverified users except registered with mobile_phone"
        ):
            _create_old_users()
            # This user should not be deleted
            RegisteredUser.objects.create(
                user=self._create_user(date_joined=now() - timedelta(days=3)),
                method="mobile_phone",
                is_verified=False,
            )

            self.assertEqual(User.objects.count(), 4)
            call_command(
                "delete_unverified_users",
                older_than_days=2,
                exclude_methods="mobile_phone,manual",
            )
            self.assertEqual(User.objects.count(), 1)

        with self.subTest("Verified user should not be deleted"):
            _create_old_users()
            # This user should not be deleted
            RegisteredUser.objects.create(
                user=self._create_user(date_joined=now() - timedelta(days=3)),
                method="email",
                is_verified=True,
            )
            self.assertEqual(User.objects.count(), 4)
            call_command(
                "delete_unverified_users",
            )
            self.assertEqual(User.objects.count(), 1)

        with self.subTest("Users which have accounting sessions should not be deleted"):
            _create_old_users()
            user = self._create_user(date_joined=now() - timedelta(days=3))
            RegisteredUser.objects.create(
                user=user,
                method="email",
                is_verified=False,
            )
            opts = _RADACCT.copy()
            opts["unique_id"] = 1
            opts["username"] = user.username
            self._create_radius_accounting(**opts)
            self.assertEqual(User.objects.count(), 4)
            call_command(
                "delete_unverified_users",
            )
            self.assertEqual(User.objects.count(), 1)
            self.assertEqual(
                RadiusAccounting.objects.filter(username=opts["username"]).exists(),
                True,
            )

        with self.subTest("Staff users should not be deleted"):
            _create_old_users()
            user = self._create_user(
                date_joined=now() - timedelta(days=3), is_staff=True
            )
            RegisteredUser.objects.create(
                user=user,
                method="email",
                is_verified=False,
            )
            self.assertEqual(User.objects.count(), 4)
            call_command(
                "delete_unverified_users",
            )
            self.assertEqual(User.objects.count(), 1)
            self.assertEqual(
                User.objects.filter(username=user.username, is_staff=True).exists(),
                True,
            )

    @capture_any_output()
    @patch.object(
        app_settings,
        "CALLED_STATION_IDS",
        {
            "1e4a8240-cfc8-4af0-88dd-7d487e3f7aa1": {
                "openvpn_config": [
                    {"host": "127.0.0.1", "port": 7505, "password": "somepassword"}
                ],
                "unconverted_ids": ["AA-AA-AA-AA-AA-0A"],
            }
        },
    )
    @patch.object(app_settings, "OPENVPN_DATETIME_FORMAT", "%Y-%m-%d %H:%M:%S")
    @patch("openwisp_radius.tasks.convert_called_station_id")
    def test_convert_called_station_id_command_with_org_id(self, *args):
        org = self._create_org(
            id="1e4a8240-cfc8-4af0-88dd-7d487e3f7aa1",
            name="command test",
            slug="command-test",
        )
        options = _RADACCT.copy()
        options["calling_station_id"] = str(EUI("bb:bb:bb:bb:bb:0b", dialect=mac_unix))
        options["called_station_id"] = "AA-AA-AA-AA-AA-0A"
        options["unique_id"] = "117"
        options["organization"] = org
        radius_acc = self._create_radius_accounting(**options)

        with self.subTest("Test telnet connection error"):
            with patch("logging.Logger.warning") as mocked_logger, patch(
                "openwisp_radius.management.commands.base.convert_called_station_id"
                ".BaseConvertCalledStationIdCommand._get_raw_management_info",
                side_effect=ConnectionRefusedError(),
            ):
                call_command("convert_called_station_id")
                mocked_logger.assert_called_once_with(
                    "Unable to establish telnet connection to 127.0.0.1 on 7505. "
                    "Skipping!"
                )

        with self.subTest("Test telnet raises OSError"):
            with patch("logging.Logger.warning") as mocked_logger, patch(
                "openwisp_radius.management.commands.base.convert_called_station_id"
                ".BaseConvertCalledStationIdCommand._get_raw_management_info",
                side_effect=OSError("[Errno 113] No route to host"),
            ):
                call_command("convert_called_station_id")
                mocked_logger.assert_called_once_with(
                    "Error encountered while connecting to 127.0.0.1:7505: "
                    "[Errno 113] No route to host. Skipping!"
                )

        with self.subTest("Test telnet connection timed out"):
            with patch("logging.Logger.warning") as mocked_logger, patch(
                "openwisp_radius.management.commands.base.convert_called_station_id"
                ".BaseConvertCalledStationIdCommand._get_raw_management_info",
                side_effect=EOFError("EOFError"),
            ):
                call_command("convert_called_station_id")
                mocked_logger.assert_called_once_with(
                    "Error encountered while connecting to 127.0.0.1:7505: "
                    "EOFError. Skipping!"
                )

        with self.subTest("Test telnet password incorrect"):
            # In the case of an incorrect password, OpenVPN Management Interface
            # will ask for password again
            with patch(
                "openwisp_radius.management.commands.base.convert_called_station_id"
                ".BaseConvertCalledStationIdCommand._get_raw_management_info",
                return_value="PASSWORD:",
            ), patch("logging.Logger.warning") as mocked_logger:
                call_command("convert_called_station_id")
                mocked_logger.assert_called_once_with(
                    "Unable to parse information received from 127.0.0.1:7505. "
                    "ParsingError: expected 'OpenVPN CLIENT LIST' but got "
                    "'PASSWORD:'. Skipping!"
                )

        with self.subTest("Test routing information empty"):
            with patch(
                "openwisp_radius.management.commands.base.convert_called_station_id"
                ".BaseConvertCalledStationIdCommand._get_openvpn_routing_info",
                return_value={},
            ), patch("logging.Logger.info") as mocked_logger:
                call_command("convert_called_station_id")
                mocked_logger.assert_called_once_with(
                    f'No routing information found for "{org.id}" organization'
                )

        with self.subTest("Test client common name does not contain a MAC address"):
            dummy_routing_obj = Routing()
            dummy_routing_obj.common_name = "common name"
            with patch(
                "openwisp_radius.management.commands.base.convert_called_station_id"
                ".BaseConvertCalledStationIdCommand._get_openvpn_routing_info",
                return_value={options["calling_station_id"]: dummy_routing_obj},
            ), patch("logging.Logger.warning") as mocked_logger:
                call_command("convert_called_station_id")
                mocked_logger.assert_called_once_with(
                    f'Failed to find a MAC address in "{dummy_routing_obj.common_name}"'
                    f". Skipping {radius_acc.session_id}!"
                )

        with self.subTest("Test routing information does not contain all addresses"):
            with patch(
                "openwisp_radius.management.commands.base.convert_called_station_id"
                ".BaseConvertCalledStationIdCommand._get_openvpn_routing_info",
                return_value={"dd:dd:dd:dd:dd:dd": Routing()},
            ), patch("logging.Logger.warning") as mocked_logger:
                call_command("convert_called_station_id")
                mocked_logger.assert_called_once_with(
                    f"Failed to find routing information for {radius_acc.session_id}."
                    " Skipping!"
                )

        with self.subTest("Test ideal condition"):
            with self._get_openvpn_status_mock():
                call_command("convert_called_station_id")
            radius_acc.refresh_from_db()
            self.assertEqual(radius_acc.called_station_id, "CC-CC-CC-CC-CC-0C")

        with self.subTest("Test session with unique_id does not exist"):
            with patch("logging.Logger.warning") as mocked_logger:
                call_command("convert_called_station_id", unique_id="111")
                mocked_logger.assert_called_once_with(
                    'RadiusAccount object with unique_id "111" does not exist.'
                )

        with self.subTest("Test session organization not in CALLED_STATION_IDS"):
            rad_options = options.copy()
            rad_options["unique_id"] = "118"
            rad_options["organization"] = self._create_org(name="new-org")
            radius_acc = self._create_radius_accounting(**rad_options)
            with patch("logging.Logger.error") as mocked_logger:
                call_command(
                    "convert_called_station_id", unique_id=radius_acc.unique_id
                )
                mocked_logger.assert_called_once_with(
                    "OPENWISP_RADIUS_CALLED_STATION_IDS does not contain setting for"
                    f' "{radius_acc.organization.name}" organization'
                )

        with self.subTest("Test update only session with unique_id"):
            rad_options = options.copy()
            rad_options["unique_id"] = "119"
            radius_acc1 = self._create_radius_accounting(**rad_options)
            rad_options["unique_id"] = "120"
            radius_acc2 = self._create_radius_accounting(**rad_options)
            with self._get_openvpn_status_mock():
                call_command(
                    "convert_called_station_id", unique_id=radius_acc1.unique_id
                )
            radius_acc1.refresh_from_db()
            radius_acc2.refresh_from_db()
            self.assertEqual(radius_acc1.called_station_id, "CC-CC-CC-CC-CC-0C")
            self.assertNotEqual(radius_acc2.called_station_id, "CC-CC-CC-CC-CC-0C")

        with self.subTest("Test stop time is None"):
            rad_options = options.copy()
            rad_options["unique_id"] = "121"
            rad_options["stop_time"] = "2017-06-10 11:50:00"
            radius_acc = self._create_radius_accounting(**rad_options)
            with self._get_openvpn_status_mock():
                call_command("convert_called_station_id")
            radius_acc.refresh_from_db()
            self.assertEqual(
                radius_acc.called_station_id, rad_options["called_station_id"]
            )

    @capture_any_output()
    @patch.object(
        app_settings,
        "CALLED_STATION_IDS",
        {
            "test-org": {
                "openvpn_config": [
                    {"host": "127.0.0.1", "port": 7505, "password": "somepassword"}
                ],
                "unconverted_ids": ["AA-AA-AA-AA-AA-0A"],
            }
        },
    )
    @patch.object(app_settings, "OPENVPN_DATETIME_FORMAT", "%Y-%m-%d %H:%M:%S")
    @patch("openwisp_radius.tasks.convert_called_station_id")
    def test_convert_called_station_id_command_with_slug(self, *args):
        options = _RADACCT.copy()
        options["calling_station_id"] = str(EUI("bb:bb:bb:bb:bb:0b", dialect=mac_unix))
        options["called_station_id"] = "AA-AA-AA-AA-AA-0A"
        options["unique_id"] = "117"
        options["organization"] = self._get_org()
        radius_acc = self._create_radius_accounting(**options)

        with self.subTest("Test ideal condition"):
            with self._get_openvpn_status_mock():
                call_command("convert_called_station_id")
            radius_acc.refresh_from_db()
            self.assertEqual(radius_acc.called_station_id, "CC-CC-CC-CC-CC-0C")
