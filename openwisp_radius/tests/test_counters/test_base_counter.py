from datetime import datetime
from unittest.mock import patch

from freezegun import freeze_time

from openwisp_utils.tests import capture_any_output

from ... import settings as app_settings
from ...counters.base import BaseCounter, BaseDailyCounter, BaseMontlhyTrafficCounter
from ...counters.exceptions import MaxQuotaReached, SkipCheck
from ...counters.resets import resets
from ...utils import load_model
from ..mixins import BaseTransactionTestCase
from .utils import TestCounterMixin

RadiusAccounting = load_model("RadiusAccounting")


class TestBaseCounter(TestCounterMixin, BaseTransactionTestCase):
    @capture_any_output()
    def test_wrong_reset_time(self):
        class BrokenCounter(BaseCounter):
            counter_name = "Broken"
            check_name = "Broken"
            reply_name = "Broken"
            reset = "broken"
            sql = "broken"

            def get_sql_params(self, start_time, end_time):
                return []

        opts = self._get_kwargs("Max-Daily-Session")
        counter = BrokenCounter(**opts)
        with self.assertRaises(SkipCheck) as ctx:
            counter.get_reset_timestamps()
        self.assertEqual(ctx.exception.level, "error")

    def test_abstract_instantiation(self):
        opts = self._get_kwargs("Max-Daily-Session")

        with self.assertRaises(TypeError) as ctx:
            BaseCounter(**opts)
        self.assertIn("abstract class BaseCounter", str(ctx.exception))

    def test_reply_name_backward_compatibility(self):
        options = self._get_kwargs("Session-Timeout")

        class BackwardCompatibleCounter(BaseCounter):
            check_name = "Max-Daily-Session"
            counter_name = "BackwardCompatibleCounter"
            reset = "daily"
            sql = "SELECT 1"

            def get_sql_params(self, start_time, end_time):
                return []

        with self.subTest("Counter does not implement reply_names or reply_name"):
            counter = BackwardCompatibleCounter(**options)
            with self.assertRaises(NotImplementedError) as ctx:
                counter.reply_names
            self.assertIn(
                "Counter classes must define 'reply_names' property.",
                str(ctx.exception),
            )

        BackwardCompatibleCounter.reply_name = "Session-Timeout"
        with self.subTest("Counter does not implement reply_names, uses reply_name"):
            counter = BackwardCompatibleCounter(**options)
            self.assertEqual(counter.reply_names, ("Session-Timeout",))

        BackwardCompatibleCounter.reply_name = ("Session-Timeout",)
        with self.subTest("Counter implements reply_names as tuple"):
            counter = BackwardCompatibleCounter(**options)
            self.assertEqual(counter.reply_names, ("Session-Timeout",))

    @freeze_time("2021-11-03T08:21:44-04:00")
    def test_resets(self):
        with self.subTest("daily"):
            start, end = resets["daily"]()
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-03 00:00:00")
            self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-04 00:00:00")

        with self.subTest("weekly"):
            start, end = resets["weekly"]()
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-01 00:00:00")
            self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-08 00:00:00")

        with self.subTest("monthly"):
            start, end = resets["monthly"]()
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-01 00:00:00")
            self.assertEqual(str(datetime.fromtimestamp(end)), "2021-12-01 00:00:00")

        user = self._get_user()

        with self.subTest("monthly_subscription same month"):
            user.date_joined = datetime.fromisoformat("2021-07-02 12:34:58")
            user.save(update_fields=["date_joined"])
            start, end = resets["monthly_subscription"](user)
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-02 00:00:00")
            self.assertEqual(str(datetime.fromtimestamp(end)), "2021-12-02 00:00:00")

        with self.subTest("monthly_subscription prev month"):
            user.date_joined = datetime.fromisoformat("2021-07-22 12:34:58")
            user.save(update_fields=["date_joined"])
            start, end = resets["monthly_subscription"](user)
            self.assertEqual(str(datetime.fromtimestamp(start)), "2021-10-22 00:00:00")
            self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-22 00:00:00")

        with self.subTest("monthly_subscription future start date logic"):
            user.date_joined = datetime.fromisoformat("2021-07-04 12:34:58")
            user.save(update_fields=["date_joined"])
            start, end = resets["monthly_subscription"](user)
            self.assertEqual(str(datetime.fromtimestamp(start)), "2021-10-04 00:00:00")
            self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-04 00:00:00")

        with self.subTest("never"):
            start, end = resets["never"]()
            self.assertEqual(start, 0)
            self.assertEqual(str(datetime.fromtimestamp(start)), "1970-01-01 00:00:00")
            self.assertIsNone(end)

    @patch.object(
        app_settings, "RADIUS_ATTRIBUTES_TYPE_MAP", {"Max-Input-Octets": "bytes"}
    )
    def test_get_attribute_type(self):
        class MaxInputOctetsCounter(BaseDailyCounter):
            check_name = "Max-Input-Octets"

        self.assertEqual(BaseDailyCounter.get_attribute_type(), "seconds")
        self.assertEqual(BaseMontlhyTrafficCounter.get_attribute_type(), "bytes")
        self.assertEqual(MaxInputOctetsCounter.get_attribute_type(), "bytes")

    def test_base_exception_logging(self):
        from unittest.mock import MagicMock

        from ...counters.exceptions import BaseException

        logger = MagicMock()
        BaseException("message", "error", logger)
        logger.error.assert_called_with("message")
        with self.assertRaises(AssertionError):
            BaseException("message", "invalid_level", logger)

    def test_consumed_method(self):
        opts = self._get_kwargs("Max-Daily-Session")
        from ...counters.sqlite.daily_counter import DailyCounter

        counter = DailyCounter(**opts)
        consumed = counter.consumed()
        self.assertEqual(consumed, 0)
        self.assertIsInstance(consumed, int)

        from .utils import _acct_data

        self._create_radius_accounting(**_acct_data)
        consumed = counter.consumed()
        self.assertEqual(consumed, int(_acct_data["session_time"]))
        self.assertIsInstance(consumed, int)

    def test_base_counter_repr(self):
        """Test __repr__() method of BaseCounter"""
        from ...counters.sqlite.daily_counter import DailyCounter

        opts = self._get_kwargs("Max-Daily-Session")
        counter = DailyCounter(**opts)
        repr_str = repr(counter)

        # Verify the format includes counter name, user, group, and organization_id
        self.assertIn("sqlite.DailyCounter", repr_str)
        self.assertIn(f"user={opts['user']}", repr_str)
        self.assertIn(f"group={opts['group']}", repr_str)
        self.assertIn(f"organization_id={counter.organization_id}", repr_str)

    @capture_any_output()
    def test_check_no_group_check(self):
        """Test check() raises SkipCheck when group_check is None"""
        from ...counters.sqlite.daily_counter import DailyCounter

        opts = self._get_kwargs("Max-Daily-Session")
        opts["group_check"] = None
        counter = DailyCounter(**opts)

        with self.assertRaises(SkipCheck) as ctx:
            counter.check()

        self.assertEqual(ctx.exception.level, "debug")
        self.assertIn(
            "does not have any Max-Daily-Session check defined", ctx.exception.message
        )

    @capture_any_output()
    def test_check_invalid_group_check_value(self):
        """Test check() raises SkipCheck when group_check.value is not an integer"""
        from ...counters.sqlite.daily_counter import DailyCounter

        opts = self._get_kwargs("Max-Daily-Session")
        original_value = opts["group_check"].value
        opts["group_check"].value = "not_a_number"
        counter = DailyCounter(**opts)

        with self.assertRaises(SkipCheck) as ctx:
            counter.check()

        self.assertEqual(ctx.exception.level, "info")
        self.assertIn("cannot be converted to integer", ctx.exception.message)

        # Restore original value
        opts["group_check"].value = original_value

    @capture_any_output()
    def test_check_quota_reached(self):
        """Test check() raises MaxQuotaReached when counter >= value"""
        from ...counters.sqlite.daily_counter import DailyCounter
        from .utils import _acct_data

        opts = self._get_kwargs("Max-Daily-Session")
        counter = DailyCounter(**opts)

        # Create accounting session that exceeds the quota
        acct_data = _acct_data.copy()
        acct_data["session_time"] = str(int(opts["group_check"].value) + 1000)
        self._create_radius_accounting(**acct_data)

        with self.assertRaises(MaxQuotaReached) as ctx:
            counter.check()

        self.assertEqual(ctx.exception.level, "info")
        self.assertIsNotNone(ctx.exception.reply_message)
        self.assertIn("Counter", ctx.exception.message)

    def test_check_quota_not_reached(self):
        """Test check() returns remaining quota when counter < value"""
        from ...counters.sqlite.daily_counter import DailyCounter
        from .utils import _acct_data

        opts = self._get_kwargs("Max-Daily-Session")
        counter = DailyCounter(**opts)

        # Create accounting session that doesn't exceed the quota
        self._create_radius_accounting(**_acct_data)

        result = counter.check()

        # Should return a tuple with remaining quota
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 1)
        expected_remaining = int(opts["group_check"].value) - int(
            _acct_data["session_time"]
        )
        self.assertEqual(result[0], expected_remaining)
        self.assertIsInstance(result[0], int)


del BaseTransactionTestCase
