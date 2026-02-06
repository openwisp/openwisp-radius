from datetime import date, datetime

from freezegun import freeze_time

from ...counters.resets import (
    _daily,
    _monthly,
    _monthly_subscription,
    _never,
    _timestamp,
    _today,
    _weekly,
)
from ..mixins import BaseTestCase


class TestCounterResets(BaseTestCase):
    @freeze_time("2021-11-03T12:30:00")
    def test_today_function(self):
        result = _today()
        self.assertIsInstance(result, date)
        self.assertEqual(result, date(2021, 11, 3))

    def test_timestamp_function(self):
        start = datetime(2021, 11, 3, 0, 0, 0)
        end = datetime(2021, 11, 4, 0, 0, 0)
        start_ts, end_ts = _timestamp(start, end)

        self.assertIsInstance(start_ts, int)
        self.assertIsInstance(end_ts, int)
        self.assertEqual(start_ts, int(start.timestamp()))
        self.assertEqual(end_ts, int(end.timestamp()))
        self.assertEqual(end_ts - start_ts, 86400)

    @freeze_time("2021-11-03T08:21:44-04:00")
    def test_daily_reset(self):
        start, end = _daily()
        self.assertIsInstance(start, int)
        self.assertIsInstance(end, int)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-03 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-04 00:00:00")
        self.assertEqual(end - start, 86400)

    @freeze_time("2021-11-03T08:21:44-04:00")
    def test_daily_with_user_param(self):
        user = self._get_user()
        start, end = _daily(user=user)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-03 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-04 00:00:00")

    @freeze_time("2021-11-03T08:21:44-04:00")  # Wednesday
    def test_weekly_reset(self):
        start, end = _weekly()
        self.assertIsInstance(start, int)
        self.assertIsInstance(end, int)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-01 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-08 00:00:00")
        self.assertEqual(end - start, 604800)

    @freeze_time("2021-11-03T08:21:44-04:00")
    def test_monthly_reset(self):
        start, end = _monthly()
        self.assertIsInstance(start, int)
        self.assertIsInstance(end, int)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-01 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-12-01 00:00:00")

    @freeze_time("2021-11-03T08:21:44-04:00")
    def test_monthly_subscription_same_month(self):
        user = self._get_user()
        user.date_joined = datetime.fromisoformat("2021-07-02 12:34:58")
        user.save(update_fields=["date_joined"])

        start, end = _monthly_subscription(user)
        self.assertIsInstance(start, int)
        self.assertIsInstance(end, int)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-02 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-12-02 00:00:00")

    @freeze_time("2021-11-03T08:21:44-04:00")
    def test_monthly_subscription_prev_month(self):
        user = self._get_user()
        user.date_joined = datetime.fromisoformat("2021-07-22 12:34:58")
        user.save(update_fields=["date_joined"])

        start, end = _monthly_subscription(user)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-10-22 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-22 00:00:00")

    @freeze_time("2021-11-03T08:21:44-04:00")
    def test_monthly_subscription_future_day(self):
        user = self._get_user()
        user.date_joined = datetime.fromisoformat("2021-07-25 12:34:58")
        user.save(update_fields=["date_joined"])

        start, end = _monthly_subscription(user)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-10-25 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-11-25 00:00:00")

    @freeze_time("2021-11-30T23:59:59")
    def test_monthly_subscription_with_kwargs(self):
        user = self._get_user()
        user.date_joined = datetime.fromisoformat("2021-07-15 12:00:00")
        user.save(update_fields=["date_joined"])

        start, end = _monthly_subscription(user, counter=None)
        self.assertIsInstance(start, int)
        self.assertIsInstance(end, int)
        self.assertEqual(str(datetime.fromtimestamp(start)), "2021-11-15 00:00:00")
        self.assertEqual(str(datetime.fromtimestamp(end)), "2021-12-15 00:00:00")

    def test_never_reset(self):
        start, end = _never()
        self.assertEqual(start, 0)
        self.assertIsNone(end)
        self.assertEqual(start, 0)
        self.assertEqual(datetime.utcfromtimestamp(start).year, 1970)

    def test_never_with_user_param(self):
        user = self._get_user()
        start, end = _never(user=user)
        self.assertEqual(start, 0)
        self.assertIsNone(end)

    def test_timestamp_with_microseconds(self):
        start = datetime(2021, 11, 3, 12, 30, 45, 123456)
        end = datetime(2021, 11, 3, 13, 45, 30, 987654)
        start_ts, end_ts = _timestamp(start, end)
        self.assertEqual(start_ts, int(start.timestamp()))
        self.assertEqual(end_ts, int(end.timestamp()))
