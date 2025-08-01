from ...counters.mysql.daily_counter import DailyCounter
from ...counters.mysql.daily_traffic_counter import DailyTrafficCounter
from ...counters.mysql.monthly_traffic_counter import (
    MonthlySubscriptionTrafficCounter,
    MonthlyTrafficCounter,
)
from ...utils import load_model
from ..mixins import BaseTransactionTestCase
from .utils import TestCounterMixin

RadiusAccounting = load_model("RadiusAccounting")


class TestMysqlCounters(TestCounterMixin, BaseTransactionTestCase):
    def test_time_counter_repr(self):
        opts = self._get_kwargs("Max-Daily-Session")
        counter = DailyCounter(**opts)
        expected = (
            "mysql.DailyCounter(user=tester, "
            "group=test-org-users, "
            f"organization_id={counter.organization_id})"
        )
        self.assertEqual(repr(counter), expected)

    def test_daily_traffic_counter_repr(self):
        opts = self._get_kwargs("Max-Daily-Session")
        counter = DailyTrafficCounter(**opts)
        expected = (
            "mysql.DailyTrafficCounter(user=tester, "
            "group=test-org-users, "
            f"organization_id={counter.organization_id})"
        )
        self.assertEqual(repr(counter), expected)

    def test_monthly_traffic_counter_repr(self):
        opts = self._get_kwargs("Max-Daily-Session")
        counter = MonthlyTrafficCounter(**opts)
        expected = (
            "mysql.MonthlyTrafficCounter(user=tester, "
            "group=test-org-users, "
            f"organization_id={counter.organization_id})"
        )
        self.assertEqual(repr(counter), expected)

        with self.subTest("MonthlySubscriptionTrafficCounter"):
            counter = MonthlySubscriptionTrafficCounter(**opts)
            expected = (
                "mysql.MonthlySubscriptionTrafficCounter(user=tester, "
                "group=test-org-users, "
                f"organization_id={counter.organization_id})"
            )
            self.assertEqual(repr(counter), expected)


del BaseTransactionTestCase
