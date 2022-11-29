from ...counters.postgresql.daily_counter import DailyCounter
from ...counters.postgresql.daily_traffic_counter import DailyTrafficCounter
from ...counters.postgresql.monthly_traffic_counter import (
    MonthlySubscriptionTrafficCounter,
    MonthlyTrafficCounter,
)
from ...utils import load_model
from ..mixins import BaseTestCase
from .utils import TestCounterMixin

RadiusAccounting = load_model('RadiusAccounting')


class TestPostgresqlCounters(TestCounterMixin, BaseTestCase):
    def test_time_counter_repr(self):
        opts = self._get_kwargs('Max-Daily-Session')
        counter = DailyCounter(**opts)
        expected = (
            'postgresql.DailyCounter(user=tester, '
            'group=test-org-users, '
            f'organization_id={counter.organization_id})'
        )
        self.assertEqual(repr(counter), expected)

    def test_daily_traffic_counter_repr(self):
        opts = self._get_kwargs('Max-Daily-Session')
        counter = DailyTrafficCounter(**opts)
        expected = (
            'postgresql.DailyTrafficCounter(user=tester, '
            'group=test-org-users, '
            f'organization_id={counter.organization_id})'
        )
        self.assertEqual(repr(counter), expected)

    def test_monthly_traffic_counter_repr(self):
        opts = self._get_kwargs('Max-Daily-Session')
        counter = MonthlyTrafficCounter(**opts)
        expected = (
            'postgresql.MonthlyTrafficCounter(user=tester, '
            'group=test-org-users, '
            f'organization_id={counter.organization_id})'
        )
        self.assertEqual(repr(counter), expected)

        with self.subTest('MonthlySubscriptionTrafficCounter'):
            counter = MonthlySubscriptionTrafficCounter(**opts)
            expected = (
                'postgresql.MonthlySubscriptionTrafficCounter(user=tester, '
                'group=test-org-users, '
                f'organization_id={counter.organization_id})'
            )
            self.assertEqual(repr(counter), expected)
