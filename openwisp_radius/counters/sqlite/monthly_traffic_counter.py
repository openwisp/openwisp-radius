from ..base import BaseMontlhyTrafficCounter
from . import SqliteCounterMixin, SqliteTrafficMixin


class MonthlyTrafficCounter(
    SqliteTrafficMixin, SqliteCounterMixin, BaseMontlhyTrafficCounter
):
    counter_name = 'sqlite.MonthlyTrafficCounter'


class MonthlySubscriptionTrafficCounter(
    SqliteTrafficMixin, SqliteCounterMixin, BaseMontlhyTrafficCounter
):
    counter_name = 'sqlite.MonthlySubscriptionTrafficCounter'
    reset = 'monthly_subscription'
