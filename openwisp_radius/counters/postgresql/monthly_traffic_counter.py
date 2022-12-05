from ..base import BaseMontlhyTrafficCounter
from . import PostgresqlTrafficMixin


class MonthlyTrafficCounter(PostgresqlTrafficMixin, BaseMontlhyTrafficCounter):
    counter_name = 'postgresql.MonthlyTrafficCounter'


class MonthlySubscriptionTrafficCounter(
    PostgresqlTrafficMixin, BaseMontlhyTrafficCounter
):
    counter_name = 'postgresql.MonthlySubscriptionTrafficCounter'
    reset = 'monthly_subscription'
