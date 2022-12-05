from ..base import BaseMontlhyTrafficCounter
from . import MysqlTrafficMixin


class MonthlyTrafficCounter(MysqlTrafficMixin, BaseMontlhyTrafficCounter):
    counter_name = 'mysql.MonthlyTrafficCounter'


class MonthlySubscriptionTrafficCounter(MysqlTrafficMixin, BaseMontlhyTrafficCounter):
    counter_name = 'mysql.MonthlySubscriptionTrafficCounter'
    reset = 'monthly_subscription'
