from ..base import BaseDailyTrafficCounter
from . import MysqlTrafficMixin


class DailyTrafficCounter(MysqlTrafficMixin, BaseDailyTrafficCounter):
    counter_name = 'mysql.DailyTrafficCounter'
