from ..base import BaseDailyTrafficCounter
from . import PostgresqlTrafficMixin


class DailyTrafficCounter(PostgresqlTrafficMixin, BaseDailyTrafficCounter):
    counter_name = 'postgresql.DailyTrafficCounter'
