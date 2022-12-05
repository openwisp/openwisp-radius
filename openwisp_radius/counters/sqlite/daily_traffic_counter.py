from ..base import BaseDailyTrafficCounter
from . import SqliteCounterMixin, SqliteTrafficMixin


class DailyTrafficCounter(
    SqliteTrafficMixin, SqliteCounterMixin, BaseDailyTrafficCounter
):
    counter_name = 'sqlite.DailyTrafficCounter'
