from ..base import BaseDailyCounter
from . import SqliteCounterMixin


class DailyCounter(SqliteCounterMixin, BaseDailyCounter):
    counter_name = 'sqlite.DailyCounter'
    sql = '''
SELECT SUM(acctsessiontime - MAX((%s - strftime('%%s', acctstarttime)), 0))
FROM radacct
WHERE username=%s
AND organization_id=%s
AND (strftime('%%s', acctstarttime) + acctsessiontime) > %s;
    '''
