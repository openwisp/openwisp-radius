from ..base import BaseDailyTrafficCounter
from . import SqliteCounterMixin


class DailyTrafficCounter(SqliteCounterMixin, BaseDailyTrafficCounter):
    counter_name = 'sqlite.DailyTrafficCounter'
    sql = '''
SELECT SUM(acctinputoctets + acctoutputoctets)
FROM radacct
WHERE username=%s
AND organization_id=%s
AND (strftime('%%s', acctstarttime) + acctsessiontime) > %s;
    '''
