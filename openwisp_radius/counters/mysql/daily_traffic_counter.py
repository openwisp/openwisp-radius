from ..base import BaseDailyTrafficCounter


class DailyTrafficCounter(BaseDailyTrafficCounter):
    counter_name = 'mysql.DailyTrafficCounter'
    sql = '''
SELECT SUM(acctinputoctets + acctoutputoctets)
FROM radacct
WHERE username=%s
AND organization_id=%s
AND UNIX_TIMESTAMP(acctstarttime) + acctsessiontime >  %s;
    '''
