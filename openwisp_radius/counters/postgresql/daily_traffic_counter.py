from ..base import BaseDailyTrafficCounter


class DailyTrafficCounter(BaseDailyTrafficCounter):
    counter_name = 'postgresql.DailyTrafficCounter'
    sql = '''
SELECT SUM(acctinputoctets) + sum(acctoutputoctets)
FROM radacct
WHERE username=%s
AND organization_id=%s
AND EXTRACT(epoch FROM acctstarttime) + acctsessiontime >  %s;
    '''
