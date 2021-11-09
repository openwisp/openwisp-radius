from ..base import BaseDailyCounter


class DailyCounter(BaseDailyCounter):
    counter_name = 'mysql.DailyCounter'
    sql = '''
SELECT SUM(acctsessiontime - GREATEST((%s - UNIX_TIMESTAMP(acctstarttime)), 0))
FROM radacct
WHERE username=%s
AND organization_id=%s
AND UNIX_TIMESTAMP(acctstarttime) + acctsessiontime > %s;
    '''
