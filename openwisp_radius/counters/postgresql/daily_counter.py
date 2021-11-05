from ..base import BaseDailyCounter


class DailyCounter(BaseDailyCounter):
    counter_name = 'postgresql.DailyCounter'
    sql = '''
SELECT SUM(acctsessiontime - GREATEST((%s - EXTRACT(epoch FROM acctstarttime)), 0))
FROM radacct
WHERE username=%s
AND organization_id=%s
AND EXTRACT(epoch FROM acctstarttime) + acctsessiontime > %s;
    '''
