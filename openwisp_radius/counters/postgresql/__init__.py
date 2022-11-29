class PostgresqlTrafficMixin:
    sql = '''
SELECT SUM(acctinputoctets) + sum(acctoutputoctets)
FROM radacct
WHERE username=%s
AND organization_id=%s
AND EXTRACT(epoch FROM acctstarttime) + acctsessiontime >  %s;
    '''
