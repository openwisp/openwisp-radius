class SqliteCounterMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # organization_id on sqlite doesn't have the dash
        self.organization_id = self.organization_id.replace('-', '')


class SqliteTrafficMixin:
    sql = '''
SELECT SUM(acctinputoctets + acctoutputoctets)
FROM radacct
WHERE username=%s
AND organization_id=%s
AND (strftime('%%s', acctstarttime) + acctsessiontime) > %s;
    '''
