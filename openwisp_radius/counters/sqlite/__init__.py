class SqliteCounterMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # organization_id on sqlite doesn't have the dash
        self.organization_id = self.organization_id.replace('-', '')
