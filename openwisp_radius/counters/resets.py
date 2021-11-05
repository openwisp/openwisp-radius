from datetime import date, datetime, timedelta

from dateutil.relativedelta import relativedelta


def _today():
    return date.today()


def _timestamp(start, end):
    return int(start.timestamp()), int(end.timestamp())


def _daily():
    dt = _today()
    start = datetime(dt.year, dt.month, dt.day)
    end = datetime(dt.year, dt.month, dt.day) + timedelta(days=1)
    return _timestamp(start, end)


def _weekly():
    dt = _today()
    start = dt - timedelta(days=dt.weekday())
    start = datetime(start.year, start.month, start.day)
    end = start + timedelta(days=7)
    return _timestamp(start, end)


def _monthly():
    dt = _today()
    start = datetime(dt.year, dt.month, 1)
    end = datetime(dt.year, dt.month, 1) + relativedelta(months=1)
    return _timestamp(start, end)


def _never():
    return 0, None


resets = {
    'daily': _daily,
    'weekly': _weekly,
    'monthly': _monthly,
    'never': _never,
}
