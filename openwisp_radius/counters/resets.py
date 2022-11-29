from datetime import date, datetime, timedelta

from dateutil.relativedelta import relativedelta


def _today():
    return date.today()


def _timestamp(start, end):
    return int(start.timestamp()), int(end.timestamp())


def _daily(user=None):
    dt = _today()
    start = datetime(dt.year, dt.month, dt.day)
    end = datetime(dt.year, dt.month, dt.day) + timedelta(days=1)
    return _timestamp(start, end)


def _weekly(user=None):
    dt = _today()
    start = dt - timedelta(days=dt.weekday())
    start = datetime(start.year, start.month, start.day)
    end = start + timedelta(days=7)
    return _timestamp(start, end)


def _monthly(user=None):
    dt = _today()
    start = datetime(dt.year, dt.month, 1)
    end = datetime(dt.year, dt.month, 1) + relativedelta(months=1)
    return _timestamp(start, end)


def _monthly_subscription(user):
    dt = _today()
    day_joined = user.date_joined.day
    start = datetime(dt.year, dt.month, day_joined)
    if start > datetime.fromordinal(dt.toordinal()):
        start = start - relativedelta(months=1)
    end = datetime(start.year, start.month, day_joined) + relativedelta(months=1)
    return _timestamp(start, end)


def _never(user=None):
    return 0, None


resets = {
    'daily': _daily,
    'weekly': _weekly,
    'monthly': _monthly,
    'monthly_subscription': _monthly_subscription,
    'never': _never,
}
