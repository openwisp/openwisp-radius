import hashlib
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from urllib.parse import urlencode

from django.utils import timezone

local_timezone = timezone.get_current_timezone()


def _get_urlencoded_datetime(date_time):
    """
    URL encodes the date_time string and returns the value.
    """
    return urlencode({"": date_time}).split("=")[1]


def get_today_start_datetime():
    """
    Returns the beginning of the current day in local timezone.
    """

    return timezone.make_aware(
        datetime.combine(timezone.localdate(), datetime.min.time())
    )


def get_utc_datetime_from_local_date():
    """
    Returns UTC time for the beginning of the current day in local timezone.
    """
    return get_today_start_datetime().astimezone(dt_timezone.utc)


def get_datetime_filter_start_datetime():
    today = get_today_start_datetime()
    return _get_urlencoded_datetime(today)


def get_datetime_filter_stop_datetime():
    tomorrow = get_today_start_datetime() + timedelta(days=1)
    return _get_urlencoded_datetime(tomorrow)


def sha1_hash(input_string):
    sha1 = hashlib.sha1()
    sha1.update(input_string.encode("utf-8"))
    return sha1.hexdigest()


def clean_registration_method(method):
    if method == "":
        method = "unspecified"
    return method
