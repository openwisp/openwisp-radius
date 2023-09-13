from datetime import datetime, timedelta

from django.utils import timezone

local_timezone = timezone.get_current_timezone()


def _get_formatted_datetime_string(date_time):
    return (
        str(datetime.combine(date_time, datetime.min.time()).astimezone(local_timezone))
        .replace(' ', '+')
        .replace(':', '%3A')
    )


def get_datetime_filter_start_date():
    start_date = timezone.localdate()
    return _get_formatted_datetime_string(start_date)


def get_datetime_filter_stop_date():
    stop_date = timezone.localdate() + timedelta(days=1)
    return _get_formatted_datetime_string(stop_date)
