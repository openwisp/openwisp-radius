import logging
from abc import ABC, abstractmethod

from django.db import connection
from django.utils.translation import gettext_lazy as _

from .. import settings as app_settings
from .exceptions import MaxQuotaReached, SkipCheck
from .resets import resets


class BaseCounter(ABC):
    @property
    @abstractmethod
    def counter_name(self):  # pragma: no cover
        pass

    @property
    @abstractmethod
    def check_name(self):  # pragma: no cover
        pass

    @property
    def reply_names(self):
        # BACKWARD COMPATIBILITY: In previous versions of openwisp-radius,
        # the Counter.reply_name was a string instead of a tuple. Thus,
        # we need to convert it to a tuple if it's a string.
        reply_name = getattr(self, "reply_name", None)
        if not reply_name:
            raise NotImplementedError(
                "Counter classes must define 'reply_names' property."
            )
        if isinstance(reply_name, str):
            return (reply_name,)
        return reply_name

    @property
    @abstractmethod
    def reset(self):  # pragma: no cover
        pass

    @property
    @abstractmethod
    def sql(self):  # pragma: no cover
        pass

    @abstractmethod
    def get_sql_params(self, start_time, end_time):  # pragma: no cover
        pass

    # This is the reply message hardcoded in the FreeRADIUS 3
    # sqlcounter module, now we can translate it with gettext
    # or customize it (in new counter classes) if needed
    reply_message = _("Your maximum daily usage time has been reached")

    def __init__(self, user, group, group_check):
        self.user = user
        assert group
        self.group = group
        self.organization_id = str(group.organization_id)
        self.group_check = group_check
        self.logger = logging.getLogger(self.__module__)

    def __repr__(self):
        return (
            f"{self.counter_name}("
            f"user={self.user}, "
            f"group={self.group}, "
            f"organization_id={self.organization_id})"
        )

    @classmethod
    def get_attribute_type(self):
        check_name = self.check_name.lower()
        if "traffic" in check_name:
            return "bytes"
        elif "session" in check_name:
            return "seconds"
        return app_settings.RADIUS_ATTRIBUTES_TYPE_MAP.get(self.check_name, None)

    def get_reset_timestamps(self):
        try:
            return resets[self.reset](self.user, counter=self)
        except KeyError:
            raise SkipCheck(
                message=f'Reset time with key "{self.reset}" not available.',
                level="error",
                logger=self.logger,
            )

    def get_counter(self):
        """
        The SQL query is executed with raw SQL for maximum flexibility and
        adherence to freeradius.
        """
        with connection.cursor() as cursor:
            start_time, end_time = self.get_reset_timestamps()
            cursor.execute(self.sql, self.get_sql_params(start_time, end_time))
            row = cursor.fetchone()
        # return result,
        # or if nothing is returned (no sessions present), return zero
        return row[0] or 0

    def check(self):
        if not self.group_check:
            raise SkipCheck(
                message=(
                    f"Group {self.group} does not have "
                    f"any {self.check_name} check defined"
                ),
                level="debug",
                logger=self.logger,
            )

        counter = self.get_counter()
        try:
            value = int(self.group_check.value)
        except ValueError:
            raise SkipCheck(
                message=(
                    f"Group check value {self.group_check.value} "
                    "cannot be converted to integer"
                ),
                level="info",
                logger=self.logger,
            )
        is_max_reached = counter >= value
        remaining = value - counter
        self.logger.debug(
            f"{self} result: is_max_reached={is_max_reached} remaining={remaining}"
        )

        if is_max_reached:
            raise MaxQuotaReached(
                message=(
                    f"Counter {self} raised MaxQuotaReached exception, "
                    f"counter value ({counter}) is greater or equal to "
                    f"{self.check_name} check value ({value})."
                ),
                level="info",
                logger=self.logger,
                reply_message=self.reply_message,
            )

        return (int(remaining),)

    def consumed(self):
        return int(self.get_counter())


class BaseDailyCounter(BaseCounter):
    check_name = "Max-Daily-Session"
    reply_names = ("Session-Timeout",)
    reset = "daily"

    def get_sql_params(self, start_time, end_time):
        return [
            start_time,
            self.user.username,
            self.organization_id,
            start_time,
        ]


class BaseTrafficCounter(BaseCounter):
    reply_names = (app_settings.TRAFFIC_COUNTER_REPLY_NAME,)

    def get_sql_params(self, start_time, end_time):
        return [
            self.user.username,
            self.organization_id,
            start_time,
        ]


class BaseDailyTrafficCounter(BaseTrafficCounter):
    check_name = app_settings.TRAFFIC_COUNTER_CHECK_NAME
    reset = "daily"


class BaseMontlhyTrafficCounter(BaseTrafficCounter):
    check_name = "Max-Monthly-Session-Traffic"
    reset = "monthly"
