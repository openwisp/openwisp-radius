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
    @abstractmethod
    def reply_name(self):  # pragma: no cover
        pass

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
    reply_message = _('Your maximum daily usage time has been reached')
    gigawords = False

    def __init__(self, user, group, group_check):
        self.user = user
        assert group
        self.group = group
        self.organization_id = str(group.organization_id)
        self.group_check = group_check
        self.logger = logging.getLogger(self.__module__)

    def __repr__(self):
        return (
            f'{self.counter_name}('
            f'user={self.user}, '
            f'group={self.group}, '
            f'organization_id={self.organization_id})'
        )

    @classmethod
    def get_attribute_type(self):
        check_name = self.check_name.lower()
        if 'traffic' in check_name:
            return 'bytes'
        elif 'session' in check_name:
            return 'seconds'
        return app_settings.RADIUS_ATTRIBUTES_TYPE_MAP.get(self.check_name, None)

    def get_reset_timestamps(self):
        try:
            return resets[self.reset](self.user)
        except KeyError:
            raise SkipCheck(
                message=f'Reset time with key "{self.reset}" not available.',
                level='error',
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

    @staticmethod
    def split_value(value):
        """
        Split a counter value into its 32-bit octets and gigawords components.
        
        This implements the RADIUS Gigawords extension (RFC 2869) which allows accounting
        for data transfers larger than 4GB (2^32 bytes). When a counter exceeds 32 bits,
        the lower 32 bits are reported in the standard Acct-*-Octets attribute, while
        the upper bits are reported in the corresponding Acct-*-Gigawords attribute.
        
        Args:
            value (int): The counter value to split
            
        Returns:
            tuple: (octets, gigawords) where:
                  - octets: the lower 32 bits (0 to 4,294,967,295)
                  - gigawords: the upper 32 bits (number of times the counter has wrapped)
                  
        Example:
            For a value of 6,442,450,944 (6GB), this returns (2147483648, 1)
            meaning 2,147,483,648 octets and 1 gigaword (1 * 2^32 + 2,147,483,648 = 6GB)
            
            To reconstruct the original value: (1 << 32) + 2147483648 = 6,442,450,944
        """
        if app_settings.GIGAWORDS_ENABLED and value > 0xFFFFFFFF:
            # 0xFFFFFFFF = 4,294,967,295 (maximum 32-bit value)
            # value & 0xFFFFFFFF extracts the lower 32 bits (remainder after division by 2^32)
            # value >> 32 shifts right by 32 bits to get the gigawords component (division by 2^32)
            return value & 0xFFFFFFFF, value >> 32
        # For values that don't exceed 32 bits, return the original value and 0 gigawords
        return value, 0
        
    def check(self, gigawords=gigawords):
        if not self.group_check:
            raise SkipCheck(
                message=(
                    f'Group {self.group} does not have '
                    f'any {self.check_name} check defined'
                ),
                level='debug',
                logger=self.logger,
            )

        counter = self.get_counter()
        try:
            value = int(self.group_check.value)
        except ValueError:
            raise SkipCheck(
                message=(
                    f'Group check value {self.group_check.value} '
                    'cannot be converted to integer'
                ),
                level='info',
                logger=self.logger,
            )
        is_max_reached = counter >= value
        remaining = value - counter
        self.logger.debug(
            f'{self} result: is_max_reached={is_max_reached} remaining={remaining}'
        )

        if is_max_reached:
            raise MaxQuotaReached(
                message=(
                    f'Counter {self} raised MaxQuotaReached exception, '
                    f'counter value ({counter}) is greater or equal to '
                    f'{self.check_name} check value ({value}).'
                ),
                level='info',
                logger=self.logger,
                reply_message=self.reply_message,
            )

        return int(remaining)


class BaseDailyCounter(BaseCounter):
    check_name = 'Max-Daily-Session'
    reply_name = 'Session-Timeout'
    reset = 'daily'

    def get_sql_params(self, start_time, end_time):
        return [
            start_time,
            self.user.username,
            self.organization_id,
            start_time,
        ]


class BaseTrafficCounter(BaseCounter):
    reply_name = app_settings.TRAFFIC_COUNTER_REPLY_NAME

    def get_sql_params(self, start_time, end_time):
        return [
            self.user.username,
            self.organization_id,
            start_time,
        ]


class BaseDailyTrafficCounter(BaseTrafficCounter):
    check_name = app_settings.TRAFFIC_COUNTER_CHECK_NAME
    reset = 'daily'


class BaseMontlhyTrafficCounter(BaseTrafficCounter):
    check_name = 'Max-Monthly-Session-Traffic'
    reset = 'monthly'
