class BaseException(Exception):
    def __init__(self, message, level, logger):
        """
        Logs a message with the specified level when raised.
        """
        self.message = message
        self.level = level
        assert level in ['debug', 'info', 'warn', 'error', 'critical', 'exception']
        # log message with specified level
        getattr(logger, level)(message)


class SkipCheck(BaseException):
    """
    Indicates an sqlcounter check should be skipped.
    """

    pass


class MaxQuotaReached(BaseException):
    """
    Indicates the maximum quota defined for a user has been reached.
    """

    def __init__(self, message, level, logger, reply_message):
        super().__init__(message, level, logger)
        self.reply_message = reply_message
