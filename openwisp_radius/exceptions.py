class PhoneTokenException(Exception):
    pass


class UserAlreadyVerified(PhoneTokenException):
    pass


class MaxAttemptsException(PhoneTokenException):
    pass


class SmsAttemptTimeoutException(PhoneTokenException):
    def __init__(
        self,
        *args,
        timeout=None,
    ):
        self.timeout = timeout
        super().__init__(*args)


class ExpiredTokenException(PhoneTokenException):
    pass


class NoOrgException(PhoneTokenException):
    pass
