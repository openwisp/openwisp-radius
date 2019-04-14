class PhoneTokenException(Exception):
    pass


class UserAlreadyActive(PhoneTokenException):
    pass


class MaxAttemptsException(PhoneTokenException):
    pass


class ExpiredTokenException(PhoneTokenException):
    pass
