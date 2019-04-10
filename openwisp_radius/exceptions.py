class PhoneTokenException(Exception):
    pass


class MaxAttemptsException(PhoneTokenException):
    pass


class ExpiredTokenException(PhoneTokenException):
    pass
