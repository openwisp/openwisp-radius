class PhoneTokenException(Exception):
    pass


class UserAlreadyVerified(PhoneTokenException):
    pass


class MaxAttemptsException(PhoneTokenException):
    pass


class ExpiredTokenException(PhoneTokenException):
    pass


class NoOrgException(PhoneTokenException):
    pass
