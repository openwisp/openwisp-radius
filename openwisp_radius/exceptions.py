class PhoneTokenException(Exception):
    pass


class UserAlreadyVerified(PhoneTokenException):
    pass


class MaxAttemptsException(PhoneTokenException):
    pass


class SmsAttemptCooldownException(PhoneTokenException):
    def __init__(
        self,
        *args,
        cooldown=None,
    ):
        self.cooldown = cooldown
        super().__init__(*args)


class ExpiredTokenException(PhoneTokenException):
    pass


class NoOrgException(PhoneTokenException):
    pass
