from .base import BatchAddMixin
from .base.prefix_add_users import BasePrefixAddUsersCommand


class Command(BatchAddMixin, BasePrefixAddUsersCommand):
    pass
