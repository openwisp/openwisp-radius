from .base import BatchAddMixin
from .base.batch_add_users import BaseBatchAddUsersCommand


class Command(BatchAddMixin, BaseBatchAddUsersCommand):
    pass
