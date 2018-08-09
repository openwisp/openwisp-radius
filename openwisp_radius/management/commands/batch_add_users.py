from django_freeradius.management.commands import BaseBatchAddUsersCommand

from . import BatchAddMixin


class Command(BatchAddMixin, BaseBatchAddUsersCommand):
    pass
