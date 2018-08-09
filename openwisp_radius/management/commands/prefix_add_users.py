from django_freeradius.management.commands import BasePrefixAddUsersCommand

from . import BatchAddMixin


class Command(BatchAddMixin, BasePrefixAddUsersCommand):
    pass
