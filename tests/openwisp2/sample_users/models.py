from django.contrib.auth.models import Group as AbstractGroup
from django.core.validators import RegexValidator
from django.db import models
from organizations.abstract import (
    AbstractOrganization,
    AbstractOrganizationInvitation,
    AbstractOrganizationOwner,
    AbstractOrganizationUser,
)

from openwisp_users.base.models import (
    AbstractUser,
    BaseGroup,
    BaseOrganization,
    BaseOrganizationOwner,
    BaseOrganizationUser,
)


class User(AbstractUser):
    social_security_number = models.CharField(
        max_length=11,
        null=True,
        blank=True,
        validators=[RegexValidator(r'^\d\d\d-\d\d-\d\d\d\d$')],
    )

    class Meta(AbstractUser.Meta):
        abstract = False


class Organization(BaseOrganization, AbstractOrganization):
    class Meta(AbstractOrganization.Meta):
        abstract = False


class OrganizationUser(BaseOrganizationUser, AbstractOrganizationUser):
    class Meta(AbstractOrganizationUser.Meta):
        abstract = False


class OrganizationOwner(BaseOrganizationOwner, AbstractOrganizationOwner):
    class Meta(AbstractOrganizationOwner.Meta):
        abstract = False


class OrganizationInvitation(AbstractOrganizationInvitation):
    pass


class Group(BaseGroup, AbstractGroup):
    class Meta(BaseGroup.Meta):
        abstract = False
