from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import signals

from openwisp_radius.base.models import (
    AbstractNas,
    AbstractOrganizationRadiusSettings,
    AbstractPhoneToken,
    AbstractRadiusAccounting,
    AbstractRadiusBatch,
    AbstractRadiusCheck,
    AbstractRadiusGroup,
    AbstractRadiusGroupCheck,
    AbstractRadiusGroupReply,
    AbstractRadiusPostAuth,
    AbstractRadiusReply,
    AbstractRadiusToken,
    AbstractRadiusUserGroup,
    AbstractRegisteredUser,
)

User = get_user_model()

class DetailsModel(models.Model):
    details = models.CharField(max_length=64, blank=True, null=True)

    class Meta:
        abstract = True


class RadiusCheck(DetailsModel, AbstractRadiusCheck):
    class Meta(AbstractRadiusCheck.Meta):
        abstract = False


class RadiusReply(DetailsModel, AbstractRadiusReply):
    class Meta(AbstractRadiusReply.Meta):
        abstract = False


class RadiusAccounting(DetailsModel, AbstractRadiusAccounting):
    class Meta(AbstractRadiusAccounting.Meta):
        abstract = False


class RadiusGroup(DetailsModel, AbstractRadiusGroup):
    class Meta(AbstractRadiusGroup.Meta):
        abstract = False


class RadiusGroupCheck(DetailsModel, AbstractRadiusGroupCheck):
    class Meta(AbstractRadiusGroupCheck.Meta):
        abstract = False


class RadiusGroupReply(DetailsModel, AbstractRadiusGroupReply):
    class Meta(AbstractRadiusGroupReply.Meta):
        abstract = False


class RadiusUserGroup(DetailsModel, AbstractRadiusUserGroup):
    class Meta(AbstractRadiusUserGroup.Meta):
        abstract = False


class RadiusPostAuth(DetailsModel, AbstractRadiusPostAuth):
    class Meta(AbstractRadiusPostAuth.Meta):
        abstract = False


class Nas(DetailsModel, AbstractNas):
    class Meta(AbstractNas.Meta):
        abstract = False


class RadiusBatch(DetailsModel, AbstractRadiusBatch):
    class Meta(AbstractRadiusBatch.Meta):
        abstract = False


class RadiusToken(DetailsModel, AbstractRadiusToken):
    class Meta(AbstractRadiusToken.Meta):
        abstract = False


class OrganizationRadiusSettings(DetailsModel, AbstractOrganizationRadiusSettings):
    class Meta(AbstractOrganizationRadiusSettings.Meta):
        abstract = False


class PhoneToken(DetailsModel, AbstractPhoneToken):
    class Meta(AbstractPhoneToken.Meta):
        abstract = False


class RegisteredUser(DetailsModel, AbstractRegisteredUser):
    class Meta(AbstractRegisteredUser.Meta):
        abstract = False


def auto_create_registered_user(sender, instance, created, **kwargs):
    if created:
        RegisteredUser.objects.create(user=instance)


# Create a new RegisteredUser object for every user
signals.post_save.connect(
    auto_create_registered_user,
    sender=User,
    weak=False,
    dispatch_uid='models.auto_create_registered_user',
)
