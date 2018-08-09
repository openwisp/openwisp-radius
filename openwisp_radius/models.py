from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import signals
from django_freeradius.base.models import (AbstractNas, AbstractRadiusAccounting, AbstractRadiusBatch,
                                           AbstractRadiusCheck, AbstractRadiusGroupCheck,
                                           AbstractRadiusGroupReply, AbstractRadiusPostAuth,
                                           AbstractRadiusProfile, AbstractRadiusReply,
                                           AbstractRadiusUserGroup, AbstractRadiusUserProfile)
from django_freeradius.utils import set_default_limits
from swapper import swappable_setting

from openwisp_users.mixins import OrgMixin


class RadiusCheck(OrgMixin, AbstractRadiusCheck):
    class Meta(AbstractRadiusCheck.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusCheck')


class RadiusAccounting(OrgMixin, AbstractRadiusAccounting):
    class Meta(AbstractRadiusAccounting.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusAccounting')


class RadiusReply(OrgMixin, AbstractRadiusReply):
    class Meta(AbstractRadiusReply.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusReply')


class RadiusGroupCheck(OrgMixin, AbstractRadiusGroupCheck):
    class Meta(AbstractRadiusGroupCheck.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusGroupCheck')


class RadiusGroupReply(OrgMixin, AbstractRadiusGroupReply):
    class Meta(AbstractRadiusGroupReply.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusGroupReply')


class RadiusPostAuth(OrgMixin, AbstractRadiusPostAuth):
    class Meta(AbstractRadiusPostAuth.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusPostAuth')


class RadiusUserGroup(OrgMixin, AbstractRadiusUserGroup):
    class Meta(AbstractRadiusUserGroup.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusUserGroup')


class Nas(OrgMixin, AbstractNas):
    class Meta(AbstractNas.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'Nas')


class RadiusBatch(OrgMixin, AbstractRadiusBatch):
    class Meta(AbstractRadiusBatch.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusBatch')


class RadiusProfile(OrgMixin, AbstractRadiusProfile):
    def _create_user_profile(self, **kwargs):
        options = dict(organization=self.organization)
        options.update(kwargs)
        return super(RadiusProfile, self)._create_user_profile(**options)

    class Meta(AbstractRadiusProfile.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusProfile')


class RadiusUserProfile(OrgMixin, AbstractRadiusUserProfile):
    def _create_radcheck(self, **kwargs):
        options = dict(organization=self.organization)
        options.update(kwargs)
        return super(RadiusUserProfile, self)._create_radcheck(**options)

    class Meta(AbstractRadiusUserProfile.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusUserProfile')


signals.post_save.connect(set_default_limits, sender=get_user_model())
