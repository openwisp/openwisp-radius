import uuid

from django.core.cache import cache
from django.core.validators import RegexValidator, _lazy_re_compile
from django.db import models
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _
from django_freeradius.base.models import (AbstractNas, AbstractRadiusAccounting, AbstractRadiusBatch,
                                           AbstractRadiusCheck, AbstractRadiusGroupCheck,
                                           AbstractRadiusGroupReply, AbstractRadiusPostAuth,
                                           AbstractRadiusProfile, AbstractRadiusReply,
                                           AbstractRadiusUserGroup, AbstractRadiusUserProfile)
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


batch_name = AbstractRadiusBatch._meta.get_field('name')


class RadiusBatch(OrgMixin, AbstractRadiusBatch):
    name = models.CharField(batch_name.verbose_name,
                            max_length=batch_name.max_length,
                            help_text=batch_name.help_text,
                            db_index=batch_name.db_index,
                            unique=False)

    class Meta(AbstractRadiusBatch.Meta):
        abstract = False
        unique_together = ('name', 'organization')
        swappable = swappable_setting('openwisp_radius', 'RadiusBatch')


profile_name = AbstractRadiusProfile._meta.get_field('name')


class RadiusProfile(OrgMixin, AbstractRadiusProfile):
    name = models.CharField(profile_name.verbose_name,
                            max_length=profile_name.max_length,
                            help_text=profile_name.help_text,
                            db_index=profile_name.db_index,
                            unique=False)

    def _create_user_profile(self, **kwargs):
        options = dict(organization=self.organization)
        options.update(kwargs)
        return super(RadiusProfile, self)._create_user_profile(**options)

    class Meta(AbstractRadiusProfile.Meta):
        abstract = False
        unique_together = ('name', 'organization')
        swappable = swappable_setting('openwisp_radius', 'RadiusProfile')


class RadiusUserProfile(OrgMixin, AbstractRadiusUserProfile):
    def _get_instance(self, **kwargs):
        options = dict(organization=self.organization)
        options.update(kwargs)
        return super(RadiusUserProfile, self)._get_instance(**options)

    class Meta(AbstractRadiusUserProfile.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusUserProfile')


key_validator = RegexValidator(
    _lazy_re_compile('^[^\s/\.]+$'),
    message=_('Key must not contain spaces, dots or slashes.'),
    code='invalid',
)


def generate_token():
    return get_random_string(length=32)


class OrganizationRadiusSettings(OrgMixin, models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    token = models.CharField(max_length=32,
                             unique=True,
                             validators=[key_validator],
                             default=generate_token)

    def save(self, *args, **kwargs):
        super(OrganizationRadiusSettings, self).save(*args, **kwargs)
        cache.set(self.pk, self.token)

    def delete(self, *args, **kwargs):
        pk = self.pk
        super(OrganizationRadiusSettings, self).delete(*args, **kwargs)
        cache.delete(pk)
