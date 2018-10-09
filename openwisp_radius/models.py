import uuid

from django.core.cache import cache
from django.core.validators import RegexValidator, _lazy_re_compile
from django.db import models
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _
from django_freeradius.base.models import (AbstractNas, AbstractRadiusAccounting, AbstractRadiusBatch,
                                           AbstractRadiusCheck, AbstractRadiusGroup, AbstractRadiusGroupCheck,
                                           AbstractRadiusGroupReply, AbstractRadiusPostAuth,
                                           AbstractRadiusReply, AbstractRadiusUserGroup)
from swapper import swappable_setting

from openwisp_users.mixins import OrgMixin
from openwisp_users.models import OrganizationUser


class RadiusCheck(OrgMixin, AbstractRadiusCheck):
    class Meta(AbstractRadiusCheck.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusCheck')


class RadiusReply(OrgMixin, AbstractRadiusReply):
    class Meta(AbstractRadiusReply.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusReply')


class RadiusAccounting(OrgMixin, AbstractRadiusAccounting):
    class Meta(AbstractRadiusAccounting.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusAccounting')


class RadiusGroup(OrgMixin, AbstractRadiusGroup):
    def get_default_queryset(self):
        return super().get_default_queryset() \
                      .filter(organization_id=self.organization.pk)

    def clean(self):
        super().clean()
        if not self.name.startswith('{}-'.format(self.organization.slug)):
            self.name = '{}-{}'.format(self.organization.slug,
                                       self.name)

    class Meta(AbstractRadiusGroup.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusGroup')


class RadiusGroupCheck(AbstractRadiusGroupCheck):
    class Meta(AbstractRadiusGroupCheck.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusGroupCheck')


class RadiusGroupReply(AbstractRadiusGroupReply):
    class Meta(AbstractRadiusGroupReply.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusGroupReply')


class RadiusUserGroup(AbstractRadiusUserGroup):
    class Meta(AbstractRadiusUserGroup.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusUserGroup')


class RadiusPostAuth(OrgMixin, AbstractRadiusPostAuth):
    class Meta(AbstractRadiusPostAuth.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusPostAuth')


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

    def save_user(self, user):
        super().save_user(user)
        obj = OrganizationUser(user=user, organization=self.organization, is_admin=False)
        obj.full_clean()
        obj.save()

    class Meta(AbstractRadiusBatch.Meta):
        abstract = False
        unique_together = ('name', 'organization')
        swappable = swappable_setting('openwisp_radius', 'RadiusBatch')


key_validator = RegexValidator(
    _lazy_re_compile('^[^\s/\.]+$'),
    message=_('Key must not contain spaces, dots or slashes.'),
    code='invalid',
)


def generate_token():
    return get_random_string(length=32)


class OrganizationRadiusSettings(models.Model):
    id = models.UUIDField(default=uuid.uuid4,
                          primary_key=True,
                          editable=False)
    organization = models.OneToOneField('openwisp_users.Organization',
                                        verbose_name=_('organization'),
                                        related_name='radius_settings',
                                        on_delete=models.CASCADE)
    token = models.CharField(max_length=32,
                             validators=[key_validator],
                             default=generate_token)

    class Meta:
        verbose_name = _('Organization radius settings')
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.organization.name

    def save(self, *args, **kwargs):
        super(OrganizationRadiusSettings, self).save(*args, **kwargs)
        cache.set(self.pk, self.token)

    def delete(self, *args, **kwargs):
        pk = self.pk
        super(OrganizationRadiusSettings, self).delete(*args, **kwargs)
        cache.delete(pk)
