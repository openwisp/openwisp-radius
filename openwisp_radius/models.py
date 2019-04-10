import logging

from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from django.utils.translation import ugettext_lazy as _
from django_freeradius.base.models import (AbstractNas, AbstractRadiusAccounting, AbstractRadiusBatch,
                                           AbstractRadiusCheck, AbstractRadiusGroup, AbstractRadiusGroupCheck,
                                           AbstractRadiusGroupReply, AbstractRadiusPostAuth,
                                           AbstractRadiusReply, AbstractRadiusToken, AbstractRadiusUserGroup)
from swapper import swappable_setting

from openwisp_users.mixins import OrgMixin
from openwisp_users.models import OrganizationUser

from openwisp_utils.base import KeyField, UUIDModel, TimeStampedEditableModel

from . import exceptions
from . import settings as app_settings
from .utils import generate_sms_token, get_sms_default_valid_until

logger = logging.getLogger(__name__)


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
        if not hasattr(self, 'organization'):
            return
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
        if OrganizationUser.objects.filter(user=user, organization=self.organization).exists():
            return
        obj = OrganizationUser(user=user, organization=self.organization, is_admin=False)
        obj.full_clean()
        obj.save()

    def get_or_create_user(self, row, users_list, password_length):
        User = get_user_model()
        username, password, email, first_name, last_name = row
        if email and User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            return user, None
        return super().get_or_create_user(row, users_list, password_length)

    class Meta(AbstractRadiusBatch.Meta):
        abstract = False
        unique_together = ('name', 'organization')
        swappable = swappable_setting('openwisp_radius', 'RadiusBatch')


class RadiusToken(AbstractRadiusToken):
    class Meta(AbstractRadiusToken.Meta):
        abstract = False
        swappable = swappable_setting('openwisp_radius', 'RadiusToken')


class OrganizationRadiusSettings(UUIDModel):
    organization = models.OneToOneField('openwisp_users.Organization',
                                        verbose_name=_('organization'),
                                        related_name='radius_settings',
                                        on_delete=models.CASCADE)
    token = KeyField(max_length=32)
    sms_verification = models.BooleanField(default=app_settings.SMS_DEFAULT_VERIFICATION,
                                           help_text=_('whether users who sign up should '
                                                       'be required to verify their mobile '
                                                       'phone number via SMS'))

    class Meta:
        verbose_name = _('Organization radius settings')
        verbose_name_plural = verbose_name

    def __str__(self):
        return self.organization.name

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        cache.set(self.organization.pk, self.token)

    def delete(self, *args, **kwargs):
        pk = self.organization.pk
        super().delete(*args, **kwargs)
        cache.delete(pk)


class PhoneToken(TimeStampedEditableModel):
    """
    Phone Verification Token (sent via SMS)
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    valid_until = models.DateTimeField(default=get_sms_default_valid_until)
    attempts = models.PositiveIntegerField(default=0)
    verified = models.BooleanField(default=False)
    token = models.CharField(max_length=8,
                             editable=False,
                             default=generate_sms_token)
    ip = models.GenericIPAddressField()

    class Meta:
        verbose_name = _('Phone verification token')
        verbose_name_plural = _('Phone verification tokens')
        ordering = ('-created',)
        index_together = (
            ('user', 'created'),
            ('user', 'created', 'ip'),
        )

    def clean(self):
        if not hasattr(self, 'user'):
            return
        if not self.user.phone_number:
            message = 'user does not have a phone number'
            logger.warning(message)
            raise ValidationError({'user': _(message)})
        date_start = self.created.date()
        date_end = date_start + timedelta(days=1)
        qs = PhoneToken.objects.filter(created__range=[date_start,
                                                       date_end])
        # limit generation of tokens per day by user
        user_token_count = qs.filter(user=self.user) \
                             .count()
        if user_token_count >= app_settings.SMS_TOKEN_MAX_USER_DAILY:
            message = 'maximum daily limit reached'
            logger.warning(message)
            raise ValidationError({'user': _(message)})
        # limit generation of tokens per day by ip
        ip_token_count = qs.filter(ip=self.ip).count()
        if ip_token_count >= app_settings.SMS_TOKEN_MAX_IP_DAILY:
            message = 'maximum daily limit reached ' \
                      'from this ip address'
            logger.warning(message)
            raise ValidationError({'ip': _(message)})

    def is_valid(self, token):
        self.attempts += 1
        if self.attempts > app_settings.SMS_TOKEN_MAX_ATTEMPTS:
            self.save()
            raise exceptions.MaxAttemptsException()
        if timezone.now() > self.valid_until:
            self.save()
            raise exceptions.ExpiredTokenException()
        valid = token == self.token
        if valid:
            self.verified = True
        self.save()
        return valid
