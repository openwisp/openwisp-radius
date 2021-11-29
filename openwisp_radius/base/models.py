import csv
import ipaddress
import json
import logging
import os
from base64 import encodebytes
from datetime import timedelta
from hashlib import md5, sha1
from io import StringIO
from os import urandom
from urllib.parse import urljoin

import phonenumbers
import swapper
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.mail import send_mail
from django.db import models
from django.db.models import Count, ProtectedError
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from jsonfield import JSONField
from model_utils.fields import AutoLastModifiedField
from passlib.hash import lmhash, nthash, sha512_crypt
from phonenumber_field.modelfields import PhoneNumberField
from private_storage.fields import PrivateFileField
from private_storage.storage.files import PrivateFileSystemStorage

from openwisp_radius.registration import REGISTRATION_METHOD_CHOICES
from openwisp_users.mixins import OrgMixin
from openwisp_utils.base import KeyField, TimeStampedEditableModel, UUIDModel

from .. import exceptions
from .. import settings as app_settings
from ..settings import (
    BATCH_DEFAULT_PASSWORD_LENGTH,
    BATCH_MAIL_MESSAGE,
    BATCH_MAIL_SENDER,
    BATCH_MAIL_SUBJECT,
)
from ..utils import (
    SmsMessage,
    find_available_username,
    generate_sms_token,
    get_sms_default_valid_until,
    load_model,
    prefix_generate_users,
    validate_csvfile,
)
from .validators import ipv6_network_validator

logger = logging.getLogger(__name__)
User = get_user_model()

OPTIONAL_FIELD_CHOICES = (
    ('disabled', _('Disabled')),
    ('allowed', _('Allowed')),
    ('mandatory', _('Mandatory')),
)

RADOP_CHECK_TYPES = (
    ('=', '='),
    (':=', ':='),
    ('==', '=='),
    ('+=', '+='),
    ('!=', '!='),
    ('>', '>'),
    ('>=', '>='),
    ('<', '<'),
    ('<=', '<='),
    ('=~', '=~'),
    ('!~', '!~'),
    ('=*', '=*'),
    ('!*', '!*'),
)
RAD_NAS_TYPES = app_settings.EXTRA_NAS_TYPES + (
    ('Async', 'Async'),
    ('Sync', 'Sync'),
    ('ISDN Sync', 'ISDN Sync'),
    ('ISDN Async V.120', 'ISDN Async V.120'),
    ('ISDN Async V.110', 'ISDN Async V.110'),
    ('Virtual', 'Virtual'),
    ('PIAFS', 'PIAFS'),
    ('HDLC Clear', 'HDLC Clear'),
    ('Channel', 'Channel'),
    ('X.25', 'X.25'),
    ('X.75', 'X.75'),
    ('G.3 Fax', 'G.3 Fax'),
    ('SDSL', 'SDSL - Symmetric DSL'),
    ('ADSL-CAP', 'ADSL-CAP'),
    ('ADSL-DMT', 'ADSL-DMT'),
    ('IDSL', 'IDSL'),
    ('Ethernet', 'Ethernet'),
    ('xDSL', 'xDSL'),
    ('Cable', 'Cable'),
    ('Wireless - Other', 'Wireless - Other'),
    ('IEEE 802.11', 'Wireless - IEEE 802.11'),
    ('Token-Ring', 'Token-Ring'),
    ('FDDI', 'FDDI'),
    ('Wireless - CDMA2000', 'Wireless - CDMA2000'),
    ('Wireless - UMTS', 'Wireless - UMTS'),
    ('Wireless - 1X-EV', 'Wireless - 1X-EV'),
    ('IAPP', 'IAPP'),
    ('FTTP', 'FTTP'),
    ('IEEE 802.16', 'Wireless - IEEE 802.16'),
    ('IEEE 802.20', 'Wireless - IEEE 802.20'),
    ('IEEE 802.22', 'Wireless - IEEE 802.22'),
    ('PPPoA', 'PPPoA - PPP over ATM'),
    ('PPPoEoA', 'PPPoEoA - PPP over Ethernet over ATM'),
    ('PPPoEoE', 'PPPoEoE - PPP over Ethernet over Ethernet'),
    ('PPPoEoVLAN', 'PPPoEoVLAN - PPP over Ethernet over VLAN'),
    ('PPPoEoQinQ', 'PPPoEoQinQ - PPP over Ethernet over IEEE 802.1QinQ'),
    ('xPON', 'xPON - Passive Optical Network'),
    ('Wireless - XGP', 'Wireless - XGP'),
    ('WiMAX', ' WiMAX Pre-Release 8 IWK Function'),
    ('WIMAX-WIFI-IWK', 'WIMAX-WIFI-IWK: WiMAX WIFI Interworking'),
    ('WIMAX-SFF', 'WIMAX-SFF: Signaling Forwarding Function for LTE/3GPP2'),
    ('WIMAX-HA-LMA', 'WIMAX-HA-LMA: WiMAX HA and or LMA function'),
    ('WIMAX-DHCP', 'WIMAX-DHCP: WIMAX DCHP service'),
    ('WIMAX-LBS', 'WIMAX-LBS: WiMAX location based service'),
    ('WIMAX-WVS', 'WIMAX-WVS: WiMAX voice service'),
    ('Other', 'Other'),
)
RADOP_REPLY_TYPES = (('=', '='), (':=', ':='), ('+=', '+='))
RADCHECK_ATTRIBUTE_TYPES = [
    'Max-Daily-Session',
    'Max-All-Session',
    'Max-Daily-Session-Traffic',
]
RADCHECK_PASSWD_TYPE = [
    'Cleartext-Password',
    'NT-Password',
    'LM-Password',
    'MD5-Password',
    'SMD5-Password',
    'SHA-Password',
    'SSHA-Password',
    'Crypt-Password',
]
RADCHECK_ATTRIBUTE_TYPES += RADCHECK_PASSWD_TYPE
_STRATEGIES = (('prefix', _('Generate from prefix')), ('csv', _('Import from CSV')))
_NOT_BLANK_MESSAGE = _('This field cannot be blank.')
_GET_IP_LIST_HELP_TEXT = _(
    'Comma separated list of IP addresses allowed to access freeradius API'
)
_GET_MOBILE_PREFIX_HELP_TEXT = _(
    'Comma separated list of international mobile prefixes '
    'allowed to register via the user registration API.'
)
_GET_OPTIONAL_FIELDS_HELP_TEXT = _(
    'Whether this field should be disabled, allowed or mandatory '
    'in the user registration API.'
)
_REGISTRATION_ENABLED_HELP_TEXT = _(
    'Whether the registration API endpoint should be enabled or not'
)
_SMS_VERIFICATION_HELP_TEXT = _(
    'Whether users who sign up should be required to verify their mobile '
    'phone number via SMS'
)
_ORGANIZATION_HELP_TEXT = _('The user is not a member of this organization')
_IDENTITY_VERIFICATION_ENABLED_HELP_TEXT = _(
    'Whether identity verification is required at the time of user registration'
)
_LOGIN_URL_HELP_TEXT = _('Enter the url where users can log in to the wifi service')
_STATUS_URL_HELP_TEXT = _('Enter the url where users can log out from the wifi service')


class AutoUsernameMixin(object):
    def clean(self):
        """
        automatically sets username
        """
        if (
            self.username
            and User.objects.filter(username=self.username).exists()
            and not self.user
        ):
            self.user = User.objects.get(username=self.username)

        if self.user:
            self.username = self.user.username
            if hasattr(self, 'organization') and not self.user.is_member(
                self.organization
            ):
                raise ValidationError({'organization': _ORGANIZATION_HELP_TEXT})
        elif not self.username:
            raise ValidationError(
                {'username': _NOT_BLANK_MESSAGE, 'user': _NOT_BLANK_MESSAGE}
            )


class AutoGroupnameMixin(object):
    def clean(self):
        """
        automatically sets groupname
        """
        super().clean()
        if self.group:
            self.groupname = self.group.name
        elif not self.groupname:
            raise ValidationError(
                {'groupname': _NOT_BLANK_MESSAGE, 'group': _NOT_BLANK_MESSAGE}
            )


class AbstractRadiusCheckQueryset(models.query.QuerySet):
    def filter_duplicate_username(self):
        pks = []
        for i in (
            self.values('username')
            .annotate(Count('id'))
            .order_by()
            .filter(id__count__gt=1)
        ):
            pks.extend([account.pk for account in self.filter(username=i['username'])])
        return self.filter(pk__in=pks)

    def filter_duplicate_value(self):
        pks = []
        for i in (
            self.values('value')
            .annotate(Count('id'))
            .order_by()
            .filter(id__count__gt=1)
        ):
            pks.extend([accounts.pk for accounts in self.filter(value=i['value'])])
        return self.filter(pk__in=pks)

    def filter_expired(self):
        return self.filter(valid_until__lt=now())

    def filter_not_expired(self):
        return self.filter(valid_until__gte=now())


def _encode_secret(attribute, new_value=None):
    if attribute == 'NT-Password':
        attribute_value = nthash.hash(new_value)
    elif attribute == 'LM-Password':
        attribute_value = lmhash.hash(new_value)
    elif attribute == 'MD5-Password':
        attribute_value = md5(new_value.encode('utf-8')).hexdigest()
    elif attribute == 'SMD5-Password':
        salt = urandom(4)
        hash = md5(new_value.encode('utf-8'))
        hash.update(salt)
        hash_encoded = encodebytes(hash.digest() + salt)
        attribute_value = hash_encoded.decode('utf-8')[:-1]
    elif attribute == 'SHA-Password':
        attribute_value = sha1(new_value.encode('utf-8')).hexdigest()
    elif attribute == 'SSHA-Password':
        salt = urandom(4)
        hash = sha1(new_value.encode('utf-8'))
        hash.update(salt)
        hash_encoded = encodebytes(hash.digest() + salt)
        attribute_value = hash_encoded.decode('utf-8')[:-1]
    elif attribute == 'Crypt-Password':
        attribute_value = sha512_crypt.hash(new_value)
    else:
        attribute_value = new_value
    return attribute_value


class AbstractRadiusCheckManager(models.Manager):
    def get_queryset(self):
        return AbstractRadiusCheckQueryset(self.model, using=self._db)

    def create(self, *args, **kwargs):
        if 'new_value' in kwargs:
            kwargs['value'] = _encode_secret(kwargs['attribute'], kwargs['new_value'])
            del kwargs['new_value']
        return super(AbstractRadiusCheckManager, self).create(*args, **kwargs)


class AbstractRadiusCheck(OrgMixin, AutoUsernameMixin, TimeStampedEditableModel):
    username = models.CharField(
        verbose_name=_('username'),
        max_length=64,
        db_index=True,
        # blank values are forbidden with custom validation
        # because this field can left blank if the user
        # foreign key is filled (it will be auto-filled)
        blank=True,
    )
    value = models.CharField(verbose_name=_('value'), max_length=253)
    op = models.CharField(
        verbose_name=_('operator'),
        max_length=2,
        choices=RADOP_CHECK_TYPES,
        default=':=',
    )
    attribute = models.CharField(
        verbose_name=_('attribute'),
        max_length=64,
        choices=[
            (i, i)
            for i in RADCHECK_ATTRIBUTE_TYPES
            if i not in app_settings.DISABLED_SECRET_FORMATS
        ],
        default=app_settings.DEFAULT_SECRET_FORMAT,
    )
    # the foreign key is not part of the standard freeradius schema
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, blank=True, null=True
    )
    # additional fields to enable more granular checks
    is_active = models.BooleanField(default=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    # internal notes
    notes = models.TextField(null=True, blank=True)
    # custom manager
    objects = AbstractRadiusCheckManager()

    class Meta:
        db_table = 'radcheck'
        verbose_name = _('check')
        verbose_name_plural = _('checks')
        abstract = True

    def __str__(self):
        return self.username


class AbstractRadiusReply(OrgMixin, AutoUsernameMixin, TimeStampedEditableModel):
    username = models.CharField(
        verbose_name=_('username'),
        max_length=64,
        db_index=True,
        # blank values are forbidden with custom validation
        # because this field can left blank if the user
        # foreign key is filled (it will be auto-filled)
        blank=True,
    )
    value = models.CharField(verbose_name=_('value'), max_length=253)
    op = models.CharField(
        verbose_name=_('operator'), max_length=2, choices=RADOP_REPLY_TYPES, default='='
    )
    attribute = models.CharField(verbose_name=_('attribute'), max_length=64)
    # the foreign key is not part of the standard freeradius schema
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, blank=True, null=True
    )

    class Meta:
        db_table = 'radreply'
        verbose_name = _('reply')
        verbose_name_plural = _('replies')
        abstract = True

    def __str__(self):
        return self.username


class AbstractRadiusAccounting(OrgMixin, models.Model):
    session_id = models.CharField(
        verbose_name=_('session ID'),
        max_length=64,
        db_column='acctsessionid',
        db_index=True,
    )
    unique_id = models.CharField(
        verbose_name=_('accounting unique ID'),
        max_length=32,
        db_column='acctuniqueid',
        unique=True,
        primary_key=True,
    )
    username = models.CharField(
        verbose_name=_('username'), max_length=64, db_index=True, null=True, blank=True
    )
    groupname = models.CharField(
        verbose_name=_('group name'), max_length=64, null=True, blank=True
    )
    realm = models.CharField(
        verbose_name=_('realm'), max_length=64, null=True, blank=True
    )
    nas_ip_address = models.GenericIPAddressField(
        verbose_name=_('NAS IP address'), db_column='nasipaddress', db_index=True
    )
    nas_port_id = models.CharField(
        verbose_name=_('NAS port ID'),
        max_length=15,
        db_column='nasportid',
        null=True,
        blank=True,
    )
    nas_port_type = models.CharField(
        verbose_name=_('NAS port type'),
        max_length=32,
        db_column='nasporttype',
        null=True,
        blank=True,
    )
    start_time = models.DateTimeField(
        verbose_name=_('start time'),
        db_column='acctstarttime',
        db_index=True,
        null=True,
        blank=True,
    )
    update_time = models.DateTimeField(
        verbose_name=_('update time'), db_column='acctupdatetime', null=True, blank=True
    )
    stop_time = models.DateTimeField(
        verbose_name=_('stop time'),
        db_column='acctstoptime',
        db_index=True,
        null=True,
        blank=True,
    )
    interval = models.IntegerField(
        verbose_name=_('interval'), db_column='acctinterval', null=True, blank=True
    )
    session_time = models.PositiveIntegerField(
        verbose_name=_('session time'),
        db_column='acctsessiontime',
        null=True,
        blank=True,
    )
    authentication = models.CharField(
        verbose_name=_('authentication'),
        max_length=32,
        db_column='acctauthentic',
        null=True,
        blank=True,
    )
    connection_info_start = models.CharField(
        verbose_name=_('connection info start'),
        max_length=50,
        db_column='connectinfo_start',
        null=True,
        blank=True,
    )
    connection_info_stop = models.CharField(
        verbose_name=_('connection info stop'),
        max_length=50,
        db_column='connectinfo_stop',
        null=True,
        blank=True,
    )
    input_octets = models.BigIntegerField(
        verbose_name=_('input octets'),
        db_column='acctinputoctets',
        null=True,
        blank=True,
    )
    output_octets = models.BigIntegerField(
        verbose_name=_('output octets'),
        db_column='acctoutputoctets',
        null=True,
        blank=True,
    )
    called_station_id = models.CharField(
        verbose_name=_('called station ID'),
        max_length=50,
        db_column='calledstationid',
        db_index=True,
        blank=True,
        null=True,
    )
    calling_station_id = models.CharField(
        verbose_name=_('calling station ID'),
        max_length=50,
        db_column='callingstationid',
        db_index=True,
        blank=True,
        null=True,
    )
    terminate_cause = models.CharField(
        verbose_name=_('termination cause'),
        max_length=32,
        db_column='acctterminatecause',
        blank=True,
        null=True,
    )
    service_type = models.CharField(
        verbose_name=_('service type'),
        max_length=32,
        db_column='servicetype',
        null=True,
        blank=True,
    )
    framed_protocol = models.CharField(
        verbose_name=_('framed protocol'),
        max_length=32,
        db_column='framedprotocol',
        null=True,
        blank=True,
    )
    framed_ip_address = models.GenericIPAddressField(
        verbose_name=_('framed IP address'),
        db_column='framedipaddress',
        # the default MySQL freeradius schema defines
        # this as NOT NULL but defaulting to empty string
        # but that wouldn't work on PostgreSQL
        null=True,
        blank=True,
    )
    framed_ipv6_address = models.GenericIPAddressField(
        verbose_name=_('framed IPv6 address'),
        db_column='framedipv6address',
        protocol='IPv6',
        null=True,
        blank=True,
    )
    framed_ipv6_prefix = models.CharField(
        verbose_name=_('framed IPv6 prefix'),
        max_length=44,
        db_column='framedipv6prefix',
        validators=[ipv6_network_validator],
        null=True,
        blank=True,
    )
    framed_interface_id = models.CharField(
        verbose_name=_('framed interface ID'),
        max_length=19,
        db_column='framedinterfaceid',
        null=True,
        blank=True,
    )
    delegated_ipv6_prefix = models.CharField(
        verbose_name=_('delegated IPv6 prefix'),
        max_length=44,
        db_column='delegatedipv6prefix',
        validators=[ipv6_network_validator],
        null=True,
        blank=True,
    )

    def save(self, *args, **kwargs):
        if not self.start_time:
            self.start_time = now()
        super(AbstractRadiusAccounting, self).save(*args, **kwargs)

    class Meta:
        db_table = 'radacct'
        verbose_name = _('accounting')
        verbose_name_plural = _('accountings')
        abstract = True

    def __str__(self):
        return self.unique_id


class AbstractNas(OrgMixin, TimeStampedEditableModel):
    name = models.CharField(
        verbose_name=_('name'),
        max_length=128,
        help_text=_('NAS Name (or IP address)'),
        db_index=True,
        db_column='nasname',
    )
    short_name = models.CharField(
        verbose_name=_('short name'), max_length=32, db_column='shortname'
    )
    type = models.CharField(
        verbose_name=_('type'), max_length=30, default='other', choices=RAD_NAS_TYPES
    )
    ports = models.PositiveIntegerField(verbose_name=_('ports'), blank=True, null=True)
    secret = models.CharField(
        verbose_name=_('secret'), max_length=60, help_text=_('Shared Secret')
    )
    server = models.CharField(
        verbose_name=_('server'), max_length=64, blank=True, null=True
    )
    community = models.CharField(
        verbose_name=_('community'), max_length=50, blank=True, null=True
    )
    description = models.CharField(
        verbose_name=_('description'), max_length=200, null=True, blank=True
    )

    class Meta:
        db_table = 'nas'
        verbose_name = _('NAS')
        verbose_name_plural = _('NAS')
        abstract = True

    def __str__(self):
        return self.name


class AbstractRadiusGroup(OrgMixin, TimeStampedEditableModel):
    """
    This is not part of the standard freeradius schema.
    It's added to facilitate the management of groups.
    """

    name = models.CharField(
        verbose_name=_('group name'), max_length=255, unique=True, db_index=True
    )
    description = models.CharField(
        verbose_name=_('description'), max_length=64, blank=True, null=True
    )
    _DEFAULT_HELP_TEXT = (
        'The default group is automatically assigned to new users; '
        'changing the default group has only effect on new users '
        '(existing users will keep being members of their current group)'
    )
    default = models.BooleanField(
        verbose_name=_('is default?'), help_text=_(_DEFAULT_HELP_TEXT), default=False
    )

    class Meta:
        verbose_name = _('group')
        verbose_name_plural = _('groups')
        abstract = True

    def __str__(self):
        return self.name

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initial_default = self.default

    def clean(self):
        self.check_default()
        if not hasattr(self, 'organization'):
            return
        if not self.name.startswith(f'{self.organization.slug}-'):
            self.name = f'{self.organization.slug}-{self.name}'

    def save(self, *args, **kwargs):
        result = super().save(*args, **kwargs)
        if self.default:
            self.set_default()
        # sync all related records
        if not self._state.adding:
            self.radiusgroupcheck_set.update(groupname=self.name)
            self.radiusgroupreply_set.update(groupname=self.name)
            self.radiususergroup_set.update(groupname=self.name)
        return result

    _DEFAULT_VALIDATION_ERROR = _(
        'There must be at least one default group present in '
        'the system. To change the default group, simply set '
        'as default the group you want to make the new default.'
    )
    _DEFAULT_PROTECTED_ERROR = _('The default group cannot be deleted')

    def delete(self, *args, **kwargs):
        if self.default:
            raise ProtectedError(self._DEFAULT_PROTECTED_ERROR, self)
        return super().delete(*args, **kwargs)

    def set_default(self):
        """
        ensures there's only 1 default group
        (logic overridable via custom models)
        """
        queryset = self.get_default_queryset()
        if queryset.exists():
            queryset.update(default=False)

    def check_default(self):
        """
        ensures the default group cannot be undefaulted
        (logic overridable via custom models)
        """
        if not self.default and self._initial_default:
            raise ValidationError({'default': self._DEFAULT_VALIDATION_ERROR})

    def get_default_queryset(self):
        """
        looks for default groups excluding the current one
        overridable by openwisp-radius and other 3rd party apps
        """
        return self.__class__.objects.exclude(pk=self.pk).filter(
            default=True, organization_id=self.organization.pk
        )


class AbstractRadiusUserGroup(
    AutoGroupnameMixin, AutoUsernameMixin, TimeStampedEditableModel
):
    username = models.CharField(
        verbose_name=_('username'),
        max_length=64,
        db_index=True,
        # blank values are forbidden with custom validation
        # because this field can left blank if the user
        # foreign key is filled (it will be auto-filled)
        blank=True,
    )
    groupname = models.CharField(
        verbose_name=_('group name'),
        max_length=64,
        # blank values are forbidden with custom validation
        # because this field can left blank if the group
        # foreign key is filled (it will be auto-filled)
        blank=True,
    )
    priority = models.IntegerField(verbose_name=_('priority'), default=1)
    # the foreign keys are not part of the standard freeradius schema,
    # these are added here to facilitate the synchronization of the
    # records which are related in different tables
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, blank=True, null=True
    )
    group = models.ForeignKey(
        'RadiusGroup', on_delete=models.CASCADE, blank=True, null=True
    )

    class Meta:
        db_table = 'radusergroup'
        verbose_name = _('user group')
        verbose_name_plural = _('user groups')
        unique_together = ('user', 'group')
        abstract = True

    def __str__(self):
        return str(self.username)


class AbstractRadiusGroupCheck(AutoGroupnameMixin, TimeStampedEditableModel):
    groupname = models.CharField(
        verbose_name=_('group name'),
        max_length=64,
        db_index=True,
        # blank values are forbidden with custom validation
        # because this field can left blank if the group
        # foreign key is filled (it will be auto-filled)
        blank=True,
    )
    attribute = models.CharField(verbose_name=_('attribute'), max_length=64)
    op = models.CharField(
        verbose_name=_('operator'),
        max_length=2,
        choices=RADOP_CHECK_TYPES,
        default=':=',
    )
    value = models.CharField(verbose_name=_('value'), max_length=253)
    # the foreign key is not part of the standard freeradius schema
    group = models.ForeignKey(
        'RadiusGroup', on_delete=models.CASCADE, blank=True, null=True
    )

    class Meta:
        db_table = 'radgroupcheck'
        verbose_name = _('group check')
        verbose_name_plural = _('group checks')
        abstract = True

    def __str__(self):
        return str(self.groupname)


class AbstractRadiusGroupReply(AutoGroupnameMixin, TimeStampedEditableModel):
    groupname = models.CharField(
        verbose_name=_('group name'),
        max_length=64,
        db_index=True,
        # blank values are forbidden with custom validation
        # because this field can left blank if the group
        # foreign key is filled (it will be auto-filled)
        blank=True,
    )
    attribute = models.CharField(verbose_name=_('attribute'), max_length=64)
    op = models.CharField(
        verbose_name=_('operator'), max_length=2, choices=RADOP_REPLY_TYPES, default='='
    )
    value = models.CharField(verbose_name=_('value'), max_length=253)
    # the foreign key is not part of the standard freeradius schema
    group = models.ForeignKey(
        'RadiusGroup', on_delete=models.CASCADE, blank=True, null=True
    )

    class Meta:
        db_table = 'radgroupreply'
        verbose_name = _('group reply')
        verbose_name_plural = _('group replies')
        abstract = True

    def __str__(self):
        return str(self.groupname)


class AbstractRadiusPostAuth(OrgMixin, UUIDModel):
    username = models.CharField(verbose_name=_('username'), max_length=64)
    password = models.CharField(
        verbose_name=_('password'), max_length=64, db_column='pass', blank=True
    )
    reply = models.CharField(verbose_name=_('reply'), max_length=32)
    called_station_id = models.CharField(
        verbose_name=_('called station ID'),
        max_length=50,
        db_column='calledstationid',
        blank=True,
        null=True,
    )
    calling_station_id = models.CharField(
        verbose_name=_('calling station ID'),
        max_length=50,
        db_column='callingstationid',
        blank=True,
        null=True,
    )
    date = models.DateTimeField(
        verbose_name=_('date'), db_column='authdate', auto_now_add=True
    )

    class Meta:
        db_table = 'radpostauth'
        verbose_name = _('post auth')
        verbose_name_plural = _('post auth log')
        abstract = True

    def __str__(self):
        return str(self.username)


_get_csv_file_private_storage = PrivateFileSystemStorage(
    location=settings.PRIVATE_STORAGE_ROOT,
    base_url=urljoin(app_settings.RADIUS_API_BASEURL, app_settings.CSV_URL_PATH),
)


def _get_csv_file_location(instance, filename):
    return os.path.join(str(instance.organization.pk), filename)


class AbstractRadiusBatch(OrgMixin, TimeStampedEditableModel):
    strategy = models.CharField(
        _('strategy'),
        max_length=16,
        choices=_STRATEGIES,
        db_index=True,
        help_text=_('Import users from a CSV or generate using a prefix'),
    )
    name = models.CharField(
        verbose_name=_('name'),
        max_length=128,
        help_text=_('A unique batch name'),
        db_index=True,
        unique=False,
    )
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='radius_batch',
        help_text=_('List of users uploaded in this batch'),
    )
    csvfile = PrivateFileField(
        null=True,
        blank=True,
        verbose_name='CSV',
        storage=_get_csv_file_private_storage,
        upload_to=_get_csv_file_location,
        help_text=_('The csv file containing the user details to be uploaded'),
        max_file_size=app_settings.MAX_CSV_FILE_SIZE,
    )
    prefix = models.CharField(
        _('prefix'),
        null=True,
        blank=True,
        max_length=20,
        help_text=_('Usernames generated will be of the format [prefix][number]'),
    )
    # List of usernames and passwords used to create PDF
    user_credentials = JSONField(
        null=True,
        blank=True,
        verbose_name='PDF',
    )
    expiration_date = models.DateField(
        verbose_name=_('expiration date'),
        null=True,
        blank=True,
        help_text=_('If left blank users will never expire'),
    )

    class Meta:
        db_table = 'radbatch'
        unique_together = ('name', 'organization')
        verbose_name = _('batch user creation')
        verbose_name_plural = _('batch user creation operations')
        abstract = True

    def __str__(self):
        return self.name

    def clean(self):
        if self.strategy == 'csv' and not self.csvfile:
            raise ValidationError(
                {'csvfile': _('This field cannot be blank.')}, code='invalid'
            )
        if self.strategy == 'prefix' and not self.prefix:
            raise ValidationError(
                {'prefix': _('This field cannot be blank.')}, code='invalid'
            )
        if (
            self.strategy == 'csv'
            and self.prefix
            or self.strategy == 'prefix'
            and self.csvfile
        ):
            # this case would happen only when using the internal API
            raise ValidationError(
                _('Mixing fields of different strategies'), code='invalid'
            )
        if self.strategy == 'csv':
            validate_csvfile(self.csvfile.file)
        super().clean()

    def add(self, reader, password_length=BATCH_DEFAULT_PASSWORD_LENGTH):
        users_list = []
        generated_passwords = []
        for row in reader:
            if len(row) == 5:
                user, password = self.get_or_create_user(
                    row, users_list, password_length
                )
                users_list.append(user)
                if password:
                    generated_passwords.append(password)
        for user in users_list:
            self.save_user(user)
        for element in generated_passwords:
            username, password, user_email = element
            send_mail(
                BATCH_MAIL_SUBJECT,
                BATCH_MAIL_MESSAGE.format(username, password),
                BATCH_MAIL_SENDER,
                [user_email],
            )

    def csvfile_upload(
        self, csvfile=None, password_length=BATCH_DEFAULT_PASSWORD_LENGTH
    ):
        if not csvfile:
            csvfile = self.csvfile
        csv_data = csvfile.read()
        csv_data = csv_data.decode('utf-8') if isinstance(csv_data, bytes) else csv_data
        reader = csv.reader(StringIO(csv_data), delimiter=',')
        self.full_clean()
        self.save()
        self.add(reader, password_length)

    def prefix_add(self, prefix, n, password_length=BATCH_DEFAULT_PASSWORD_LENGTH):
        users_list, user_credentials = prefix_generate_users(prefix, n, password_length)
        for user in users_list:
            user.full_clean()
            self.save_user(user)
        self.user_credentials = json.dumps(user_credentials)
        self.full_clean()
        self.save()

    def get_or_create_user(self, row, users_list, password_length):
        User = get_user_model()
        username, password, email, first_name, last_name = row
        if email and User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            return user, None
        generated_password = None
        username, password, email, first_name, last_name = row
        if not username and email:
            username = email.split('@')[0]
        username = find_available_username(username, users_list)
        user = User(
            username=username, email=email, first_name=first_name, last_name=last_name
        )
        cleartext_delimiter = 'cleartext$'
        if not password:
            password = get_random_string(length=password_length)
            user.set_password(password)
            generated_password = [username, password, email]
        elif password and password.startswith(cleartext_delimiter):
            password = password[len(cleartext_delimiter) :]
            user.set_password(password)
        else:
            user.password = password
        user.full_clean()
        return user, generated_password

    def save_user(self, user):
        OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
        user.save()
        self.users.add(user)
        if OrganizationUser.objects.filter(
            user=user, organization=self.organization
        ).exists():
            return
        obj = OrganizationUser(
            user=user, organization=self.organization, is_admin=False
        )
        obj.full_clean()
        obj.save()

    def delete(self):
        self.users.all().delete()
        super().delete()
        self._remove_files()

    def expire(self):
        users = self.users.all()
        for u in users:
            u.is_active = False
            u.save()

    def _remove_files(self):
        if self.csvfile:
            path = self.csvfile.path
            if os.path.isfile(path):
                os.remove(path)


class AbstractRadiusToken(OrgMixin, TimeStampedEditableModel, models.Model):
    # key field is a primary key so additional id field will be redundant
    id = None
    # tokens are not supposed to be modified, can be regenerated if necessary
    modified = None
    key = models.CharField(_('Key'), max_length=40, primary_key=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='radius_token'
    )
    can_auth = models.BooleanField(
        default=False,
        help_text=(
            'Enable the radius token to be used for freeradius authorization request'
        ),
    )

    class Meta:
        db_table = 'radiustoken'
        verbose_name = _('radius token')
        verbose_name_plural = _('radius token')
        abstract = True

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super().save(*args, **kwargs)

    def delete_cache(self, *args, **kwargs):
        username = f'rt-{self.user.username}'
        if cache.get(username):
            cache.delete(username)

    def generate_key(self):
        return get_random_string(length=40)

    def __str__(self):
        return self.key


class AbstractOrganizationRadiusSettings(UUIDModel):
    organization = models.OneToOneField(
        swapper.get_model_name('openwisp_users', 'Organization'),
        verbose_name=_('organization'),
        related_name='radius_settings',
        on_delete=models.CASCADE,
    )
    token = KeyField(max_length=32)
    sms_verification = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text=_SMS_VERIFICATION_HELP_TEXT,
    )
    needs_identity_verification = models.BooleanField(
        null=True,
        blank=True,
        default=None,
        help_text=_IDENTITY_VERIFICATION_ENABLED_HELP_TEXT,
    )
    sms_sender = models.CharField(
        _('Sender'),
        max_length=128,
        blank=True,
        null=True,
        help_text=_(
            'alpha numeric identifier used as sender for SMS sent by this organization'
        ),
    )
    sms_meta_data = JSONField(
        null=True,
        blank=True,
        help_text=_(
            'Additional configuration for SMS backend in JSON format (optional)'
        ),
    )
    freeradius_allowed_hosts = models.TextField(
        null=True,
        blank=True,
        help_text=_GET_IP_LIST_HELP_TEXT,
    )
    allowed_mobile_prefixes = models.TextField(
        null=True,
        blank=True,
        help_text=_GET_MOBILE_PREFIX_HELP_TEXT,
    )
    first_name = models.CharField(
        verbose_name=_('first name'),
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        max_length=12,
        null=True,
        blank=True,
        choices=OPTIONAL_FIELD_CHOICES,
    )
    last_name = models.CharField(
        verbose_name=_('last name'),
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        max_length=12,
        null=True,
        blank=True,
        choices=OPTIONAL_FIELD_CHOICES,
    )
    location = models.CharField(
        verbose_name=_('location'),
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        max_length=12,
        null=True,
        blank=True,
        choices=OPTIONAL_FIELD_CHOICES,
    )
    birth_date = models.CharField(
        verbose_name=_('birth date'),
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        max_length=12,
        null=True,
        blank=True,
        choices=OPTIONAL_FIELD_CHOICES,
    )
    registration_enabled = models.BooleanField(
        null=True,
        blank=True,
        default=True,
        help_text=_REGISTRATION_ENABLED_HELP_TEXT,
    )
    login_url = models.URLField(null=True, blank=True, help_text=_LOGIN_URL_HELP_TEXT)
    status_url = models.URLField(null=True, blank=True, help_text=_STATUS_URL_HELP_TEXT)

    class Meta:
        verbose_name = _('Organization radius settings')
        verbose_name_plural = verbose_name
        abstract = True

    def __str__(self):
        return self.organization.name

    @property
    def freeradius_allowed_hosts_list(self):
        addresses = []
        if self.freeradius_allowed_hosts:
            addresses = self.freeradius_allowed_hosts.split(',')
        return addresses

    @property
    def allowed_mobile_prefixes_list(self):
        mobile_prefixes = []
        if self.allowed_mobile_prefixes:
            mobile_prefixes = self.allowed_mobile_prefixes.split(',')
        return mobile_prefixes

    def get_registration_enabled(self):
        if self.registration_enabled is None:
            return app_settings.REGISTRATION_API_ENABLED
        return self.registration_enabled

    def get_sms_verification(self):
        if self.sms_verification is None:
            return app_settings.SMS_VERIFICATION_ENABLED
        return self.sms_verification

    def clean(self):
        if self.get_sms_verification() and not self.sms_sender:
            raise ValidationError(
                {
                    'sms_sender': _(
                        'if SMS verification is enabled this field is required.'
                    )
                }
            )
        self._clean_freeradius_allowed_hosts()
        self._clean_allowed_mobile_prefixes()
        self._clean_optional_fields()

    def _clean_freeradius_allowed_hosts(self):
        allowed_hosts_set = set(self.freeradius_allowed_hosts_list)
        settings_allowed_hosts_set = set(app_settings.FREERADIUS_ALLOWED_HOSTS)
        if not allowed_hosts_set and not settings_allowed_hosts_set:
            raise ValidationError(
                {
                    'freeradius_allowed_hosts': _(
                        'Cannot be empty when the settings value for '
                        '`OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS` is not provided.'
                    )
                }
            )
        elif allowed_hosts_set:
            if allowed_hosts_set == settings_allowed_hosts_set:
                self.freeradius_allowed_hosts = None
            else:
                try:
                    for ip_address in allowed_hosts_set:
                        ipaddress.ip_network(ip_address)
                except ValueError:
                    raise ValidationError(
                        {
                            'freeradius_allowed_hosts': _(
                                'Invalid input. Please enter valid ip addresses '
                                'or subnets separated by comma. (no spaces)'
                            )
                        }
                    )

    def _clean_allowed_mobile_prefixes(self):
        valid_country_codes = phonenumbers.COUNTRY_CODE_TO_REGION_CODE.keys()
        allowed_mobile_prefixes_set = set(self.allowed_mobile_prefixes_list)
        settings_allowed_mobile_prefixes_set = set(app_settings.ALLOWED_MOBILE_PREFIXES)
        for code in self.allowed_mobile_prefixes_list:
            if not code or code[0] != '+' or int(code[1:]) not in valid_country_codes:
                raise ValidationError(
                    {
                        'allowed_mobile_prefixes': _(
                            'Invalid input. Please enter valid mobile '
                            'prefixes separated by comma. (no spaces)'
                        )
                    }
                )

        if allowed_mobile_prefixes_set == settings_allowed_mobile_prefixes_set:
            self.allowed_mobile_prefixes = None

    def _clean_optional_fields(self):
        global_settings = app_settings.OPTIONAL_REGISTRATION_FIELDS
        for field in ['first_name', 'last_name', 'location', 'birth_date']:
            if getattr(self, field) == global_settings.get(field):
                setattr(self, field, None)

    def save_cache(self, *args, **kwargs):
        cache.set(self.organization.pk, self.token)
        cache.set(f'ip-{self.organization.pk}', self.freeradius_allowed_hosts_list)

    def delete_cache(self, *args, **kwargs):
        cache.delete(self.organization.pk)
        cache.delete(f'ip-{self.organization.pk}')


class AbstractPhoneToken(TimeStampedEditableModel):
    """
    Phone Verification Token (sent via SMS)
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    valid_until = models.DateTimeField(default=get_sms_default_valid_until)
    attempts = models.PositiveIntegerField(default=0)
    verified = models.BooleanField(default=False)
    token = models.CharField(max_length=8, editable=False, default=generate_sms_token)
    ip = models.GenericIPAddressField()
    # if users change their phone number, a record of the previously
    # verified phone numbers is kept thanks to this field
    phone_number = PhoneNumberField(blank=False, null=False)

    class Meta:
        verbose_name = _('Phone verification token')
        verbose_name_plural = _('Phone verification tokens')
        ordering = ('-created',)
        index_together = (('user', 'created'), ('user', 'created', 'ip'))
        abstract = True

    def clean(self):
        if not hasattr(self, 'user'):
            return
        self._validate_phone_number_uniqueness()
        self._validate_max_attempts()

    def _validate_phone_number_uniqueness(self):
        """
        Users cannot create a phone token if the number
        is already taken by another user
        """
        phone_number_already_taken = (
            User.objects.filter(phone_number=self.phone_number)
            .exclude(pk=self.user.pk)
            .exists()
        )
        if phone_number_already_taken:
            raise ValidationError(
                {
                    'phone_number': _(
                        'This phone number is already associated to another user.'
                    )
                }
            )

    def _validate_max_attempts(self):
        """
        Enforce limits on the creation of phone tokens to prevent abuse
        which can lead to excessive expenditure for sending SMS
        """
        date_start = timezone.localdate()
        date_end = date_start + timedelta(days=1)
        PhoneToken = load_model('PhoneToken')
        qs = PhoneToken.objects.filter(created__range=[date_start, date_end])
        # limit generation of tokens per day by user
        user_token_count = qs.filter(user=self.user).count()
        if user_token_count >= app_settings.SMS_TOKEN_MAX_USER_DAILY:
            logger.warning(
                f'The user {self.user} has reached the maximum daily SMS limit.'
            )
            raise ValidationError(_('Maximum daily limit reached.'))
        # limit generation of tokens per day by ip
        ip_token_count = qs.filter(ip=self.ip).count()
        if ip_token_count >= app_settings.SMS_TOKEN_MAX_IP_DAILY:
            logger.warning(
                logger.warning(
                    _(
                        f'User {self.user} has reached the maximum '
                        f'daily SMS limit from ip address {self.ip}'
                    )
                )
            )
            raise ValidationError(
                _('Maximum daily limit reached from this IP address.')
            )

    def save(self, *args, **kwargs):
        created = self._state.adding
        result = super().save(*args, **kwargs)
        if created:
            self.send_token()
        return result

    def send_token(self):
        OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
        org_user = OrganizationUser.objects.filter(user=self.user).first()
        if not org_user:
            raise exceptions.NoOrgException(
                _('The user {user} is not member of any organization').format(
                    user=self.user
                )
            )
        org_radius_settings = org_user.organization.radius_settings
        message = _('{organization} verification code: {code}').format(
            organization=org_radius_settings.organization.name, code=self.token
        )
        sms_message = SmsMessage(
            body=str(message),
            from_phone=str(org_radius_settings.sms_sender),
            to=[str(self.phone_number)],
        )
        sms_message.send(meta_data=org_radius_settings.sms_meta_data)

    def is_valid(self, token):
        self.attempts += 1
        try:
            self.verified = self.__check(token)
        except exceptions.PhoneTokenException as phone_error:
            self.save()
            raise phone_error
        self.save()
        return self.verified

    def _validate_already_verified(self):
        try:
            if self.user.registered_user.is_verified:
                logger.warning(f'User {self.user.pk} is already verified')
                raise exceptions.UserAlreadyVerified(
                    _('This user has been already verified.')
                )
        except ObjectDoesNotExist:
            pass

    def __check(self, token):
        self._validate_already_verified()
        if self.attempts > app_settings.SMS_TOKEN_MAX_ATTEMPTS:
            logger.warning(
                f'User {self.user} has reached the max '
                f'attempt limit for token {self.pk}.'
            )
            raise exceptions.MaxAttemptsException(
                _('Maximum number of attempts reached, request a new code.')
            )
        if timezone.now() > self.valid_until:
            logger.warning(
                f'User {self.user} has tried to verify an expired token: {self.pk}.'
            )
            raise exceptions.ExpiredTokenException(
                _(
                    'This verification code has expired, '
                    'Please send a new code and try again.'
                )
            )
        return token == self.token


class AbstractRegisteredUser(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='registered_user',
        primary_key=True,
    )
    method = models.CharField(
        _('registration method'),
        help_text=_(
            'users can sign up in different ways, some methods are valid as '
            'indirect identity verification (eg: mobile phone SIM card in '
            'most countries)'
        ),
        max_length=64,
        blank=True,
        default='',
        choices=REGISTRATION_METHOD_CHOICES,
    )
    is_verified = models.BooleanField(
        _('verified'),
        help_text=_(
            'whether the user has completed any identity '
            'verification process sucessfully'
        ),
        default=False,
    )
    modified = AutoLastModifiedField(_('Last verification change'), editable=True)
    _weak_verification_methods = {'', 'email'}

    @property
    def is_identity_verified_strong(self):
        return self.is_verified and self.method not in self._weak_verification_methods

    class Meta:
        abstract = True
        verbose_name = _('Registration Information')
        verbose_name_plural = verbose_name
