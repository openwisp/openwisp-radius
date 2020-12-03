import logging

import phonenumbers
import swapper
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from dj_rest_auth.registration.serializers import (
    RegisterSerializer as BaseRegisterSerializer,
)
from dj_rest_auth.serializers import (
    PasswordResetSerializer as BasePasswordResetSerializer,
)
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import AllowAllUsersModelBackend
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from rest_framework.authtoken.serializers import (
    AuthTokenSerializer as BaseAuthTokenSerializer,
)

from .. import settings as app_settings
from ..base.forms import PasswordResetForm
from ..utils import load_model
from .utils import ErrorDictMixin, is_sms_verification_enabled

logger = logging.getLogger(__name__)

RadiusPostAuth = load_model('RadiusPostAuth')
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
RadiusToken = load_model('RadiusToken')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
Organization = swapper.load_model('openwisp_users', 'Organization')
User = get_user_model()


class AuthTokenSerializer(BaseAuthTokenSerializer):
    """
    Recognizes also inactive users.
    The API will still reject these users but the
    consumers need to know the credentials are valid
    to trigger account verification again.
    """

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            backend = AllowAllUsersModelBackend()
            user = backend.authenticate(
                request=self.context.get('request'),
                username=username,
                password=password,
            )
            if not user:
                msg = _('Unable to log in with provided credentials.')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs


class AllowedMobilePrefixMixin(object):
    def is_prefix_allowed(self, phone_number, mobile_prefixes):
        """
        Verifies if a phone number's international prefix is allowed
        """
        country_code = phonenumbers.parse(str(phone_number)).country_code
        allowed_global_prefixes = set(app_settings.ALLOWED_MOBILE_PREFIXES)
        allowed_org_prefixes = set(mobile_prefixes)
        allowed_prefixes = allowed_global_prefixes.union(allowed_org_prefixes)
        if not allowed_prefixes:
            return True
        return ('+' + str(country_code)) in allowed_prefixes


class AuthorizeSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=User._meta.get_field('username').max_length, write_only=True
    )
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)


class RadiusPostAuthSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        help_text='The `password` is stored only on unsuccessful authorizations.',
        required=False,
        allow_blank=True,
        style={'input_type': 'password'},
    )
    called_station_id = serializers.CharField(required=False, allow_blank=True)
    calling_station_id = serializers.CharField(required=False, allow_blank=True)

    def validate(self, data):
        # do not save correct passwords in clear text
        if data['reply'] == 'Access-Accept':
            data['password'] = ''
        passwd = data['password']
        data['password'] = f'{passwd[:63]}\u2026' if len(passwd) > 64 else passwd
        return super().validate(data)

    class Meta:
        model = RadiusPostAuth
        fields = '__all__'
        read_only_fields = ('organization',)


STATUS_TYPE_CHOICES = (
    ('Start', 'Start'),
    ('Interim-Update', 'Interim-Update'),
    ('Stop', 'Stop'),
    ('Accounting-On', 'Accounting-On (ignored)'),
    ('Accounting-Off', 'Accounting-Off (ignored)'),
)


class RadiusAccountingSerializer(serializers.ModelSerializer):
    framed_ip_address = serializers.IPAddressField(required=False, allow_blank=True)
    framed_ipv6_address = serializers.IPAddressField(
        required=False, allow_blank=True, protocol='IPv6'
    )
    session_time = serializers.IntegerField(required=False, default=0)
    stop_time = serializers.DateTimeField(required=False)
    update_time = serializers.DateTimeField(required=False)
    input_octets = serializers.IntegerField(required=False, default=0)
    output_octets = serializers.IntegerField(required=False, default=0)
    # this is needed otherwise serialize will ignore status_type from accounting packet
    # as it's not a model field
    status_type = serializers.ChoiceField(
        write_only=True, required=True, choices=STATUS_TYPE_CHOICES
    )

    def _disable_token_auth(self, user):
        try:
            radius_token = RadiusToken.objects.get(user__username=user)
        except RadiusToken.DoesNotExist:
            pass
        else:
            radius_token.can_auth = False
            radius_token.save()

    def run_validation(self, data):
        for field in ['session_time', 'input_octets', 'output_octets']:
            if data.get('status_type', None) == 'Start' and data[field] == '':
                data[field] = 0
        return super().run_validation(data)

    def validate(self, data):
        """
        We need to set some timestamps according to the accounting packet type
        * update_time: set everytime a Interim-Update / Stop packet is received
        * stop_time: set everytime a Stop packet is received
        * session_time: calculated if not present in the accounting packet
        :param data: accounting packet
        :return: Dict accounting packet
        """
        time = timezone.now()
        status_type = data.pop('status_type')
        if status_type == 'Interim-Update':
            data['update_time'] = time
        if status_type == 'Stop':
            data['update_time'] = time
            data['stop_time'] = time
            # disable radius_token auth capability
            self._disable_token_auth(data['username'])
        return data

    def create(self, validated_data):
        if app_settings.API_ACCOUNTING_AUTO_GROUP:
            username = validated_data.get('username', '')
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                logging.warning(
                    _(f'No corresponding user found for username: {username}')
                )
            else:
                group = user.radiususergroup_set.order_by('priority').first()
                groupname = group.groupname if group else None
                validated_data.update(groupname=groupname)
        return super().create(validated_data)

    class Meta:
        model = RadiusAccounting
        fields = '__all__'
        read_only_fields = ('organization',)


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True)

    class Meta:
        model = User
        fields = '__all__'


class RadiusOrganizationField(serializers.SlugRelatedField):
    def get_queryset(self):
        queryset = Organization.objects.all()
        request = self.context.get('request', None)
        if not request.user.is_superuser:
            queryset = queryset.filter(pk__in=request.user.organizations_dict.keys())
        return queryset


class RadiusBatchSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(
        help_text=('UUID of the organization in which the radius batch is created.'),
        read_only=True,
    )
    organization_slug = RadiusOrganizationField(
        help_text=('Slug of the organization for creating radius batch.'),
        required=True,
        label='organization',
        slug_field='slug',
        write_only=True,
    )
    users = UserSerializer(many=True, read_only=True,)
    prefix = serializers.CharField(
        help_text=(
            'Prefix for creating usernames. '
            'Only required when `prefix` strategy is used.`'
        ),
        required=False,
    )
    csvfile = serializers.FileField(
        help_text=(
            'CSV file for extracting user\'s information. '
            'Only required when `csv` strategy is used.`'
        ),
        required=False,
    )
    pdf_link = serializers.SerializerMethodField(
        help_text=(
            'Downlaod link to PDF file containing user credentials. '
            'Provided only for `prefix` strategy.`'
        ),
        required=False,
        read_only=True,
    )
    number_of_users = serializers.IntegerField(
        help_text=(
            'Number of users to be generated. '
            'Only required when `prefix` strategy is used.`'
        ),
        required=False,
        write_only=True,
        min_value=1,
    )

    def get_pdf_link(self, obj):
        if isinstance(obj, RadiusBatch) and obj.strategy == 'prefix':
            request = self.context.get('request')
            return request.build_absolute_uri(
                reverse(
                    'radius:download_rad_batch_pdf',
                    args=[obj.organization.slug, obj.pk],
                )
            )
        return None

    def validate(self, data):
        if data['strategy'] == 'prefix' and not data.get('number_of_users'):
            raise serializers.ValidationError(
                {'number_of_users': _('The field number_of_users cannot be empty')}
            )
        validated_data = super().validate(data)
        # Additional Model Validation
        batch_data = validated_data.copy()
        batch_data.pop('number_of_users', None)
        batch_data['organization'] = batch_data.pop('organization_slug', None)
        instance = self.instance or self.Meta.model(**batch_data)
        instance.full_clean()
        return validated_data

    class Meta:
        model = RadiusBatch
        fields = '__all__'
        read_only_fields = ('created', 'modified', 'user_credentials')


class PasswordResetSerializer(BasePasswordResetSerializer):
    password_reset_form_class = PasswordResetForm

    def save(self):
        request = self.context.get('request')
        password_reset_url = self.context.get('password_reset_url')
        # Set some values to trigger the send_email method.
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),
            'email_template_name': ('custom_password_reset_email.html'),
            'request': request,
            'extra_email_context': {'password_reset_url': password_reset_url},
        }
        opts.update(self.get_email_options())
        self.reset_form.save(**opts)


class RegisterSerializer(
    ErrorDictMixin, AllowedMobilePrefixMixin, BaseRegisterSerializer
):
    phone_number = PhoneNumberField(
        help_text=(
            'Required only when the organization has enabled SMS '
            'verification in its "Organization RADIUS Settings."'
        ),
        allow_blank=True,
        default='',
    )

    def validate_phone_number(self, phone_number):
        org = self.context['view'].organization
        if is_sms_verification_enabled(org):
            if not phone_number:
                raise serializers.ValidationError(_('This field is required'))
            mobile_prefixes = org.radius_settings.allowed_mobile_prefixes_list
            if not self.is_prefix_allowed(phone_number, mobile_prefixes):
                raise serializers.ValidationError(
                    _('This international mobile prefix is not allowed.')
                )
        else:
            # Phone number should not be stored if sms verification is disabled
            phone_number = None
        return phone_number

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        # commit=False does not save the user to the DB yet
        adapter.save_user(request, user, self, commit=False)
        # the custom_signup method contains the openwisp specific logic
        self.custom_signup(request, user)
        setup_user_email(request, user, [])
        return user

    def custom_signup(self, request, user, save=True):
        phone_number = self.validated_data['phone_number']
        if phone_number != self.fields['phone_number'].default:
            user.phone_number = phone_number
        org = self.context['view'].organization
        if is_sms_verification_enabled(org):
            user.is_active = False
        try:
            user.full_clean()
        except ValidationError as e:
            raise serializers.ValidationError(self._get_error_dict(e))
        user.save()
        orgUser = OrganizationUser(organization=org, user=user)
        orgUser.full_clean()
        orgUser.save()


class ValidatePhoneTokenSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=8)


class ChangePhoneNumberSerializer(
    ErrorDictMixin, AllowedMobilePrefixMixin, serializers.Serializer
):
    phone_number = PhoneNumberField()

    @property
    def user(self):
        return self.context['request'].user

    def validate_phone_number(self, phone_number):
        if self.user.phone_number == phone_number:
            raise serializers.ValidationError(
                _('The new phone number must be different than the old one.')
            )
        org = self.context['view'].organization
        mobile_prefixes = org.radius_settings.allowed_mobile_prefixes_list
        if not self.is_prefix_allowed(phone_number, mobile_prefixes):
            raise serializers.ValidationError(
                _('This international mobile prefix is not allowed.')
            )
        return phone_number

    def save(self):
        self.user.is_active = False
        self.user.save()
