import swapper
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_auth.registration.serializers import (
    RegisterSerializer as BaseRegisterSerializer,
)
from rest_auth.serializers import PasswordResetSerializer as BasePasswordResetSerializer
from rest_framework import serializers
from rest_framework.exceptions import APIException

from ..utils import load_model
from .utils import ErrorDictMixin

RadiusPostAuth = load_model('RadiusPostAuth')
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
User = get_user_model()


class RadiusPostAuthSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=False, allow_blank=True)
    called_station_id = serializers.CharField(required=False, allow_blank=True)
    calling_station_id = serializers.CharField(required=False, allow_blank=True)

    def validate(self, data):
        # do not save correct passwords in clear text
        if data['reply'] == 'Access-Accept':
            data['password'] = ''
        return data

    class Meta:
        model = RadiusPostAuth
        fields = '__all__'


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
    status_type = serializers.ChoiceField(write_only=True, choices=STATUS_TYPE_CHOICES)

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
        return data

    class Meta:
        model = RadiusAccounting
        fields = '__all__'


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True)

    class Meta:
        model = User
        fields = '__all__'


class RadiusBatchSerializer(serializers.ModelSerializer):
    users = UserSerializer(many=True, read_only=True)
    prefix = serializers.CharField(required=False)
    csvfile = serializers.FileField(required=False)
    pdf = serializers.FileField(required=False, read_only=True)
    pdf_link = serializers.SerializerMethodField(required=False, read_only=True)
    number_of_users = serializers.IntegerField(
        required=False, write_only=True, min_value=1
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
                {'number_of_users': 'The field number_of_users cannot be empty'}
            )
        return super().validate(data)

    class Meta:
        model = RadiusBatch
        fields = '__all__'


class PasswordResetSerializer(BasePasswordResetSerializer):
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


class RegisterSerializer(ErrorDictMixin, BaseRegisterSerializer):
    phone_number = PhoneNumberField(allow_blank=True, default='')

    @property
    def is_sms_verification_enabled(self):
        org = self.context['view'].organization
        try:
            return org.radius_settings.sms_verification
        except ObjectDoesNotExist:
            raise APIException(
                'Could not complete operation '
                'because of an internal misconfiguration'
            )

    def validate_phone_number(self, phone_number):
        if self.is_sms_verification_enabled and not phone_number:
            raise serializers.ValidationError(_('This field is required'))
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
        if self.is_sms_verification_enabled:
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


class ChangePhoneNumberSerializer(ErrorDictMixin, serializers.Serializer):
    phone_number = PhoneNumberField()

    @property
    def user(self):
        return self.context['request'].user

    def validate_phone_number(self, phone_number):
        if self.user.phone_number == phone_number:
            raise serializers.ValidationError(
                _('The new phone number must be ' 'different than the old one.')
            )
        return phone_number

    def validate(self, data):
        self.user.phone_number = data['phone_number']
        try:
            self.user.full_clean()
        except ValidationError as e:
            raise serializers.ValidationError(self._get_error_dict(e))
        return data

    def save(self):
        self.user.is_active = False
        self.user.save()
