from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_auth.registration.serializers import RegisterSerializer as BaseRegisterSerializer
from rest_auth.serializers import PasswordResetSerializer as BasePasswordResetSerializer
from rest_framework import serializers

from .utils import ErrorDictMixin


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
            'extra_email_context': {
                'password_reset_url': password_reset_url
            }
        }
        opts.update(self.get_email_options())
        self.reset_form.save(**opts)


class RegisterSerializer(ErrorDictMixin, BaseRegisterSerializer):
    phone_number = PhoneNumberField(allow_blank=True,
                                    default='')

    def validate_phone_number(self, mobile):
        org = self.context['view'].organization
        if org.radius_settings.sms_verification and not mobile:
            raise serializers.ValidationError(_('This field is required'))
        return mobile

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
        if org.radius_settings.sms_verification:
            user.is_active = False
        try:
            user.full_clean()
        except ValidationError as e:
            raise serializers.ValidationError(self._get_error_dict(e))
        user.save()
        org.add_user(user)


class ValidatePhoneTokenSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=8)
