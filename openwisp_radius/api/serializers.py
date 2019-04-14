from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_auth.registration.serializers import RegisterSerializer as BaseRegisterSerializer
from rest_auth.serializers import PasswordResetSerializer as BasePasswordResetSerializer
from rest_framework import serializers


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


class RegisterSerializer(BaseRegisterSerializer):
    mobile_phone = PhoneNumberField(allow_blank=True,
                                    default='')

    def validate_mobile_phone(self, mobile):
        org = self.context['view'].organization
        if org.radius_settings.sms_verification and not mobile:
            raise serializers.ValidationError(_('This field is required'))
        return mobile

    def custom_signup(self, request, user, save=True):
        user.phone_number = self.validated_data['mobile_phone']
        org = self.context['view'].organization
        deactivated = False
        if org.radius_settings.sms_verification:
            user.is_active = False
            deactivated = True
        if (user.phone_number or deactivated) and save:
            user.save()


class ValidatePhoneTokenSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=8)
