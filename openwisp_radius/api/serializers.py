from django.conf import settings
from rest_auth.serializers import PasswordResetSerializer as BasePasswordResetSerializer


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
