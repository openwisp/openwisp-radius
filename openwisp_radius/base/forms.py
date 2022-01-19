import re

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm as BasePasswordResetForm
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.template import loader
from django.utils.translation import gettext_lazy as _

from openwisp_utils.admin_theme.email import send_email

from .. import settings as app_settings
from .models import RADCHECK_PASSWD_TYPE, AbstractNas, AbstractRadiusCheck

radcheck_value_field = AbstractRadiusCheck._meta.get_field('value')
nas_type_field = AbstractNas._meta.get_field('type')
User = get_user_model()


class ModeSwitcherForm(forms.ModelForm):
    MODE_CHOICES = (
        ('-', '----- {0} -----'.format(_('Please select an option'))),
        ('guided', _('Guided (dropdown)')),
        ('custom', _('Custom (text input)')),
    )
    mode = forms.ChoiceField(choices=MODE_CHOICES)

    class Media:
        js = ['admin/js/jquery.init.js', 'openwisp-radius/js/mode-switcher.js']
        css = {'all': ('openwisp-radius/css/mode-switcher.css',)}


class RadiusCheckForm(ModeSwitcherForm):
    _secret_help_text = _(
        'The secret must contain at least one lowercase '
        'and uppercase characters, '
        'one number and one of these symbols: '
        '! % - _ + = [ ] { } : , . ? < > ( ) ; '
    )
    # custom field not backed by database
    new_value = forms.CharField(
        label=_('Value'),
        required=False,
        max_length=radcheck_value_field.max_length,
        widget=forms.PasswordInput(),
    )

    def clean_attribute(self):
        if self.data['attribute'] not in app_settings.DISABLED_SECRET_FORMATS:
            return self.cleaned_data['attribute']

    def clean_new_value(self):
        if not self.data['new_value']:
            return None
        if self.data['attribute'] in RADCHECK_PASSWD_TYPE:
            for regexp in app_settings.RADCHECK_SECRET_VALIDATORS.values():
                found = re.findall(regexp, self.data['new_value'])
                if not found:
                    raise ValidationError(self._secret_help_text)
        return self.cleaned_data['new_value']

    class Media:
        js = ['admin/js/jquery.init.js', 'openwisp-radius/js/radcheck.js']
        css = {'all': ('openwisp-radius/css/radcheck.css',)}


class RadiusBatchForm(forms.ModelForm):
    number_of_users = forms.IntegerField(
        required=False,
        validators=[MinValueValidator(1)],
        help_text=_('Number of users to be generated'),
    )

    def clean(self):
        data = self.cleaned_data
        strategy = data.get('strategy')
        number_of_users = data.get('number_of_users')
        if strategy == 'prefix' and not number_of_users:
            self.add_error('number_of_users', 'This field is required')
        super().clean()
        return data

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'csvfile' in self.fields:
            docs_link = (
                'https://openwisp-radius.readthedocs.io/en/latest'
                '/user/importing_users.html'
            )
            help_text = f"Refer to the <b><u><a href='{docs_link}'>docs</a></u></b> \
                for more details on importing users from a CSV"
            self.fields['csvfile'].help_text = help_text


class PasswordResetForm(BasePasswordResetForm):
    def get_users(self, email):
        """
        Given an email, return matching user who should receive a reset.

        This allows subclasses to more easily customize the default policies
        that prevent users with unusable passwords from resetting their password.
        """
        user = User.objects.get(email=email)
        return [user] if user.has_usable_password() else []

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        subject = context.get('subject')
        body_html = loader.render_to_string(email_template_name, context)
        send_email(subject, body_html, body_html, [to_email], context)
