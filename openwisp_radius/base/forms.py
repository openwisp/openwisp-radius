from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm as BasePasswordResetForm
from django.core.validators import MinValueValidator
from django.template import loader
from django.utils.translation import gettext_lazy as _

from openwisp_utils.admin_theme.email import send_email

from .models import AbstractNas, AbstractRadiusCheck

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
                'https://openwisp.io/docs/stable/radius/user/importing_users.html'
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
