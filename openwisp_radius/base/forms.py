import warnings

from django import forms
from django.core.validators import MinValueValidator
from django.utils.translation import gettext_lazy as _

from openwisp_users.base.forms import PasswordResetForm as BasePasswordResetForm

from .models import AbstractNas, AbstractRadiusCheck

radcheck_value_field = AbstractRadiusCheck._meta.get_field("value")
nas_type_field = AbstractNas._meta.get_field("type")


class ModeSwitcherForm(forms.ModelForm):
    MODE_CHOICES = (
        ("-", "----- {0} -----".format(_("Please select an option"))),
        ("guided", _("Guided (dropdown)")),
        ("custom", _("Custom (text input)")),
    )
    mode = forms.ChoiceField(choices=MODE_CHOICES)

    class Media:
        js = ["admin/js/jquery.init.js", "openwisp-radius/js/mode-switcher.js"]
        css = {"all": ("openwisp-radius/css/mode-switcher.css",)}


class RadiusBatchForm(forms.ModelForm):
    number_of_users = forms.IntegerField(
        required=False,
        validators=[MinValueValidator(1)],
        help_text=_("Number of users to be generated"),
    )

    def clean(self):
        data = self.cleaned_data
        strategy = data.get("strategy")
        number_of_users = data.get("number_of_users")
        if strategy == "prefix" and not number_of_users:
            self.add_error("number_of_users", "This field is required")
        super().clean()
        return data

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "csvfile" in self.fields:
            docs_link = (
                "https://openwisp.io/docs/stable/radius/user/importing_users.html"
            )
            help_text = f"Refer to the <b><u><a href='{docs_link}'>docs</a></u></b> \
                for more details on importing users from a CSV"
            self.fields["csvfile"].help_text = help_text


class PasswordResetForm(BasePasswordResetForm):
    """
    DEPRECATED: Use openwisp_users.base.forms.PasswordResetForm instead.
    TODO: Remove in 1.4.0
    """

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "openwisp_radius.base.forms.PasswordResetForm is deprecated. "
            "Use openwisp_users.base.forms.PasswordResetForm instead. "
            "This class will be removed in openwisp-radius 1.4.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
