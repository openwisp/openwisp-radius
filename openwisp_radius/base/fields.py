from django import forms
from django.db.models.fields import BooleanField, CharField, TextField, URLField
from django.utils.translation import gettext_lazy as _


class FallbackMixin(object):
    def __init__(self, *args, **kwargs):
        self.fallback = kwargs.pop('fallback', None)
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        kwargs['fallback'] = self.fallback
        return (name, path, args, kwargs)


class FallbackFromDbValueMixin:
    def from_db_value(self, value, expression, connection):
        if value is None:
            return self.fallback
        return value


class FallbackBooleanChoiceField(FallbackMixin, BooleanField):
    def formfield(self, **kwargs):
        default_value = _('Enabled') if self.fallback else _('Disabled')
        kwargs.update(
            {
                "form_class": forms.NullBooleanField,
                'widget': forms.Select(
                    choices=[
                        (
                            '',
                            _('Default') + f' ({default_value})',
                        ),
                        (True, _('Enabled')),
                        (False, _('Disabled')),
                    ]
                ),
            }
        )
        return super().formfield(**kwargs)


class FallbackCharChoiceField(FallbackMixin, CharField):
    def get_choices(self, **kwargs):
        for choice, value in self.choices:
            if choice == self.fallback:
                default = value
                break
        kwargs.update({'blank_choice': [('', _('Default') + f' ({default})')]})
        return super().get_choices(**kwargs)

    def formfield(self, **kwargs):
        kwargs.update(
            {
                "choices_form_class": forms.TypedChoiceField,
            }
        )
        return super().formfield(**kwargs)


class FallbackCharField(FallbackMixin, FallbackFromDbValueMixin, CharField):
    """
    Populates the form with the fallback value
    if the value is set to null in the database.
    """

    pass


class FallbackURLField(FallbackMixin, FallbackFromDbValueMixin, URLField):
    """
    Populates the form with the fallback value
    if the value is set to null in the database.
    """

    pass


class FallbackTextField(FallbackMixin, FallbackFromDbValueMixin, TextField):
    """
    Populates the form with the fallback value
    if the value is set to null in the database.
    """

    def formfield(self, **kwargs):
        kwargs.update({'form_class': FallbackTextFormField})
        return super().formfield(**kwargs)


class FallbackTextFormField(forms.CharField):
    def widget_attrs(self, widget):
        attrs = super().widget_attrs(widget)
        attrs.update({'rows': 2, 'cols': 34, 'style': 'width:auto'})
        return attrs
