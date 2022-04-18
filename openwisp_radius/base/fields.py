from django import forms
from django.db.models.fields import BooleanField, CharField, TextField
from django.utils.translation import gettext_lazy as _


class FallbackMixin(object):
    def __init__(self, *args, **kwargs):
        self.fallback = kwargs.pop('fallback', None)
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        kwargs['fallback'] = self.fallback
        return (name, path, args, kwargs)


class FallbackBooleanField(FallbackMixin, BooleanField):
    def formfield(self, **kwargs):
        default_value = _('Enabled') if self.fallback else _('Disabled')
        kwargs.update(
            {
                "form_class": FallbackNullChoiceField,
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


class FallbackCharField(FallbackMixin, CharField):
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
                "choices_form_class": FallbackChoiceField,
            }
        )
        return super().formfield(**kwargs)


class FallbackTextField(FallbackMixin, TextField):
    def formfield(self, **kwargs):
        kwargs.update({'form_class': FallbackCharFormField})
        return super().formfield(**kwargs)


class FallbackCharFormField(forms.CharField):
    def widget_attrs(self, widget):
        attrs = super().widget_attrs(widget)
        attrs.update({'rows': 2, 'cols': 34, 'style': 'width:auto'})
        return attrs


class FallbackChoiceField(forms.TypedChoiceField):
    pass


class FallbackNullChoiceField(forms.NullBooleanField):
    pass
