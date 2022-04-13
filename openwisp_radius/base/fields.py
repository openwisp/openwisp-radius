from django import forms
from django.db.models.fields import BooleanField, CharField, TextField
from django.utils.translation import gettext_lazy as _


class FallbackMixin(object):
    def __init__(self, *args, **kwargs):
        self.fallback = kwargs.pop('fallback', None)
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return self.fallback
        return value

    def clean(self, value, model_instance):
        value = super().clean(value, model_instance)
        if value == self.fallback:
            return None
        return value

    def formfield(self, **kwargs):
        kwargs.update({'fallback': self.fallback})
        return super().formfield(**kwargs)

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
        form_field = super().formfield(**kwargs)
        form_field.fallback = self.fallback
        return form_field


class FallbackTextField(FallbackMixin, TextField):
    def formfield(self, **kwargs):
        kwargs.update({'form_class': FallbackCharFormField})
        return super().formfield(**kwargs)


class FallbackFormFieldMixin(object):
    def __init__(self, *args, **kwargs):
        self.fallback = kwargs.pop('fallback', None)
        super().__init__(*args, **kwargs)

    def prepare_value(self, value):
        if value is self.fallback:
            # It is required to set this value to None
            # because the fallback model field sets the value
            # of the field to the fallback value if the database
            # returns null value. This affects rendering of the
            # "select" widget and the option with the fallback value
            # gets selected instead of the "Default" option.
            value = None
        return super().prepare_value(value)


class FallbackCharFormField(FallbackFormFieldMixin, forms.CharField):
    def widget_attrs(self, widget):
        attrs = super().widget_attrs(widget)
        attrs.update({'rows': 2, 'cols': 34, 'style': 'width:auto'})
        return attrs


class FallbackChoiceField(FallbackFormFieldMixin, forms.TypedChoiceField):
    pass


class FallbackNullChoiceField(FallbackFormFieldMixin, forms.NullBooleanField):
    pass
