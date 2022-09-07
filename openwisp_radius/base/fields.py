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
    """
    Returns the fallback value when the value of the field
    is falsy (None or '').

    It does not set the field's value to "None" when the value
    is equal to the fallback value. This allows overriding of
    the value when a user knows that the default will get changed.
    """

    def from_db_value(self, value, expression, connection):
        if value is None:
            return self.fallback
        return value


class FalsyValueNoneMixin:
    """
    If the field contains an empty string, then
    stores "None" in the database if the field is
    nullable.
    """

    # TDjango convention is to use the empty string, not NULL
    # for representing "no data" in the database.
    # https://docs.djangoproject.com/en/dev/ref/models/fields/#null
    # We need to use NULL for fallback field here to keep
    # the fallback logic simple. Hence, we allow only "None" (NULL)
    # as empty value here.
    empty_values = [None]

    def clean(self, value, model_instance):
        if not value and self.null is True:
            return None
        return super().clean(value, model_instance)


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


class FallbackCharField(
    FallbackMixin, FalsyValueNoneMixin, FallbackFromDbValueMixin, CharField
):
    """
    Populates the form with the fallback value
    if the value is set to null in the database.
    """

    pass


class FallbackURLField(
    FallbackMixin, FalsyValueNoneMixin, FallbackFromDbValueMixin, URLField
):
    """
    Populates the form with the fallback value
    if the value is set to null in the database.
    """

    pass


class FallbackTextField(
    FallbackMixin, FalsyValueNoneMixin, FallbackFromDbValueMixin, TextField
):
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
