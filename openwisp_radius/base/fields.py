from django import forms
from django.db import connection
from django.db.models.fields import BooleanField, CharField, Field, TextField


class FallbackMixin(object):
    def __init__(self, *args, **kwargs):
        # remove fallback from kwargs to avoid error
        self.fallback = kwargs.pop('fallback', None)
        super().__init__(*args, **kwargs)

    def value_from_object(self, obj):
        '''
        Handles change form
        '''
        value = getattr(obj, self.attname)
        if value is None:
            return self.fallback
        return value

    def get_choices(self, include_blank=True):
        return super().get_choices(include_blank=False)


class FallbackFormFieldMixin(object):
    def __init__(self, *args, **kwargs):
        # receive fallback hidden in label
        verbose_name, fallback = kwargs['label'].split('?-')
        self.fallback = fallback
        kwargs['label'] = verbose_name
        super().__init__(*args, **kwargs)

    def prepare_value(self, value):
        '''
        Handles create form
        '''
        if value is None:
            value = self.fallback
        return super().prepare_value(value)


'''
Model Fields
'''


class FallbackTextField(FallbackMixin, TextField):
    def formfield(self, **kwargs):
        '''
        Tick to hide fallback in verbose name.
        So django formfield do not remove it
        '''
        self.verbose_name += f'?-{self.fallback}'
        form_field = Field.formfield(
            self,
            form_class=FallbackFormCharField,
            **{
                'max_length': self.max_length,
                **({} if self.choices is not None else {'widget': forms.Textarea}),
                **kwargs,
            },
        )
        verbose_name, _ = self.verbose_name.split('?-')
        self.verbose_name = verbose_name
        return form_field


class FallbackBooleanField(FallbackMixin, BooleanField):
    pass


class FallbackChoiceField(FallbackMixin, CharField):
    def formfield(self, **kwargs):
        defaults = {'max_length': self.max_length}
        '''
        Tick to hide fallback in verbose name.
        So django formfield do not remove it
        '''
        self.verbose_name += f'?-{self.fallback}'
        if self.null and not connection.features.interprets_empty_strings_as_nulls:
            defaults['empty_value'] = None
        defaults.update(kwargs)
        form_field = Field.formfield(
            self,
            form_class=FallbackFormChoiceField,
            choices_form_class=FallbackFormChoiceField,
            **defaults,
        )
        verbose_name, _ = self.verbose_name.split('?-')
        self.verbose_name = verbose_name
        return form_field


'''
Form Fields
'''


class FallbackFormChoiceField(FallbackFormFieldMixin, forms.TypedChoiceField):
    pass


class FallbackFormCharField(FallbackFormFieldMixin, forms.CharField):
    def widget_attrs(self, widget):
        return {'rows': 2, 'cols': 34, 'style': 'width:auto'}
