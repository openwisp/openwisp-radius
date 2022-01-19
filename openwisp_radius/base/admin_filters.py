from django.contrib.admin import SimpleListFilter
from django.utils.translation import gettext_lazy as _


class DuplicateListFilter(SimpleListFilter):
    title = _('find duplicates')
    parameter_name = 'duplicates'

    def lookups(self, request, model_admin):
        return (('username', _('username')), ('value', _('value')))

    def queryset(self, request, queryset):
        if self.value() == 'value':
            return queryset.filter_duplicate_value()
        elif self.value() == 'username':
            return queryset.filter_duplicate_username()


class RegisteredUserFilter(SimpleListFilter):
    title = _('Verified')
    parameter_name = 'is_verified'

    def lookups(self, request, model_admin):
        return (
            ('unknown', _('Unknown')),
            ('true', _('Yes')),
            ('false', _('No')),
        )

    def queryset(self, request, queryset):
        if self.value() == 'unknown':
            return queryset.filter(registered_user__isnull=True)
        elif self.value():
            return queryset.filter(registered_user__is_verified=self.value() == 'true')
        return queryset
