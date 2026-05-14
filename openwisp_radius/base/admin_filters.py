from django.contrib.admin import SimpleListFilter
from django.db.models import Q
from django.utils.translation import gettext_lazy as _


class RegisteredUserFilter(SimpleListFilter):
    title = _("Verified")
    parameter_name = "is_verified"

    def lookups(self, request, model_admin):
        return (
            ("unknown", _("Unknown")),
            ("true", _("Yes")),
            ("false", _("No")),
        )

    def queryset(self, request, queryset):
        if self.value() is None:
            return queryset
        where = Q()
        if not request.user.is_superuser:
            where = Q(
                registered_users__organization__in=request.user.organizations_managed
            )
        if self.value() == "unknown":
            where &= Q(registered_users__isnull=True)
        elif self.value():
            where &= Q(registered_users__is_verified=self.value() == "true")
        return queryset.filter(where).distinct()
