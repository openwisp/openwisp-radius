from django.contrib.admin import SimpleListFilter
from django.db.models import Exists, OuterRef, Q
from django.utils.translation import gettext_lazy as _

from ..utils import load_model

RegisteredUser = load_model("RegisteredUser")


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
            where &= Q(
                registered_users__organization__in=request.user.organizations_managed
            )
        if self.value() == "unknown":
            if not request.user.is_superuser:
                # Restrict the "unknown" check to organizations managed by the
                # current admin. A plain `registered_users__isnull=True` filter
                # would treat users registered in other organizations as known
                # and incorrectly exclude them from the results.
                registered_users = RegisteredUser.objects.filter(
                    user=OuterRef("pk"),
                    organization__in=request.user.organizations_managed,
                )
                return queryset.annotate(
                    has_managed_registered_user=Exists(registered_users)
                ).filter(has_managed_registered_user=False)

            where &= Q(registered_users__isnull=True)
        elif self.value():
            where &= Q(registered_users__is_verified=self.value() == "true")
        return queryset.filter(where).distinct()
