from django.contrib import messages
from django.contrib.admin.models import CHANGE, LogEntry
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _


def disable_action(modeladmin, request, queryset):
    queryset.update(is_active=False)
    ct = ContentType.objects.get_for_model(queryset.model)
    for entry in queryset:
        LogEntry.objects.log_action(
            user_id=request.user.id,
            content_type_id=ct.pk,
            object_id=entry.pk,
            object_repr=entry.username,
            action_flag=CHANGE,
            change_message=_('Disabled'),
        )
    messages.add_message(request, messages.INFO, '%d disabled' % queryset.count())


disable_action.short_description = _('Disable')


def enable_action(modeladmin, request, queryset):
    queryset.update(is_active=True)
    ct = ContentType.objects.get_for_model(queryset.model)
    for entry in queryset:
        LogEntry.objects.log_action(
            user_id=request.user.id,
            content_type_id=ct.pk,
            object_id=entry.pk,
            object_repr=entry.username,
            action_flag=CHANGE,
            change_message=_('Enabled'),
        )
    messages.add_message(request, messages.INFO, '%d enabled' % queryset.count())


enable_action.short_description = _('Enable')
