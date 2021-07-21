from urllib.parse import urljoin

from django import forms
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.admin import ModelAdmin, StackedInline
from django.contrib.admin.utils import model_ngettext
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.forms.widgets import Select
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from openwisp_users.admin import OrganizationAdmin, UserAdmin
from openwisp_users.multitenancy import MultitenantAdminMixin, MultitenantOrgFilter
from openwisp_utils.admin import (
    AlwaysHasChangedMixin,
    ReadOnlyAdmin,
    TimeReadonlyAdminMixin,
)

from . import settings as app_settings
from .base.admin_actions import disable_action, enable_action
from .base.admin_filters import (
    DuplicateListFilter,
    ExpiredListFilter,
    RegisteredUserFilter,
)
from .base.forms import ModeSwitcherForm, RadiusBatchForm, RadiusCheckForm
from .base.models import (
    _GET_IP_LIST_HELP_TEXT,
    _GET_MOBILE_PREFIX_HELP_TEXT,
    _GET_OPTIONAL_FIELDS_HELP_TEXT,
    _IDENTITY_VERIFICATION_ENABLED_HELP_TEXT,
    _REGISTRATION_ENABLED_HELP_TEXT,
    _SMS_VERIFICATION_HELP_TEXT,
    OPTIONAL_FIELD_CHOICES,
    _encode_secret,
)
from .settings import RADIUS_API_BASEURL, RADIUS_API_URLCONF
from .utils import load_model

Nas = load_model('Nas')
RadiusAccounting = load_model('RadiusAccounting')
RadiusToken = load_model('RadiusToken')
RadiusBatch = load_model('RadiusBatch')
RadiusCheck = load_model('RadiusCheck')
RadiusGroup = load_model('RadiusGroup')
RadiusPostAuth = load_model('RadiusPostAuth')
RadiusReply = load_model('RadiusReply')
PhoneToken = load_model('PhoneToken')
RadiusGroupCheck = load_model('RadiusGroupCheck')
RadiusGroupReply = load_model('RadiusGroupReply')
RadiusUserGroup = load_model('RadiusUserGroup')
RegisteredUser = load_model('RegisteredUser')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
User = get_user_model()
OPTIONAL_SETTINGS = app_settings.OPTIONAL_REGISTRATION_FIELDS


class OrganizationFirstMixin(MultitenantAdminMixin):
    def get_fields(self, request, obj=None):
        fields = super().get_fields(request, obj=None)
        fields.remove('organization')
        fields.insert(0, 'organization')
        return fields


class TimeStampedEditableAdmin(TimeReadonlyAdminMixin, ModelAdmin):
    ordering = ['created']


class AlwaysHasChangedForm(AlwaysHasChangedMixin, forms.ModelForm):
    pass


@admin.register(RadiusCheck)
class RadiusCheckAdmin(MultitenantAdminMixin, TimeStampedEditableAdmin):
    list_display = [
        'username',
        'organization',
        'attribute',
        'op',
        'value',
        'is_active',
        'valid_until',
        'created',
        'modified',
    ]
    search_fields = ['username', 'value']
    list_filter = [
        DuplicateListFilter,
        ('organization', MultitenantOrgFilter),
        ExpiredListFilter,
        'created',
        'modified',
        'valid_until',
    ]
    readonly_fields = ['value']
    form = RadiusCheckForm
    fields = [
        'mode',
        'organization',
        'user',
        'username',
        'op',
        'attribute',
        'value',
        'new_value',
        'is_active',
        'valid_until',
        'notes',
        'created',
        'modified',
    ]
    autocomplete_fields = ['user']
    actions = TimeStampedEditableAdmin.actions + [disable_action, enable_action]

    def save_model(self, request, obj, form, change):
        if form.data.get('new_value'):
            obj.value = _encode_secret(
                form.data['attribute'], form.data.get('new_value')
            )
        obj.save()

    def get_fields(self, request, obj=None):
        """do not show raw value (readonly) when adding a new item"""
        fields = self.fields[:]
        if not obj:
            fields.remove('value')
        return fields


@admin.register(RadiusReply)
class RadiusReplyAdmin(MultitenantAdminMixin, TimeStampedEditableAdmin):
    list_display = [
        'username',
        'organization',
        'attribute',
        'op',
        'value',
        'created',
        'modified',
    ]
    autocomplete_fields = ['user']
    form = ModeSwitcherForm
    list_filter = (('organization', MultitenantOrgFilter),)
    fields = [
        'mode',
        'organization',
        'user',
        'username',
        'attribute',
        'op',
        'value',
        'created',
        'modified',
    ]


BaseAccounting = ReadOnlyAdmin if not app_settings.EDITABLE_ACCOUNTING else ModelAdmin


@admin.register(RadiusAccounting)
class RadiusAccountingAdmin(OrganizationFirstMixin, BaseAccounting):
    list_display = [
        'session_id',
        'organization',
        'username',
        'session_time',
        'input_octets',
        'output_octets',
        'calling_station_id',
        'called_station_id',
        'start_time',
        'stop_time',
    ]
    search_fields = [
        'unique_id',
        'username',
        'calling_station_id',
        'called_station_id',
        'nas_ip_address',
    ]
    list_filter = ['start_time', 'stop_time', ('organization', MultitenantOrgFilter)]
    ordering = ['-start_time']


@admin.register(Nas)
class NasAdmin(MultitenantAdminMixin, TimeStampedEditableAdmin):
    fieldsets = (
        (
            None,
            {
                'fields': (
                    'organization',
                    'name',
                    'short_name',
                    'type',
                    'ports',
                    'secret',
                    'server',
                    'community',
                    'description',
                )
            },
        ),
    )
    search_fields = ['name', 'short_name', 'server']
    list_display = [
        'name',
        'organization',
        'short_name',
        'type',
        'secret',
        'created',
        'modified',
    ]
    list_filter = (('organization', MultitenantOrgFilter),)

    def save_model(self, request, obj, form, change):
        data = form.cleaned_data
        obj.type = data.get('custom_type') or data.get('type')
        super(NasAdmin, self).save_model(request, obj, form, change)

    class Media:
        css = {'all': ('openwisp-radius/css/nas.css',)}


class RadiusGroupCheckInline(TimeReadonlyAdminMixin, StackedInline):
    model = RadiusGroupCheck
    exclude = ['groupname']
    extra = 0


class RadiusGroupReplyInline(TimeReadonlyAdminMixin, StackedInline):
    model = RadiusGroupReply
    exclude = ['groupname']
    extra = 0


@admin.register(RadiusGroup)
class RadiusGroupAdmin(OrganizationFirstMixin, TimeStampedEditableAdmin):
    list_display = [
        'get_group_name',
        'organization',
        'name',
        'description',
        'default',
        'created',
        'modified',
    ]
    search_fields = ['name']
    list_filter = (('organization', MultitenantOrgFilter),)
    inlines = [RadiusGroupCheckInline, RadiusGroupReplyInline]
    select_related = ('organization',)

    def get_group_name(self, obj):
        return obj.name.replace(f'{obj.organization.slug}-', '')

    get_group_name.short_description = _('Group name')

    def has_delete_permission(self, request, obj=None):
        if not request.user.is_superuser and obj and obj.default:
            return False
        return super().has_delete_permission(request, obj)

    def delete_selected_groups(self, request, queryset):
        if self.get_default_queryset(request, queryset).exists():
            msg = _(
                'Cannot proceed with the delete operation because '
                'the batch of items contains the default group, '
                'which cannot be deleted'
            )
            self.message_user(request, msg, messages.ERROR)
            return False
        if not self.has_delete_permission(request):
            raise PermissionDenied
        n = queryset.count()
        if n:
            queryset.delete()
            self.message_user(
                request,
                _('Successfully deleted %(count)d %(items)s.')
                % {'count': n, 'items': model_ngettext(self.opts, n)},
                messages.SUCCESS,
            )
        return None

    delete_selected_groups.allowed_permissions = ('delete',)

    def get_actions(self, request):
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    actions = ['delete_selected_groups']

    def get_default_queryset(self, request, queryset):
        """overridable"""
        return queryset.filter(default=True)


if app_settings.USERGROUP_ADMIN:

    @admin.register(RadiusUserGroup)
    class RadiusUserGroupAdmin(MultitenantAdminMixin, TimeStampedEditableAdmin):
        list_display = ['username', 'groupname', 'priority', 'created', 'modified']
        autocomplete_fields = ['user', 'group']
        form = ModeSwitcherForm
        fields = [
            'mode',
            'user',
            'username',
            'group',
            'groupname',
            'priority',
            'created',
            'modified',
        ]
        multitenant_parent = 'group'


class RadGroupMixin(object):
    list_display = ['groupname', 'attribute', 'op', 'value', 'created', 'modified']
    autocomplete_fields = ['group']
    form = ModeSwitcherForm
    fields = [
        'mode',
        'group',
        'groupname',
        'attribute',
        'op',
        'value',
        'created',
        'modified',
    ]


if app_settings.GROUPCHECK_ADMIN:

    @admin.register(RadiusGroupCheck)
    class RadiusGroupCheckAdmin(
        MultitenantAdminMixin, RadGroupMixin, TimeStampedEditableAdmin
    ):
        multitenant_parent = 'group'


if app_settings.GROUPREPLY_ADMIN:

    @admin.register(RadiusGroupReply)
    class RadiusGroupReplyAdmin(
        MultitenantAdminMixin, RadGroupMixin, TimeStampedEditableAdmin
    ):
        multitenant_parent = 'group'


BasePostAuth = ReadOnlyAdmin if not app_settings.EDITABLE_POSTAUTH else ModelAdmin


@admin.register(RadiusPostAuth)
class RadiusPostAuthAdmin(OrganizationFirstMixin, BasePostAuth):
    list_display = [
        'username',
        'organization',
        'reply',
        'calling_station_id',
        'called_station_id',
        'date',
    ]
    list_filter = [
        'date',
        'reply',
        ('organization', MultitenantOrgFilter),
    ]
    search_fields = ['username', 'reply', 'calling_station_id', 'called_station_id']
    exclude = ['id']
    ordering = ['-date']


@admin.register(RadiusBatch)
class RadiusBatchAdmin(MultitenantAdminMixin, TimeStampedEditableAdmin):
    change_form_template = 'openwisp-radius/admin/rad_batch_users_change_form.html'
    list_display = [
        'name',
        'organization',
        'strategy',
        'expiration_date',
        'created',
        'modified',
    ]
    fields = [
        'strategy',
        'organization',
        'name',
        'csvfile',
        'prefix',
        'number_of_users',
        'users',
        'expiration_date',
        'created',
        'modified',
    ]
    list_filter = [
        'strategy',
        ('organization', MultitenantOrgFilter),
    ]
    search_fields = ['name']
    form = RadiusBatchForm

    class Media:
        js = [
            'admin/js/jquery.init.js',
            'openwisp-radius/js/strategy-switcher.js',
        ]
        css = {'all': ('openwisp-radius/css/radiusbatch.css',)}

    def number_of_users(self, obj):
        return obj.users.count()

    number_of_users.short_description = _('number of users')

    def get_fields(self, request, obj=None):
        fields = super().get_fields(request, obj)[:]
        if not obj:
            fields.remove('users')
        return fields

    def save_model(self, request, obj, form, change):
        data = form.cleaned_data
        strategy = data.get('strategy')
        if not change:
            if strategy == 'csv':
                if data.get('csvfile', False):
                    csvfile = data.get('csvfile')
                    obj.csvfile_upload(csvfile)
            elif strategy == 'prefix':
                prefix = data.get('prefix')
                n = data.get('number_of_users')
                obj.prefix_add(prefix, n)
        else:
            obj.save()

    def delete_model(self, request, obj):
        obj.users.all().delete()
        super(RadiusBatchAdmin, self).delete_model(request, obj)

    def change_view(self, request, object_id, form_url='', extra_context=None):
        extra_context = extra_context or {}
        radbatch = RadiusBatch.objects.get(pk=object_id)
        if radbatch.strategy == 'prefix':
            batch_pdf_api_url = reverse(
                'radius:download_rad_batch_pdf',
                urlconf=RADIUS_API_URLCONF,
                args=[radbatch.organization.slug, object_id],
            )
            if RADIUS_API_BASEURL:
                batch_pdf_api_url = urljoin(RADIUS_API_BASEURL, batch_pdf_api_url)
            extra_context['download_rad_batch_pdf_url'] = batch_pdf_api_url
        return super().change_view(
            request,
            object_id,
            form_url,
            extra_context=extra_context,
        )

    def get_actions(self, request):
        actions = super().get_actions(request)
        if 'delete_selected' in actions:
            del actions['delete_selected']
        return actions

    actions = ['delete_selected_batches']

    def delete_selected_batches(self, request, queryset):
        for obj in queryset:
            obj.delete()

    delete_selected_batches.short_description = _('Delete selected batches')

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = super(RadiusBatchAdmin, self).get_readonly_fields(
            request, obj
        )
        if obj:
            return (
                'strategy',
                'prefix',
                'csvfile',
                'number_of_users',
                'users',
                'expiration_date',
            ) + readonly_fields
        return readonly_fields


# Inlines for UserAdmin & OrganizationAdmin
class RadiusUserGroupInline(StackedInline):
    model = RadiusUserGroup
    exclude = ['username', 'groupname', 'created', 'modified']
    ordering = ('priority',)
    autocomplete_fields = ('group',)
    verbose_name = _('radius user group')
    verbose_name_plural = _('radius user groups')
    extra = 0


class PhoneTokenInline(TimeReadonlyAdminMixin, StackedInline):
    model = PhoneToken
    extra = 0
    readonly_fields = ('verified', 'valid_until', 'attempts', 'phone_number', 'ip')

    def has_add_permission(self, request, obj):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class RegisteredUserInline(StackedInline):
    model = RegisteredUser
    form = AlwaysHasChangedForm
    extra = 0
    readonly_fields = ('modified',)

    def has_delete_permission(self, request, obj=None):
        return False


UserAdmin.inlines.insert(0, RegisteredUserInline)
UserAdmin.inlines += [
    RadiusUserGroupInline,
    PhoneTokenInline,
]
UserAdmin.list_filter += (RegisteredUserFilter, 'registered_user__method')


def get_is_verified(self, obj):
    try:
        value = 'yes' if obj.registered_user.is_verified else 'no'
    except Exception:
        value = 'unknown'

    return mark_safe(f'<img src="/static/admin/img/icon-{value}.svg" alt="{value}">')


UserAdmin.get_is_verified = get_is_verified
UserAdmin.get_is_verified.short_description = _('Verified')
UserAdmin.list_display.insert(3, 'get_is_verified')
UserAdmin.list_select_related = ('registered_user',)


class FallbackFieldMixin(object):
    def __init__(self, fallback, *args, **kwargs):
        self.fallback = fallback
        super().__init__(*args, **kwargs)

    def prepare_value(self, value):
        if value is None:
            value = self.fallback
        return super().prepare_value(value)


class FallbackCharField(FallbackFieldMixin, forms.CharField):
    pass


class FallbackChoiceField(FallbackFieldMixin, forms.ChoiceField):
    pass


class FallbackNullChoiceField(FallbackFieldMixin, forms.NullBooleanField):
    pass


def _enabled_disabled_helper(field):
    if getattr(app_settings, field):
        return _('Enabled')
    return _('Disabled')


class OrganizationRadiusSettingsForm(AlwaysHasChangedMixin, forms.ModelForm):
    freeradius_allowed_hosts = FallbackCharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 2, 'cols': 34}),
        help_text=_GET_IP_LIST_HELP_TEXT,
        fallback=','.join(app_settings.FREERADIUS_ALLOWED_HOSTS),
    )
    allowed_mobile_prefixes = FallbackCharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 2, 'cols': 34}),
        help_text=_GET_MOBILE_PREFIX_HELP_TEXT,
        fallback=','.join(app_settings.ALLOWED_MOBILE_PREFIXES),
    )
    registration_enabled = FallbackNullChoiceField(
        required=False,
        widget=Select(
            choices=[
                (
                    '',
                    _('Default')
                    + f' ({_enabled_disabled_helper("REGISTRATION_API_ENABLED")})',
                ),
                (True, _('Enabled')),
                (False, _('Disabled')),
            ]
        ),
        help_text=_REGISTRATION_ENABLED_HELP_TEXT,
        fallback='',
    )
    needs_identity_verification = FallbackNullChoiceField(
        required=False,
        widget=Select(
            choices=[
                (
                    '',
                    _('Default')
                    + f' ({_enabled_disabled_helper("NEEDS_IDENTITY_VERIFICATION")})',
                ),
                (True, _('Enabled')),
                (False, _('Disabled')),
            ]
        ),
        help_text=_IDENTITY_VERIFICATION_ENABLED_HELP_TEXT,
        fallback='',
    )
    sms_verification = FallbackNullChoiceField(
        required=False,
        widget=Select(
            choices=[
                (
                    '',
                    _('Default')
                    + f' ({_enabled_disabled_helper("SMS_VERIFICATION_ENABLED")})',
                ),
                (True, _('Enabled')),
                (False, _('Disabled')),
            ]
        ),
        help_text=_SMS_VERIFICATION_HELP_TEXT,
        fallback='',
    )
    first_name = FallbackChoiceField(
        required=False,
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        choices=OPTIONAL_FIELD_CHOICES,
        fallback=OPTIONAL_SETTINGS.get('first_name', 'disabled'),
    )
    last_name = FallbackChoiceField(
        required=False,
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        choices=OPTIONAL_FIELD_CHOICES,
        fallback=OPTIONAL_SETTINGS.get('last_name', 'disabled'),
    )
    location = FallbackChoiceField(
        required=False,
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        choices=OPTIONAL_FIELD_CHOICES,
        fallback=OPTIONAL_SETTINGS.get('location', 'disabled'),
    )
    birth_date = FallbackChoiceField(
        required=False,
        help_text=_GET_OPTIONAL_FIELDS_HELP_TEXT,
        choices=OPTIONAL_FIELD_CHOICES,
        fallback=OPTIONAL_SETTINGS.get('birth_date', 'disabled'),
    )


class OrganizationRadiusSettingsInline(admin.StackedInline):
    model = OrganizationRadiusSettings
    form = OrganizationRadiusSettingsForm
    fieldsets = (
        (
            None,
            {
                'fields': (
                    'token',
                    'freeradius_allowed_hosts',
                    'registration_enabled',
                    'needs_identity_verification',
                    'sms_verification',
                    'first_name',
                    'last_name',
                    'birth_date',
                    'location',
                    'sms_sender',
                    'allowed_mobile_prefixes',
                    'login_url',
                    'status_url',
                )
            },
        ),
        (
            _('Advanced options'),
            {'classes': ('collapse',), 'fields': ('sms_meta_data',)},
        ),
    )


OrganizationAdmin.save_on_top = True
OrganizationAdmin.inlines.insert(2, OrganizationRadiusSettingsInline)

# avoid cluttering the admin with too many models, leave only the
# minimum required to configure social login and check if it's working
if app_settings.SOCIAL_LOGIN_ENABLED:
    from allauth.socialaccount.admin import SocialAccount, SocialApp, SocialAppAdmin

    class SocialAccountInline(admin.StackedInline):
        model = SocialAccount
        extra = 0
        readonly_fields = ('provider', 'uid', 'extra_data')

        def has_add_permission(self, request, obj):
            return False

        def has_delete_permission(self, request, obj=None):
            return False

    UserAdmin.inlines += [SocialAccountInline]
    admin.site.register(SocialApp, SocialAppAdmin)


if settings.DEBUG:

    @admin.register(RadiusToken)
    class RadiusTokenAdmin(ModelAdmin):
        list_display = ['key', 'user', 'created']
        fields = ['user', 'organization', 'can_auth']
        ordering = ('-created',)
