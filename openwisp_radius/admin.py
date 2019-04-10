from django import forms
from django.contrib import admin
from django.contrib.admin import StackedInline
from django.utils.translation import ugettext_lazy as _
from django_freeradius import settings as app_settings
from django_freeradius.base.admin import (AbstractNasAdmin, AbstractRadiusAccountingAdmin,
                                          AbstractRadiusBatchAdmin, AbstractRadiusCheckAdmin,
                                          AbstractRadiusGroupAdmin, AbstractRadiusGroupCheckAdmin,
                                          AbstractRadiusGroupReplyAdmin, AbstractRadiusPostAuthAdmin,
                                          AbstractRadiusReplyAdmin, AbstractRadiusUserGroupAdmin,
                                          RadiusUserGroupInline)

from openwisp_users.admin import OrganizationAdmin, UserAdmin
from openwisp_users.multitenancy import MultitenantAdminMixin, MultitenantOrgFilter
from openwisp_utils.admin import AlwaysHasChangedMixin, TimeReadonlyAdminMixin

from .models import (Nas, OrganizationRadiusSettings, PhoneToken, RadiusAccounting, RadiusBatch, RadiusCheck,
                     RadiusGroup, RadiusGroupCheck, RadiusGroupReply, RadiusPostAuth, RadiusReply,
                     RadiusUserGroup)


class OrganizationFirstMixin(MultitenantAdminMixin):
    def get_fields(self, request, obj=None):
        fields = super().get_fields(request, obj=None)
        fields.remove('organization')
        fields.insert(0, 'organization')
        return fields


@admin.register(RadiusCheck)
class RadiusCheckAdmin(MultitenantAdminMixin,
                       AbstractRadiusCheckAdmin):
    pass


RadiusCheckAdmin.fields.insert(1, 'organization')
RadiusCheckAdmin.list_display.insert(1, 'organization')
RadiusCheckAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusReply)
class RadiusReplyAdmin(MultitenantAdminMixin,
                       AbstractRadiusReplyAdmin):
    pass


RadiusReplyAdmin.fields.insert(1, 'organization')
RadiusReplyAdmin.list_display += ('organization',)
RadiusReplyAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusAccounting)
class RadiusAccountingAdmin(OrganizationFirstMixin,
                            AbstractRadiusAccountingAdmin):
    pass


RadiusAccountingAdmin.list_display.insert(1, 'organization',)
RadiusAccountingAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusGroup)
class RadiusGroupAdmin(OrganizationFirstMixin,
                       AbstractRadiusGroupAdmin):
    select_related = ('organization',)

    def get_group_name(self, obj):
        return obj.name.replace('{}-'.format(obj.organization.slug), '')

    get_group_name.short_description = _('Group name')


RadiusGroupAdmin.list_display[0] = 'get_group_name'
RadiusGroupAdmin.list_display.insert(1, 'organization')
RadiusGroupAdmin.list_filter += (('organization', MultitenantOrgFilter),)


if app_settings.USERGROUP_ADMIN:
    @admin.register(RadiusUserGroup)
    class RadiusUserGroupAdmin(MultitenantAdminMixin,
                               AbstractRadiusUserGroupAdmin):
        multitenant_parent = 'group'


if app_settings.GROUPREPLY_ADMIN:
    @admin.register(RadiusGroupReply)
    class RadiusGroupReplyAdmin(MultitenantAdminMixin,
                                AbstractRadiusGroupReplyAdmin):
        multitenant_parent = 'group'


if app_settings.GROUPCHECK_ADMIN:
    @admin.register(RadiusGroupCheck)
    class RadiusGroupCheckAdmin(MultitenantAdminMixin,
                                AbstractRadiusGroupCheckAdmin):
        multitenant_parent = 'group'


@admin.register(Nas)
class NasAdmin(MultitenantAdminMixin,
               AbstractNasAdmin):
    pass


NasAdmin.fieldsets[0][1]['fields'] = ('organization',) + NasAdmin.fieldsets[0][1]['fields']
NasAdmin.list_display.insert(1, 'organization')
NasAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusPostAuth)
class RadiusPostAuthAdmin(OrganizationFirstMixin,
                          AbstractRadiusPostAuthAdmin):
    pass


RadiusPostAuthAdmin.list_display.insert(1, 'organization')
RadiusPostAuthAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusBatch)
class RadiusBatchAdmin(MultitenantAdminMixin,
                       AbstractRadiusBatchAdmin):
    pass


RadiusBatchAdmin.fields.insert(0, 'organization')
RadiusBatchAdmin.list_display.insert(1, 'organization')
RadiusBatchAdmin.list_filter += (('organization', MultitenantOrgFilter),)


class PhoneTokenInline(TimeReadonlyAdminMixin, StackedInline):
    model = PhoneToken
    extra = 0
    readonly_fields = ('verified', 'valid_until', 'attempts', 'ip')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


UserAdmin.inlines += [RadiusUserGroupInline, PhoneTokenInline]


class AlwaysHasChangedForm(AlwaysHasChangedMixin, forms.ModelForm):
    pass


class OrganizationRadiusSettingsInline(admin.StackedInline):
    model = OrganizationRadiusSettings
    form = AlwaysHasChangedForm


OrganizationAdmin.save_on_top = True
OrganizationAdmin.inlines.insert(2, OrganizationRadiusSettingsInline)


# avoid cluttering the admin with too many models, leave only the
# minimum required to configure social login and check if it's working
if app_settings.SOCIAL_LOGIN_ENABLED:
    from django.apps import apps
    from allauth.socialaccount.admin import SocialAccount, SocialApp, SocialAppAdmin

    Token = apps.get_model('authtoken', 'Token')

    admin.site.unregister(Token)
    admin.site.register(SocialApp, SocialAppAdmin)

    class SocialAccountInline(admin.StackedInline):
        model = SocialAccount
        extra = 0
        readonly_fields = ('provider', 'uid', 'extra_data')

        def has_add_permission(self, request, obj=None):
            return False

        def has_delete_permission(self, request, obj=None):
            return False

    UserAdmin.inlines += [SocialAccountInline]
