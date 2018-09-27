from django import forms
from django.contrib import admin
from django_freeradius.base.admin import (AbstractNasAdmin, AbstractRadiusAccountingAdmin,
                                          AbstractRadiusBatchAdmin, AbstractRadiusCheckAdmin,
                                          AbstractRadiusGroupAdmin, AbstractRadiusGroupCheckAdmin,
                                          AbstractRadiusGroupReplyAdmin, AbstractRadiusPostAuthAdmin,
                                          AbstractRadiusReplyAdmin, AbstractRadiusUserGroupAdmin,
                                          RadiusUserGroupInline)

from openwisp_users.admin import OrganizationAdmin, UserAdmin
from openwisp_utils.admin import MultitenantAdminMixin, MultitenantOrgFilter

from .models import (Nas, OrganizationRadiusSettings, RadiusAccounting, RadiusBatch, RadiusCheck, RadiusGroup,
                     RadiusGroupCheck, RadiusGroupReply, RadiusPostAuth, RadiusReply, RadiusUserGroup)


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
    pass


RadiusGroupAdmin.list_display.insert(1, 'organization')
RadiusGroupAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusUserGroup)
class RadiusUserGroupAdmin(MultitenantAdminMixin,
                           AbstractRadiusUserGroupAdmin):
    pass


@admin.register(RadiusGroupReply)
class RadiusGroupReplyAdmin(MultitenantAdminMixin,
                            AbstractRadiusGroupReplyAdmin):
    pass


@admin.register(RadiusGroupCheck)
class RadiusGroupCheckAdmin(MultitenantAdminMixin,
                            AbstractRadiusGroupCheckAdmin):
    pass


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


def get_inline_instances(modeladmin, request, obj=None):
    inlines = super(UserAdmin, modeladmin).get_inline_instances(request, obj)
    if obj:
        usergroup = RadiusUserGroupInline(modeladmin.model,
                                          modeladmin.admin_site)
        inlines.append(usergroup)
    return inlines


UserAdmin.get_inline_instances = get_inline_instances


# TODO: remove this once AlwaysHasChangedMixin is available in openwisp-utils
class AlwaysHasChangedForm(forms.ModelForm):
    def has_changed(self):
        """
        This django-admin trick ensures the settings
        are saved even if default values are unchanged
        (without this trick new setting objects won't be
        created unless users change the default values)
        """
        if self.instance._state.adding:
            return True
        return super(AlwaysHasChangedForm, self).has_changed()


class OrganizationRadiusSettingsInline(admin.StackedInline):
    model = OrganizationRadiusSettings
    form = AlwaysHasChangedForm


OrganizationAdmin.save_on_top = True
OrganizationAdmin.inlines.insert(0, OrganizationRadiusSettingsInline)
