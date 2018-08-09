from django.contrib import admin
from django_freeradius.base.admin import (AbstractNasAdmin, AbstractRadiusAccountingAdmin,
                                          AbstractRadiusBatchAdmin, AbstractRadiusCheckAdmin,
                                          AbstractRadiusGroupCheckAdmin, AbstractRadiusGroupReplyAdmin,
                                          AbstractRadiusPostAuthAdmin, AbstractRadiusProfileAdmin,
                                          AbstractRadiusReplyAdmin, AbstractRadiusUserGroupAdmin,
                                          AbstractRadiusUserProfileInline, AbstractUserAdmin)

from openwisp_users.admin import UserAdmin
from openwisp_utils.admin import MultitenantAdminMixin, MultitenantOrgFilter, MultitenantRelatedOrgFilter

from .models import (Nas, RadiusAccounting, RadiusBatch, RadiusCheck, RadiusGroupCheck, RadiusGroupReply,
                     RadiusPostAuth, RadiusProfile, RadiusReply, RadiusUserGroup, RadiusUserProfile)


@admin.register(RadiusCheck)
class RadiusCheckAdmin(MultitenantAdminMixin, AbstractRadiusCheckAdmin):
    pass


RadiusCheckAdmin.list_display += ('organization',)
RadiusCheckAdmin.list_filter += (('organization', MultitenantOrgFilter),)
RadiusCheckAdmin.fields.insert(1, 'organization')


@admin.register(RadiusReply)
class RadiusReplyAdmin(MultitenantAdminMixin, AbstractRadiusReplyAdmin):
    pass


RadiusReplyAdmin.list_display += ('organization',)
RadiusReplyAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusAccounting)
class RadiusAccountingAdmin(MultitenantAdminMixin, AbstractRadiusAccountingAdmin):
    pass


RadiusAccountingAdmin.list_display += ('organization',)
RadiusAccountingAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(Nas)
class NasAdmin(MultitenantAdminMixin, AbstractNasAdmin):
    pass


NasAdmin.list_display += ('organization',)
NasAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusUserGroup)
class RadiusUserGroupAdmin(MultitenantAdminMixin, AbstractRadiusUserGroupAdmin):
    pass


RadiusUserGroupAdmin.list_display += ('organization',)
RadiusUserGroupAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusGroupReply)
class RadiusGroupReplyAdmin(MultitenantAdminMixin, AbstractRadiusGroupReplyAdmin):
    pass


RadiusGroupReplyAdmin.list_display += ('organization',)
RadiusGroupReplyAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusGroupCheck)
class RadiusGroupCheckAdmin(MultitenantAdminMixin, AbstractRadiusGroupCheckAdmin):
    pass


RadiusGroupCheckAdmin.list_display += ('organization',)
RadiusGroupCheckAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusPostAuth)
class RadiusPostAuthAdmin(MultitenantAdminMixin, AbstractRadiusPostAuthAdmin):
    pass


RadiusPostAuthAdmin.list_display += ('organization',)
RadiusPostAuthAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusBatch)
class RadiusBatchAdmin(MultitenantAdminMixin, AbstractRadiusBatchAdmin):
    pass


RadiusBatchAdmin.list_display += ('organization',)
RadiusBatchAdmin.list_filter += (('organization', MultitenantOrgFilter),)


@admin.register(RadiusProfile)
class RadiusProfileAdmin(MultitenantAdminMixin, AbstractRadiusProfileAdmin):
    pass


RadiusProfileAdmin.list_display += ('organization',)
RadiusProfileAdmin.list_filter += (('organization', MultitenantOrgFilter),)


class RadiusUserProfileInline(AbstractRadiusUserProfileInline):
    model = RadiusUserProfile


UserAdmin.inlines.append(RadiusUserProfileInline)
