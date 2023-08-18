from django.contrib import admin
from django.urls import reverse
from swapper import load_model

Device = load_model('config', 'Device')
RadiusAccounting = load_model('openwisp_radius', 'RadiusAccounting')

BaseDeviceAdmin = admin.site._registry[Device].__class__


class DeviceAdmin(BaseDeviceAdmin):
    change_form_template = 'admin/config/radius-monitoring/device/change_form.html'

    class Media:
        js = tuple(BaseDeviceAdmin.Media.js) + (
            'radius-monitoring/js/device-change.js',
        )
        css = {
            'all': ('radius-monitoring/css/device-change.css',)
            + BaseDeviceAdmin.Media.css['all']
        }

    def get_extra_context(self, pk=None):
        ctx = super().get_extra_context(pk)
        ctx.update(
            {
                'radius_accounting_api_endpoint': reverse(
                    'radius:radius_accounting_list'
                ),
                'radius_accounting': reverse(
                    f'admin:{RadiusAccounting._meta.app_label}'
                    f'_{RadiusAccounting._meta.model_name}_changelist'
                ),
            }
        )
        return ctx


admin.site.unregister(Device)
admin.site.register(Device, DeviceAdmin)
