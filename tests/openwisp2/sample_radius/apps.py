from openwisp_radius.apps import OpenwispRadiusConfig
from openwisp_radius.receivers import send_email_on_new_accounting_handler
from openwisp_radius.signals import radius_accounting_success


class SampleOpenwispRadiusConfig(OpenwispRadiusConfig):
    name = 'openwisp2.sample_radius'
    label = 'sample_radius'
    verbose_name = 'Sample Radius'

    def connect_signals(self):
        from .api.views import AccountingView

        radius_accounting_success.connect(
            send_email_on_new_accounting_handler,
            sender=AccountingView,
            dispatch_uid='send_email_on_new_accounting',
        )
        return super().connect_signals()
