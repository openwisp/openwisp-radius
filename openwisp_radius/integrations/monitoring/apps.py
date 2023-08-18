from django.apps import AppConfig
from django.db.models.signals import post_save
from django.utils.translation import gettext_lazy as _
from openwisp_monitoring.monitoring.configuration import (
    _register_chart_configuration_choice,
    register_metric,
)
from swapper import load_model


class OpenwispRadiusMonitoringConfig(AppConfig):
    name = 'openwisp_radius.integrations.monitoring'
    label = 'openwisp_radius_monitoring'
    verbose_name = _('OpenWISP RADIUS Monitoring')

    def ready(self):
        super().ready()
        self.register_radius_metrics()
        self.connect_signal_receivers()

    def register_radius_metrics(self):
        from .configuration import RADIUS_METRICS

        for metric_key, metric_config in RADIUS_METRICS.items():
            register_metric(metric_key, metric_config)
            for chart_key, chart_config in metric_config.get('charts', {}).items():
                _register_chart_configuration_choice(chart_key, chart_config)

    def connect_signal_receivers(self):
        from .receivers import (
            post_save_organizationuser,
            post_save_radiusaccounting,
            post_save_registereduser,
        )

        OrganizationUser = load_model('openwisp_users', 'OrganizationUser')
        RegisteredUser = load_model('openwisp_radius', 'RegisteredUser')
        RadiusAccounting = load_model('openwisp_radius', 'RadiusAccounting')

        post_save.connect(
            post_save_organizationuser,
            sender=OrganizationUser,
            dispatch_uid='post_save_organizationuser_user_signup_metric',
        )
        post_save.connect(
            post_save_registereduser,
            sender=RegisteredUser,
            dispatch_uid='post_save_registereduser_user_signup_metric',
        )
        post_save.connect(
            post_save_radiusaccounting,
            sender=RadiusAccounting,
            dispatch_uid='post_save_radiusaccounting_radius_acc_metric',
        )
