from django_freeradius.apps import DjangoFreeradiusConfig


class OpenwispRadiusConfig(DjangoFreeradiusConfig):
    name = 'openwisp_radius'

    def check_settings(self):
        pass
