from uuid import uuid4

from openwisp_monitoring.db import timeseries_db
from openwisp_monitoring.db.backends import TIMESERIES_DB
from openwisp_monitoring.device.utils import manage_short_retention_policy
from swapper import load_model


class CreateDeviceMonitoringMixin(object):
    TEST_MAC_ADDRESS = '00:11:22:33:44:55'
    ORIGINAL_DB = TIMESERIES_DB['NAME']
    TEST_DB = f'{ORIGINAL_DB}_test'

    @classmethod
    def setUpClass(cls):
        # By default timeseries_db.db shall connect to the database
        # defined in settings when apps are loaded. We don't want that while testing
        timeseries_db.db_name = cls.TEST_DB
        del timeseries_db.db
        del timeseries_db.dbs
        timeseries_db.create_database()
        manage_short_retention_policy()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        timeseries_db.drop_database()
        super().tearDownClass()

    def tearDown(self):
        timeseries_db.delete_metric_data()
        super().tearDown()

    @property
    def device_model(self):
        return load_model('config', 'Device')

    @property
    def metric_model(self):
        return load_model('monitoring', 'Metric')

    @property
    def chart_model(self):
        return load_model('monitoring', 'Chart')

    @property
    def location_model(self):
        return load_model('geo', 'Location')

    @property
    def object_location_model(self):
        return load_model('geo', 'DeviceLocation')

    def _create_device(self, **kwargs):
        options = dict(
            name='default.test.device',
            organization=self._get_org(),
            mac_address=self.TEST_MAC_ADDRESS,
            hardware_id=str(uuid4().hex),
            model='TP-Link TL-WDR4300 v1',
            os='LEDE Reboot 17.01-SNAPSHOT r3313-c2999ef',
        )
        options.update(kwargs)
        d = self.device_model(**options)
        d.full_clean()
        d.save()
        return d

    def _create_location(self, **kwargs):
        options = dict(
            name='test-location',
            address='Via del Corso, Roma, Italia',
            geometry='SRID=4326;POINT (12.512124 41.898903)',
            type='outdoor',
        )
        options.update(kwargs)
        location = self.location_model(**options)
        location.full_clean()
        location.save()
        return location

    def _create_device_location(self, **kwargs):
        options = dict()
        options.update(kwargs)
        device_location = self.object_location_model(**options)
        device_location.full_clean()
        device_location.save()
        return device_location
