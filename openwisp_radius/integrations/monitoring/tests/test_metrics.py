from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.test import tag
from swapper import load_model

from openwisp_radius.tests import _RADACCT
from openwisp_radius.tests.mixins import BaseTransactionTestCase

from ..migrations import create_general_metrics
from ..utils import sha1_hash
from .mixins import CreateDeviceMonitoringMixin

TASK_PATH = 'openwisp_radius.integrations.monitoring.tasks'

RegisteredUser = load_model('openwisp_radius', 'RegisteredUser')
User = get_user_model()


@tag('radius_monitoring')
class TestMetrics(CreateDeviceMonitoringMixin, BaseTransactionTestCase):
    def _create_registered_user(self, **kwargs):
        options = {'is_verified': False, 'method': 'mobile_phone'}
        options.update(**kwargs)
        if 'user' not in options:
            options['user'] = self._create_user()
        reg_user = RegisteredUser(**options)
        reg_user.full_clean()
        reg_user.save()
        return reg_user

    @patch('logging.Logger.warning')
    def test_post_save_radiusaccounting(self, *args):
        user = self._create_user()
        reg_user = self._create_registered_user(user=user)
        device = self._create_device()
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        options = _RADACCT.copy()
        options.update(
            {
                'unique_id': '117',
                'username': user.username,
                'called_station_id': device.mac_address.replace('-', ':').upper(),
                'calling_station_id': '00:00:00:00:00:00',
                'input_octets': '8000000000',
                'output_octets': '9000000000',
            }
        )
        options['stop_time'] = options['start_time']

        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration='radius_acc',
                name='RADIUS Accounting',
                key='radius_acc',
                object_id=str(device.id),
                content_type=ContentType.objects.get_for_model(self.device_model),
                extra_tags={
                    'called_station_id': device.mac_address,
                    'calling_station_id': sha1_hash('00:00:00:00:00:00'),
                    'location_id': str(device_loc.location.id),
                    'method': reg_user.method,
                    'organization_id': str(self.default_org.id),
                },
            ).count(),
            1,
        )
        metric = self.metric_model.objects.filter(configuration='radius_acc').first()
        traffic_chart = metric.chart_set.get(configuration='radius_traffic')
        points = traffic_chart.read()
        self.assertEqual(points['traces'][0][0], 'download')
        self.assertEqual(points['traces'][0][1][-1], 8)
        self.assertEqual(points['traces'][1][0], 'upload')
        self.assertEqual(points['traces'][1][1][-1], 9)
        self.assertEqual(points['summary'], {'upload': 9, 'download': 8})

        session_chart = metric.chart_set.get(configuration='rad_session')
        points = session_chart.read()
        self.assertEqual(points['traces'][0][0], 'mobile_phone')
        self.assertEqual(points['traces'][0][1][-1], 1)
        self.assertEqual(points['summary'], {'mobile_phone': 1})

    @patch('openwisp_radius.integrations.monitoring.tasks.post_save_radiusaccounting')
    def test_post_save_radiusaccouting_open_session(self, mocked_task):
        radius_options = _RADACCT.copy()
        radius_options['unique_id'] = '117'
        session = self._create_radius_accounting(**radius_options)
        self.assertEqual(session.stop_time, None)
        mocked_task.assert_not_called()

    @patch('logging.Logger.warning')
    def test_post_save_radius_accounting_device_not_found(self, mocked_logger):
        """
        This test checks that radius accounting metric is created
        even if the device could not be found with the called_station_id.
        This scenario can happen on an installations which uses the
        convert_called_station_id feature, but it is not configured
        properly leaving all called_station_id unconverted.
        """
        user = self._create_user()
        reg_user = self._create_registered_user(user=user)
        options = _RADACCT.copy()
        options.update(
            {
                'unique_id': '117',
                'username': user.username,
                'called_station_id': '11:22:33:44:55:66',
                'calling_station_id': '00:00:00:00:00:00',
                'input_octets': '8000000000',
                'output_octets': '9000000000',
            }
        )
        options['stop_time'] = options['start_time']
        # Remove calls for user registration from mocked logger
        mocked_logger.reset_mock()

        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration='radius_acc',
                name='RADIUS Accounting',
                key='radius_acc',
                object_id=None,
                content_type=None,
                extra_tags={
                    'called_station_id': '11:22:33:44:55:66',
                    'calling_station_id': sha1_hash('00:00:00:00:00:00'),
                    'location_id': None,
                    'method': reg_user.method,
                    'organization_id': str(self.default_org.id),
                },
            ).count(),
            1,
        )
        # The TransactionTestCase truncates all the data after each test.
        # The general metrics and charts which are created by migrations
        # get deleted after each test. Therefore, we create them again here.
        create_general_metrics(None, None)
        metric = self.metric_model.objects.filter(configuration='radius_acc').first()
        # A dedicated chart for this metric was not created since the
        # related device was not identified by the called_station_id.
        # The data however can be retrieved from the general charts.
        self.assertEqual(metric.chart_set.count(), 0)
        general_traffic_chart = self.chart_model.objects.get(
            configuration='gen_rad_traffic'
        )
        points = general_traffic_chart.read()
        self.assertEqual(points['traces'][0][0], 'download')
        self.assertEqual(points['traces'][0][1][-1], 8)
        self.assertEqual(points['traces'][1][0], 'upload')
        self.assertEqual(points['traces'][1][1][-1], 9)
        self.assertEqual(points['summary'], {'upload': 9, 'download': 8})

        general_session_chart = self.chart_model.objects.get(
            configuration='gen_rad_session'
        )
        points = general_session_chart.read()
        self.assertEqual(points['traces'][0][0], 'mobile_phone')
        self.assertEqual(points['traces'][0][1][-1], 1)
        self.assertEqual(points['summary'], {'mobile_phone': 1})
        mocked_logger.assert_called_once_with(
            f'Device object not found with MAC "{options["called_station_id"]}"'
            f' and organization "{self.default_org.id}".'
            ' The metric will be written without a related object!'
        )

    @patch('logging.Logger.info')
    def test_post_save_radius_accounting_registereduser_not_found(self, mocked_logger):
        """
        This test checks that radius accounting metric is created
        even if the RegisteredUser object could not be found for the user.
        This scenario can happen on an installations which do not require
        users to signup to access the internet/
        """
        user = self._create_user()
        device = self._create_device()
        device_loc = self._create_device_location(
            content_object=device,
            location=self._create_location(organization=device.organization),
        )
        options = _RADACCT.copy()
        options.update(
            {
                'unique_id': '117',
                'username': user.username,
                'called_station_id': device.mac_address.replace('-', ':').upper(),
                'calling_station_id': '00:00:00:00:00:00',
                'input_octets': '8000000000',
                'output_octets': '9000000000',
            }
        )
        options['stop_time'] = options['start_time']

        self._create_radius_accounting(**options)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration='radius_acc',
                name='RADIUS Accounting',
                key='radius_acc',
                object_id=str(device.id),
                content_type=ContentType.objects.get_for_model(self.device_model),
                extra_tags={
                    'called_station_id': device.mac_address,
                    'calling_station_id': sha1_hash('00:00:00:00:00:00'),
                    'location_id': str(device_loc.location.id),
                    'method': 'unspecified',
                    'organization_id': str(self.default_org.id),
                },
            ).count(),
            1,
        )
        metric = self.metric_model.objects.filter(configuration='radius_acc').first()
        traffic_chart = metric.chart_set.get(configuration='radius_traffic')
        points = traffic_chart.read()
        self.assertEqual(points['traces'][0][0], 'download')
        self.assertEqual(points['traces'][0][1][-1], 8)
        self.assertEqual(points['traces'][1][0], 'upload')
        self.assertEqual(points['traces'][1][1][-1], 9)
        self.assertEqual(points['summary'], {'upload': 9, 'download': 8})

        session_chart = metric.chart_set.get(configuration='rad_session')
        points = session_chart.read()
        self.assertEqual(points['traces'][0][0], 'unspecified')
        self.assertEqual(points['traces'][0][1][-1], 1)
        self.assertEqual(points['summary'], {'unspecified': 1})
        mocked_logger.assert_called_once_with(
            f'RegisteredUser object not found for "{user.username}".'
            ' The metric will be written with "unspecified" registration method!'
        )

    def test_write_user_registration_metrics(self):
        from ..tasks import write_user_registration_metrics

        def _read_chart(chart, **kwargs):
            return chart.read(
                additional_query_kwargs={'additional_params': kwargs},
            )

        # The TransactionTestCase truncates all the data after each test.
        # The general metrics and charts which are created by migrations
        # get deleted after each test. Therefore, we create them again here.
        # The "Metric._get_metric" caches the metric, this interferes with
        # create_general_metrics, hence we clear the cache here.
        cache.clear()
        create_general_metrics(None, None)
        org = self._get_org()
        user_signup_metric = self.metric_model.objects.get(key='user_signups')
        total_user_signup_metric = self.metric_model.objects.get(key='tot_user_signups')
        with self.subTest(
            'User does not has OrganizationUser and RegisteredUser object'
        ):
            self._get_admin()
            write_user_registration_metrics.delay()

            user_signup_chart = user_signup_metric.chart_set.first()
            all_points = _read_chart(user_signup_chart, organization_id=['__all__'])
            self.assertEqual(all_points['traces'][0][0], 'unspecified')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(all_points['summary'], {'unspecified': 1})
            org_points = _read_chart(user_signup_chart, organization_id=[str(org.id)])
            self.assertEqual(len(org_points['traces']), 0)

            total_user_signup_chart = total_user_signup_metric.chart_set.first()
            all_points = _read_chart(
                total_user_signup_chart, organization_id=['__all__']
            )
            self.assertEqual(all_points['traces'][0][0], 'unspecified')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(all_points['summary'], {'unspecified': 1})
            org_points = _read_chart(
                total_user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(len(org_points['traces']), 0)

        self.metric_model.post_delete_receiver(user_signup_metric)
        self.metric_model.post_delete_receiver(total_user_signup_metric)
        User.objects.all().delete()

        with self.subTest('User has OrganizationUser but no RegisteredUser object'):
            user = self._create_org_user(organization=org).user
            write_user_registration_metrics.delay()

            user_signup_chart = user_signup_metric.chart_set.first()
            all_points = _read_chart(user_signup_chart, organization_id=['__all__'])
            self.assertEqual(all_points['traces'][0][0], 'unspecified')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(all_points['summary'], {'unspecified': 1})
            org_points = _read_chart(user_signup_chart, organization_id=[str(org.id)])
            self.assertEqual(all_points['traces'][0][0], 'unspecified')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(all_points['summary'], {'unspecified': 1})

            total_user_signup_chart = total_user_signup_metric.chart_set.first()
            all_points = _read_chart(
                total_user_signup_chart, organization_id=['__all__']
            )
            self.assertEqual(all_points['traces'][0][0], 'unspecified')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(all_points['summary'], {'unspecified': 1})
            org_points = _read_chart(
                total_user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(all_points['traces'][0][0], 'unspecified')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(all_points['summary'], {'unspecified': 1})

        self.metric_model.post_delete_receiver(user_signup_metric)
        self.metric_model.post_delete_receiver(total_user_signup_metric)

        with self.subTest(
            'Test user has both OrganizationUser and RegisteredUser object'
        ):
            self._create_registered_user(user=user)
            write_user_registration_metrics.delay()

            user_signup_chart = user_signup_metric.chart_set.first()
            all_points = _read_chart(user_signup_chart, organization_id=['__all__'])
            self.assertEqual(all_points['traces'][0][0], 'mobile_phone')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(
                all_points['summary'], {'mobile_phone': 1, 'unspecified': 0}
            )
            org_points = _read_chart(user_signup_chart, organization_id=[str(org.id)])
            self.assertEqual(all_points['traces'][0][0], 'mobile_phone')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(
                all_points['summary'], {'mobile_phone': 1, 'unspecified': 0}
            )

            total_user_signup_chart = total_user_signup_metric.chart_set.first()
            org_points = _read_chart(
                total_user_signup_chart, organization_id=['__all__']
            )
            self.assertEqual(org_points['traces'][0][0], 'mobile_phone')
            self.assertEqual(org_points['traces'][0][1][-1], 1)
            self.assertEqual(
                org_points['summary'], {'mobile_phone': 1, 'unspecified': 0}
            )
            org_points = _read_chart(
                total_user_signup_chart, organization_id=[str(org.id)]
            )
            self.assertEqual(all_points['traces'][0][0], 'mobile_phone')
            self.assertEqual(all_points['traces'][0][1][-1], 1)
            self.assertEqual(
                all_points['summary'], {'mobile_phone': 1, 'unspecified': 0}
            )
