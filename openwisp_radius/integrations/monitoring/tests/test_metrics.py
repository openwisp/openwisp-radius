from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.test import tag
from swapper import load_model

from openwisp_radius.tests import _RADACCT
from openwisp_radius.tests.mixins import BaseTransactionTestCase

from ..migrations import create_general_metrics
from .mixins import CreateDeviceMonitoringMixin

TASK_PATH = 'openwisp_radius.integrations.monitoring.tasks'

RegisteredUser = load_model('openwisp_radius', 'RegisteredUser')


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
    def test_post_save_registered_user(self, *args):
        user = self._create_user()
        org1 = self._create_org(name='org1')
        org2 = self._create_org(name='org2')
        self._create_org_user(user=user, organization=org1)
        self._create_org_user(user=user, organization=org2)
        self._create_registered_user(user=user)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration='user_signups',
                name='User SignUps',
                key='user_signups',
                object_id=None,
                content_type=None,
            ).count(),
            1,
        )
        metric = self.metric_model.objects.filter(key='user_signups').first()
        points = metric.read()
        # The query performs DISTINCT on the username field,
        # therefore the read() method returns only one point.
        self.assertEqual(len(points), 1)
        # Assert username field is hashed
        self.assertNotEqual(points[0]['user_id'], str(user.id))

    @patch('openwisp_monitoring.monitoring.models.Metric.write')
    @patch('logging.Logger.warning')
    @patch('openwisp_monitoring.monitoring.models.Metric.batch_write')
    def test_post_save_registered_user_edge_cases(
        self, mocked_metric_batch_write, mocked_logger, *args
    ):
        user = self._create_user()

        with self.subTest('Test organization user does not exist'):
            reg_user = self._create_registered_user(user=user)
            mocked_logger.assert_called_once_with(
                f'"{user.id}" is not a member of any organization.'
                ' Skipping user_signup metric writing!'
            )
            mocked_metric_batch_write.assert_not_called()

        self._create_org_user(user=user)

        with self.subTest('Test saving an existing RegisteredUser object'):
            with patch(f'{TASK_PATH}.post_save_registereduser.delay') as mocked_task:
                reg_user.is_verified = True
                reg_user.full_clean()
                reg_user.save()
            mocked_task.assert_not_called()
            mocked_metric_batch_write.assert_not_called()

    @patch('logging.Logger.warning')
    def test_post_save_organization_user(self, *args):
        user = self._create_user()
        self._create_registered_user(user=user, method='')
        self._create_org_user(user=user)
        self.assertEqual(
            self.metric_model.objects.filter(
                configuration='user_signups',
                name='User SignUps',
                key='user_signups',
                object_id=None,
                content_type=None,
            ).count(),
            1,
        )
        metric = self.metric_model.objects.filter(key='user_signups').first()
        points = metric.read()
        self.assertEqual(len(points), 1)
        # Assert username field is hashed
        self.assertNotEqual(points[0]['user_id'], str(user.id))

    @patch('openwisp_monitoring.monitoring.models.Metric.batch_write')
    @patch('logging.Logger.warning')
    @patch('openwisp_monitoring.monitoring.models.Metric.write')
    def test_post_save_organization_user_edge_cases(
        self, mocked_metric_write, mocked_logger, *args
    ):
        user = self._create_user()

        with self.subTest('Test registered user does not exist'):
            org_user = self._create_org_user(user=user)
            mocked_logger.assert_called_once_with(
                f'RegisteredUser object not found for "{user.id}".'
                ' Skipping user_signup metric writing!'
            )
            mocked_metric_write.assert_not_called()

        self._create_registered_user(user=user)

        with self.subTest('Test saving an existing RegisteredUser object'):
            with patch(f'{TASK_PATH}.post_save_organizationuser.delay') as mocked_task:
                org_user.is_admin = True
                org_user.full_clean()
                org_user.save()
            mocked_task.assert_not_called()
            mocked_metric_write.assert_not_called()

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
                    'calling_station_id': '00:00:00:00:00:00',
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

    @patch('logging.Logger.warning')
    def test_post_save_radius_accounting(self, mocked_logger):
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
                    'calling_station_id': '00:00:00:00:00:00',
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

    @patch('openwisp_monitoring.monitoring.models.Metric.batch_write')
    @patch('logging.Logger.warning')
    def test_post_save_radiusaccounting_edge_cases(
        self, mocked_logger, mocked_metric_write, *args
    ):
        options = _RADACCT.copy()
        options['called_station_id'] = '00:00:00:00:00:00'
        options['unique_id'] = '117'
        with self.subTest('Test session is not closed'):
            with patch(f'{TASK_PATH}.post_save_registereduser.delay') as mocked_task:
                rad_acc = self._create_radius_accounting(**options)
                self.assertEqual(rad_acc.stop_time, None)
            mocked_task.assert_not_called()
            mocked_metric_write.assert_not_called()

        user = self._create_user()
        options['username'] = user.username
        options['unique_id'] = '118'
        options['stop_time'] = options['start_time']

        with self.subTest('Test RegisteredUser object does not exist'):
            rad_acc = self._create_radius_accounting(**options)
            self.assertNotEqual(rad_acc.stop_time, None)
            mocked_logger.assert_called_once_with(
                f'RegisteredUser object not found for "{user.username}".'
                ' Skipping radius_acc metric writing!'
            )
