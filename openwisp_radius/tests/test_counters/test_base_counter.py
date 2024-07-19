from datetime import datetime
from unittest.mock import patch

from freezegun import freeze_time

from openwisp_utils.tests import capture_any_output

from ... import settings as app_settings
from ...counters.base import BaseCounter, BaseDailyCounter, BaseMontlhyTrafficCounter
from ...counters.exceptions import SkipCheck
from ...counters.resets import resets
from ...utils import load_model
from ..mixins import BaseTransactionTestCase
from .utils import TestCounterMixin

RadiusAccounting = load_model('RadiusAccounting')


class TestBaseCounter(TestCounterMixin, BaseTransactionTestCase):
    @capture_any_output()
    def test_wrong_reset_time(self):
        class BrokenCounter(BaseCounter):
            counter_name = 'Broken'
            check_name = 'Broken'
            reply_name = 'Broken'
            reset = 'broken'
            sql = 'broken'

            def get_sql_params(self, start_time, end_time):
                return []

        opts = self._get_kwargs('Max-Daily-Session')
        counter = BrokenCounter(**opts)
        with self.assertRaises(SkipCheck) as ctx:
            counter.get_reset_timestamps()
        self.assertEqual(ctx.exception.level, 'error')

    def test_abstract_instantiation(self):
        opts = self._get_kwargs('Max-Daily-Session')

        with self.assertRaises(TypeError) as ctx:
            BaseCounter(**opts)
        self.assertIn('abstract class BaseCounter', str(ctx.exception))

    @freeze_time('2021-11-03T08:21:44-04:00')
    def test_resets(self):
        with self.subTest('daily'):
            start, end = resets['daily']()
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), '2021-11-03 00:00:00')
            self.assertEqual(str(datetime.fromtimestamp(end)), '2021-11-04 00:00:00')

        with self.subTest('weekly'):
            start, end = resets['weekly']()
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), '2021-11-01 00:00:00')
            self.assertEqual(str(datetime.fromtimestamp(end)), '2021-11-08 00:00:00')

        with self.subTest('monthly'):
            start, end = resets['monthly']()
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), '2021-11-01 00:00:00')
            self.assertEqual(str(datetime.fromtimestamp(end)), '2021-12-01 00:00:00')

        user = self._get_user()

        with self.subTest('monthly_subscription same month'):
            user.date_joined = datetime.fromisoformat('2021-07-02 12:34:58')
            user.save(update_fields=['date_joined'])
            start, end = resets['monthly_subscription'](user)
            self.assertIsInstance(start, int)
            self.assertIsInstance(end, int)
            self.assertEqual(str(datetime.fromtimestamp(start)), '2021-11-02 00:00:00')
            self.assertEqual(str(datetime.fromtimestamp(end)), '2021-12-02 00:00:00')

        with self.subTest('monthly_subscription prev month'):
            user.date_joined = datetime.fromisoformat('2021-07-22 12:34:58')
            user.save(update_fields=['date_joined'])
            start, end = resets['monthly_subscription'](user)
            self.assertEqual(str(datetime.fromtimestamp(start)), '2021-10-22 00:00:00')
            self.assertEqual(str(datetime.fromtimestamp(end)), '2021-11-22 00:00:00')

        with self.subTest('never'):
            start, end = resets['never']()
            self.assertEqual(start, 0)
            self.assertEqual(str(datetime.fromtimestamp(start)), '1970-01-01 00:00:00')
            self.assertIsNone(end)

    @patch.object(
        app_settings, 'RADIUS_ATTRIBUTES_TYPE_MAP', {'Max-Input-Octets': 'bytes'}
    )
    def test_get_attribute_type(self):
        class MaxInputOctetsCounter(BaseDailyCounter):
            check_name = 'Max-Input-Octets'

        self.assertEqual(BaseDailyCounter.get_attribute_type(), 'seconds')
        self.assertEqual(BaseMontlhyTrafficCounter.get_attribute_type(), 'bytes')
        self.assertEqual(MaxInputOctetsCounter.get_attribute_type(), 'bytes')


del BaseTransactionTestCase
