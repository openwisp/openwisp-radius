from datetime import datetime

from freezegun import freeze_time

from openwisp_utils.tests import capture_any_output

from ...counters.base import BaseCounter
from ...counters.exceptions import SkipCheck
from ...counters.resets import resets
from ...utils import load_model
from ..mixins import BaseTestCase
from .utils import TestCounterMixin

RadiusAccounting = load_model('RadiusAccounting')


class TestBaseCounter(TestCounterMixin, BaseTestCase):
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

        with self.subTest('never'):
            start, end = resets['never']()
            self.assertEqual(start, 0)
            self.assertEqual(str(datetime.fromtimestamp(start)), '1970-01-01 00:00:00')
            self.assertIsNone(end)
