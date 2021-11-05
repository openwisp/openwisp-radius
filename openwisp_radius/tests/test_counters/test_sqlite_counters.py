from openwisp_utils.tests import capture_any_output

from ...counters.base import BaseCounter
from ...counters.exceptions import MaxQuotaReached, SkipCheck
from ...counters.sqlite.daily_counter import DailyCounter
from ...counters.sqlite.daily_traffic_counter import DailyTrafficCounter
from ...utils import load_model
from ..mixins import BaseTestCase
from .utils import TestCounterMixin, _acct_data

RadiusAccounting = load_model('RadiusAccounting')


class TestSqliteCounters(TestCounterMixin, BaseTestCase):
    def test_time_counter_repr(self):
        opts = self._get_kwargs('Max-Daily-Session')
        counter = DailyCounter(**opts)
        expected = (
            'sqlite.DailyCounter(user=tester, '
            'group=test-org-users, '
            f'organization_id={counter.organization_id})'
        )
        self.assertEqual(repr(counter), expected)

    def test_time_counter_no_sessions(self):
        opts = self._get_kwargs('Max-Daily-Session')
        counter = DailyCounter(**opts)
        self.assertEqual(counter.check(), int(opts['group_check'].value))

    def test_time_counter_with_sessions(self):
        opts = self._get_kwargs('Max-Daily-Session')
        counter = DailyCounter(**opts)
        self._create_radius_accounting(**_acct_data)
        expected = int(opts['group_check'].value) - int(_acct_data['session_time'])
        self.assertEqual(counter.check(), expected)
        _acct_data2 = _acct_data.copy()
        _acct_data2.update({'session_id': '2', 'unique_id': '2', 'session_time': '500'})
        self._create_radius_accounting(**_acct_data2)
        session_time = int(_acct_data['session_time']) + int(
            _acct_data2['session_time']
        )
        expected = int(opts['group_check'].value) - session_time
        self.assertEqual(counter.check(), expected)

    @capture_any_output()
    def test_counter_skip_exceptions(self):
        options = self._get_kwargs('Max-Daily-Session')

        with self.subTest('missing group'):
            opts = options.copy()
            opts['group'] = None
            with self.assertRaises(AssertionError):
                counter = DailyCounter(**opts)

        with self.subTest('missing group check'):
            opts = options.copy()
            opts['group_check'] = None
            counter = DailyCounter(**opts)
            with self.assertRaises(SkipCheck) as ctx:
                counter.check()
            self.assertEqual(ctx.exception.level, 'debug')

        group_check_value = options['group_check'].value

        with self.subTest('missing group check'):
            opts = options.copy()
            opts['group_check'].value = 'broken'
            counter = DailyCounter(**opts)
            with self.assertRaises(SkipCheck) as ctx:
                counter.check()
            self.assertEqual(ctx.exception.level, 'info')
            self.assertIn('cannot be converted to integer', ctx.exception.message)

        options['group_check'].value = group_check_value

        with self.subTest('MaxQuotaReached'):
            acct_data = _acct_data.copy()
            acct_data['session_time'] = '200000'
            self._create_radius_accounting(**acct_data)
            with self.assertRaises(MaxQuotaReached) as ctx:
                counter.check()
            self.assertEqual(ctx.exception.level, 'info')
            self.assertEqual(ctx.exception.reply_message, BaseCounter.reply_message)

    def test_traffic_counter_no_sessions(self):
        opts = self._get_kwargs('Max-Daily-Session-Traffic')
        counter = DailyTrafficCounter(**opts)
        self.assertEqual(counter.check(), int(opts['group_check'].value))

    def test_traffic_counter_with_sessions(self):
        opts = self._get_kwargs('Max-Daily-Session-Traffic')
        counter = DailyTrafficCounter(**opts)
        acct = _acct_data.copy()
        acct.update({'input_octets': '50000', 'output_octets': '60000'})
        self._create_radius_accounting(**acct)
        traffic = int(acct['input_octets']) + int(acct['output_octets'])
        expected = int(opts['group_check'].value) - traffic
        self.assertEqual(counter.check(), expected)

    def test_traffic_counter_reply_and_check_name(self):
        opts = self._get_kwargs('Max-Daily-Session-Traffic')
        counter = DailyTrafficCounter(**opts)
        self.assertEqual(counter.check_name, 'Max-Daily-Session-Traffic')
        self.assertEqual(counter.reply_name, 'ChilliSpot-Max-Total-Octets')
