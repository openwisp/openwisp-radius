import os
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.utils.timezone import now

from openwisp_utils.tests import capture_any_output, capture_stdout

from .. import settings as app_settings
from ..utils import load_model
from . import _RADACCT, CallCommandMixin, FileMixin
from .mixins import BaseTestCase

User = get_user_model()
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
RadiusPostAuth = load_model('RadiusPostAuth')
RegisteredUser = load_model('RegisteredUser')


class TestCommands(FileMixin, CallCommandMixin, BaseTestCase):
    @capture_any_output()
    def test_cleanup_stale_radacct_command(self):
        options = _RADACCT.copy()
        options['unique_id'] = '117'
        self._create_radius_accounting(**options)
        call_command('cleanup_stale_radacct', 30)
        session = RadiusAccounting.objects.get(unique_id='117')
        self.assertNotEqual(session.stop_time, None)
        self.assertNotEqual(session.session_time, None)
        self.assertEqual(session.update_time, session.stop_time)

    @capture_any_output()
    def test_delete_old_postauth_command(self):
        options = dict(username='steve', password='jones', reply='value1')
        self._create_radius_postauth(**options)
        RadiusPostAuth.objects.filter(username='steve').update(date='2017-06-10')
        call_command('delete_old_postauth', 3)
        self.assertEqual(RadiusPostAuth.objects.filter(username='steve').count(), 0)

    @capture_any_output()
    def test_delete_old_radacct_command(self):
        options = _RADACCT.copy()
        options['stop_time'] = '2017-06-10 11:50:00'
        options['update_time'] = '2017-03-10 11:50:00'
        options['unique_id'] = '666'
        self._create_radius_accounting(**options)
        call_command('delete_old_radacct', 3)
        self.assertEqual(RadiusAccounting.objects.filter(unique_id='666').count(), 0)

    @capture_stdout()
    def test_batch_add_users_command(self):
        self.assertEqual(RadiusBatch.objects.all().count(), 0)
        path = self._get_path('static/test_batch.csv')
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration='28-01-2018',
            name='test',
        )
        self._call_command('batch_add_users', **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        radiusbatch = RadiusBatch.objects.first()
        self.assertEqual(get_user_model().objects.all().count(), 3)
        self.assertEqual(radiusbatch.expiration_date.strftime('%d-%m-%y'), '28-01-18')
        path = self._get_path('static/test_batch_new.csv')
        options = dict(organization=self.default_org.slug, file=path, name='test1')
        self._call_command('batch_add_users', **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 2)
        self.assertEqual(get_user_model().objects.all().count(), 6)
        invalid_csv_path = self._get_path('static/test_batch_invalid.csv')
        with self.assertRaises(CommandError):
            options = dict(
                organization=self.default_org.slug,
                file='doesnotexist.csv',
                name='test3',
            )
            self._call_command('batch_add_users', **options)
        with self.assertRaises(SystemExit):
            options = dict(
                organization=self.default_org.slug, file=invalid_csv_path, name='test4'
            )
            self._call_command('batch_add_users', **options)

    @capture_stdout()
    def test_deactivate_expired_users_command(self):
        path = self._get_path('static/test_batch.csv')
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration='28-01-1970',
            name='test',
        )
        self._call_command('batch_add_users', **options)
        self.assertEqual(get_user_model().objects.filter(is_active=True).count(), 3)
        call_command('deactivate_expired_users')
        self.assertEqual(get_user_model().objects.filter(is_active=True).count(), 0)

    @capture_stdout()
    def test_delete_old_users_command(self):
        path = self._get_path('static/test_batch.csv')
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration='28-01-1970',
            name='test',
        )
        self._call_command('batch_add_users', **options)
        expiration_date = (now() - timedelta(days=30 * 15)).strftime('%d-%m-%Y')
        path = self._get_path('static/test_batch_new.csv')
        options = dict(
            organization=self.default_org.slug,
            file=path,
            expiration=expiration_date,
            name='test1',
        )
        self._call_command('batch_add_users', **options)
        self.assertEqual(get_user_model().objects.all().count(), 6)
        call_command('delete_old_users')
        self.assertEqual(get_user_model().objects.all().count(), 3)
        call_command('delete_old_users', older_than_months=12)
        self.assertEqual(get_user_model().objects.all().count(), 0)

    @capture_stdout()
    def test_prefix_add_users_command(self):
        self.assertEqual(RadiusBatch.objects.all().count(), 0)
        output_pdf = os.path.join(settings.MEDIA_ROOT, 'test_prefix10.pdf')
        options = dict(
            organization=self.default_org.slug,
            prefix='test-prefix7',
            n=10,
            name='test',
            expiration='28-01-2018',
            output=output_pdf,
        )
        self._call_command('prefix_add_users', **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertTrue(os.path.isfile(output_pdf))
        os.remove(output_pdf)
        radiusbatch = RadiusBatch.objects.first()
        users = get_user_model().objects.all()
        self.assertEqual(users.count(), 10)
        for u in users:
            self.assertTrue('test-prefix7' in u.username)
        self.assertEqual(radiusbatch.expiration_date.strftime('%d-%m-%y'), '28-01-18')
        options = dict(
            organization=self.default_org.slug, prefix='test-prefix8', n=5, name='test1'
        )
        self._call_command('prefix_add_users', **options)
        self.assertEqual(RadiusBatch.objects.all().count(), 2)
        self.assertEqual(get_user_model().objects.all().count(), 15)
        options = dict(
            organization=self.default_org.slug,
            prefix='test-prefix9',
            n=-5,
            name='test2',
        )
        with self.assertRaises(SystemExit):
            self._call_command('prefix_add_users', **options)

    @capture_stdout()
    def test_unverified_users_command(self):
        def _create_old_users():
            User.objects.all().delete()
            RadiusBatch.objects.all().delete()
            path = self._get_path('static/test_batch.csv')
            options = dict(organization=self.default_org.slug, file=path, name='test',)
            self._call_command('batch_add_users', **options)
            User.objects.update(date_joined=now() - timedelta(days=3))
            for user in User.objects.all():
                RegisteredUser.objects.create(
                    user=user, method='email', is_verified=False
                )

        with self.subTest('Delete unverified users older than 2 days'):
            _create_old_users()
            # This user should not be deleted
            RegisteredUser.objects.create(
                user=self._create_user(), method='mobile_phone', is_verified=False
            )

            self.assertEqual(User.objects.count(), 4)
            call_command('delete_unverified_users', older_than_days=2)
            self.assertEqual(User.objects.count(), 1)

        with self.subTest(
            'Delete unverified users except registered with mobile_phone'
        ):
            _create_old_users()
            # This user should not be deleted
            RegisteredUser.objects.create(
                user=self._create_user(date_joined=now() - timedelta(days=3)),
                method='mobile_phone',
                is_verified=False,
            )

            self.assertEqual(User.objects.count(), 4)
            call_command(
                'delete_unverified_users',
                older_than_days=2,
                exclude_methods='mobile_phone,manual',
            )
            self.assertEqual(User.objects.count(), 1)

        with self.subTest('Verified user should not be deleted'):
            _create_old_users()
            # This user should not be deleted
            RegisteredUser.objects.create(
                user=self._create_user(date_joined=now() - timedelta(days=3)),
                method='email',
                is_verified=True,
            )
            self.assertEqual(User.objects.count(), 4)
            call_command('delete_unverified_users',)
            self.assertEqual(User.objects.count(), 1)

    @patch.object(
        app_settings,
        'CALLED_STATION_IDS',
        {
            'test-org': {
                'openvpn_config': [
                    {'host': '127.0.0.1', 'port': 7505, 'password': 'somepassword'}
                ],
                'captive_portal_macs': ['AA-AA-AA-AA-AA-AA'],
            }
        },
    )
    def test_convert_called_station_id_command(self):
        options = _RADACCT.copy()
        options['calling_station_id'] = 'bb:bb:bb:bb:bb:bb'
        options['called_station_id'] = 'AA-AA-AA-AA-AA-AA'
        options['unique_id'] = '117'
        options['organization'] = self._get_org()
        radius_acc = self._create_radius_accounting(**options)
        with open(self._get_path('static/openvpn.status')) as status_file:
            with patch(
                'openwisp_radius.management.commands.base.convert_called_station_id'
                '.BaseConvertCalledStationIdCommand._get_raw_management_info',
                return_value=status_file.read(),
            ):
                call_command('convert_called_station_id')
        radius_acc.refresh_from_db()
        self.assertEqual(radius_acc.called_station_id, 'CC-CC-CC-CC-CC-CC')
