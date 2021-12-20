from datetime import timedelta
from unittest import mock

from celery import Celery
from celery.contrib.testing.worker import start_worker
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail, management
from django.utils.timezone import now

from openwisp_radius import tasks
from openwisp_utils.tests import capture_any_output, capture_stdout

from ..utils import load_model
from . import _RADACCT, FileMixin
from .mixins import BaseTestCase

User = get_user_model()
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
RadiusPostAuth = load_model('RadiusPostAuth')
RegisteredUser = load_model('RegisteredUser')


class TestCelery(FileMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app = Celery('openwisp2')
        app.config_from_object('django.conf:settings', namespace='CELERY')
        app.autodiscover_tasks()
        cls.celery_worker = start_worker(app)

    def _get_expired_user_from_radius_batch(self):
        reader = [['sample', 'admin', 'user@openwisp.com', 'SampleName', 'Lastname']]
        batch = self._create_radius_batch(
            name='test',
            strategy='csv',
            csvfile=self._get_csvfile(reader),
            expiration_date='1998-01-28',
        )
        batch.add(reader)
        return batch.users.first()

    @capture_stdout()
    def test_cleanup_stale_radacct(self):
        options = _RADACCT.copy()
        options['unique_id'] = '118'
        self._create_radius_accounting(**options)
        result = tasks.cleanup_stale_radacct.delay(30)
        self.assertTrue(result.successful())
        session = RadiusAccounting.objects.get(unique_id='118')
        self.assertNotEqual(session.stop_time, None)
        self.assertNotEqual(session.session_time, None)
        self.assertEqual(session.update_time, session.stop_time)

    @capture_stdout()
    def test_deactivate_expired_users(self):
        user = self._get_expired_user_from_radius_batch()
        self.assertTrue(user.is_active)
        result = tasks.deactivate_expired_users.delay()
        self.assertTrue(result.successful())
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    @capture_stdout()
    def test_delete_old_users(self):
        self._get_expired_user_from_radius_batch()
        self.assertEqual(User.objects.all().count(), 1)
        result = tasks.delete_old_users.delay(1)
        self.assertTrue(result.successful())
        self.assertEqual(User.objects.all().count(), 0)

    @capture_any_output()
    def test_delete_old_postauth(self):
        options = dict(username='steve', password='jones', reply='value2')
        self._create_radius_postauth(**options)
        RadiusPostAuth.objects.filter(username='steve').update(date='2018-01-31')
        result = tasks.delete_old_postauth.delay(3)
        self.assertTrue(result.successful())
        self.assertEqual(RadiusPostAuth.objects.filter(username='steve').count(), 0)

    @capture_any_output()
    def test_delete_old_radacct(self):
        options = _RADACCT.copy()
        options['stop_time'] = '2017-06-10 11:50:00'
        options['update_time'] = '2017-03-10 11:50:00'
        options['unique_id'] = '666'
        self._create_radius_accounting(**options)
        result = tasks.delete_old_radacct.delay(3)
        self.assertTrue(result.successful())
        self.assertEqual(RadiusAccounting.objects.filter(unique_id='666').count(), 0)

    @capture_stdout()
    def test_delete_unverified_users(self):
        path = self._get_path('static/test_batch.csv')
        options = dict(
            organization=self.default_org.slug,
            file=path,
            name='test',
        )
        management.call_command('batch_add_users', **options)
        User.objects.update(date_joined=now() - timedelta(days=3))
        for user in User.objects.all():
            RegisteredUser.objects.create(user=user, method='email', is_verified=False)
        self.assertEqual(User.objects.count(), 3)
        tasks.delete_unverified_users.delay(older_than_days=2)
        self.assertEqual(User.objects.count(), 0)

    @mock.patch('openwisp_radius.tasks.logger')
    @mock.patch('django.utils.translation.activate')
    @capture_stdout()
    def test_send_login_email(self, translation_activate, logger):
        accounting_data = _RADACCT.copy()
        total_mails = len(mail.outbox)
        with self.subTest('do not send email if username is invalid'):
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)
            logger.warning.assert_called_with(
                'user with {} does not exists'.format(accounting_data.get('username'))
            )

        logger.reset_mock()
        user = self._get_user()
        accounting_data['username'] = user.username
        organization = self._get_org()
        accounting_data['organization'] = organization.id

        with self.subTest('do not send mail if user is not a member of organization'):
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)
            logger.warning.assert_called_with(
                f'{user.username} is not the member of {organization.name}'
            )
            translation_activate.assert_not_called()

        logger.reset_mock()
        self._create_org_user()

        with self.subTest(
            'do not send mail if login_url does not exists for the organization'
        ):
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)
            logger.error.assert_called_with(
                f'login_url is not defined for {organization.name} organization'
            )
            translation_activate.assert_not_called()

        radius_settings = organization.radius_settings
        radius_settings.login_url = 'https://wifi.openwisp.org/default/login/'
        radius_settings.save(update_fields=['login_url'])

        with self.subTest(
            'it should send mail if login_url exists for the organization'
        ):
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails + 1)
            email = mail.outbox.pop()
            self.assertRegex(
                ''.join(email.alternatives[0][0].splitlines()),
                '<a href=".*?sesame=.*">.*Manage Session.*<\/a>',
            )
            self.assertIn(
                'A new session has been started for your account:' f' {user.username}',
                ' '.join(email.alternatives[0][0].split()),
            )
            self.assertIn(
                'You can review your session to find out how much time'
                ' and/or traffic has been used or you can terminate the session',
                ' '.join(email.alternatives[0][0].split()),
            )
            translation_activate.assert_called_with(user.language)

        translation_activate.reset_mock()

        with self.subTest('it should send mail in user language preference'):
            user.language = 'it'
            user.save(update_fields=['language'])
            tasks.send_login_email.delay(accounting_data)
            self.assertRegex(
                ''.join(email.alternatives[0][0].splitlines()),
                '<a href=".*?sesame=.*">.*Manage Session.*<\/a>',
            )
            self.assertEqual(translation_activate.call_args_list[0][0][0], 'it')
            self.assertEqual(
                translation_activate.call_args_list[1][0][0],
                getattr(settings, 'LANGUAGE_CODE'),
            )
