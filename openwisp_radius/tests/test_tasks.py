from datetime import timedelta
from unittest import mock

from allauth.account.models import EmailAddress
from celery import Celery
from celery.contrib.testing.worker import start_worker
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail, management
from django.test.utils import override_settings
from django.utils.timezone import now

from openwisp_radius import tasks
from openwisp_utils.tests import capture_any_output, capture_stdout

from .. import settings as app_settings
from ..utils import load_model
from . import _RADACCT, FileMixin
from .mixins import BaseTestCase

User = get_user_model()
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
RadiusPostAuth = load_model('RadiusPostAuth')
RegisteredUser = load_model('RegisteredUser')


class TestTasks(FileMixin, BaseTestCase):
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
    def test_delete_old_radiusbatch_users(self):
        self._get_expired_user_from_radius_batch()
        self.assertEqual(User.objects.all().count(), 1)
        result = tasks.delete_old_radiusbatch_users.delay(1)
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
            user.registered_user.is_verified = False
            user.registered_user.method = 'email'
            user.registered_user.save(update_fields=['is_verified', 'method'])
        self.assertEqual(User.objects.count(), 3)
        tasks.delete_unverified_users.delay(older_than_days=2)
        self.assertEqual(User.objects.count(), 0)

    @mock.patch('openwisp_radius.tasks.logger')
    @mock.patch('openwisp_radius.utils.logger')
    @mock.patch('django.utils.translation.activate')
    def test_send_login_email(self, translation_activate, utils_logger, task_logger):
        accounting_data = _RADACCT.copy()
        organization = self._get_org()
        accounting_data['organization'] = organization.id
        total_mails = len(mail.outbox)
        radius_settings = organization.radius_settings

        with self.subTest('do not send email if username is invalid'):
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)
            username = accounting_data.get('username')
            task_logger.warning.assert_called_with(
                f'user with username "{username}" does not exists'
            )

        user = self._get_user()
        accounting_data['username'] = user.username

        with self.subTest(
            'do not send mail if login_url does not exists for the organization'
        ):
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)
            utils_logger.debug.assert_called_with(
                f'login_url is not defined for {organization.name} organization'
            )
            translation_activate.assert_not_called()

        radius_settings = organization.radius_settings
        radius_settings.login_url = 'https://wifi.openwisp.org/default/login/'
        radius_settings.save(update_fields=['login_url'])
        total_mails = len(mail.outbox)

        with self.subTest('do not send mail if user is not a member of organization'):
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)
            utils_logger.warning.assert_called_with(
                f'user with username "{user.username}" is '
                f'not member of "{organization.name}"'
            )
            translation_activate.assert_not_called()

        self._create_org_user()

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
            self.assertNotIn(
                'Note: this link is valid only for an hour from now',
                ' '.join(email.alternatives[0][0].split()),
            )
            translation_activate.assert_called_with(user.language)

        translation_activate.reset_mock()

        with override_settings(SESAME_MAX_AGE=2 * 60 * 60):
            with self.subTest(
                'it should check expiration text is present when SESAME_MAX_AGE is set'
            ):
                tasks.send_login_email.delay(accounting_data)
                self.assertEqual(len(mail.outbox), total_mails + 1)
                email = mail.outbox.pop()
                self.assertIn(
                    'Note: this link is valid only for an hour from now',
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

        translation_activate.reset_mock()
        total_mails = len(mail.outbox)

        with self.subTest('user has multiple verified email addresses'):
            EmailAddress.objects.create(
                user=user, email='tester-change@example.com', verified=True
            )
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails + 1)

        translation_activate.reset_mock()
        total_mails = len(mail.outbox)

        with self.subTest('do not send email to unverified email address'):
            user.emailaddress_set.update(verified=False)
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)

        user.emailaddress_set.update(verified=True)

        with self.subTest('do not fail if radius_settings missing'):
            organization.radius_settings.delete()
            tasks.send_login_email.delay(accounting_data)
            self.assertEqual(len(mail.outbox), total_mails)
            utils_logger.warning.assert_called_with(
                f'Organization "{organization.name}" does not '
                'have any OpenWISP RADIUS settings configured'
            )
            translation_activate.assert_not_called()

    @mock.patch.object(app_settings, 'UNVERIFY_INACTIVE_USERS', 30)
    def test_unverify_inactive_users(self, *args):
        """
        Checks that inactive users are unverified after the days
        configured in OPENWISP_RADIUS_UNVERIFY_INACTIVE_USERS setting,
        here 30 days.

        Only non-staff users that do not have unspecified(''), manual
        and email registration methods are considered.
        """
        today = now()
        admin = self._create_admin(last_login=today - timedelta(days=90))
        active_user = self._create_org_user().user
        unspecified_user = self._create_org_user(
            user=self._create_user(
                username='unspecified_user', email='unspecified_user@example.com'
            )
        ).user
        manually_registered_user = self._create_org_user(
            user=self._create_user(
                username='manually_registered_user',
                email='manually_registered_user@example.com',
            )
        ).user
        email_registered_user = self._create_org_user(
            user=self._create_user(
                username='email_registered_user',
                email='email_registered_user@example.com',
            )
        ).user
        mobile_registered_user = self._create_org_user(
            user=self._create_user(
                username='mobile_registered_user',
                email='mobile_registered_user@example.com',
            )
        ).user

        User.objects.filter(id=active_user.id).update(last_login=today)
        User.objects.exclude(id=active_user.id).update(
            last_login=today - timedelta(days=60)
        )
        RegisteredUser.objects.create(user=admin, is_verified=True)
        RegisteredUser.objects.create(user=active_user, is_verified=True)
        RegisteredUser.objects.create(
            user=unspecified_user, method='', is_verified=True
        )
        RegisteredUser.objects.create(
            user=manually_registered_user, method='manual', is_verified=True
        )
        RegisteredUser.objects.create(
            user=email_registered_user, method='email', is_verified=True
        )
        RegisteredUser.objects.create(
            user=mobile_registered_user, method='mobile_phone', is_verified=True
        )

        tasks.unverify_inactive_users.delay()
        admin.refresh_from_db()
        active_user.refresh_from_db()
        unspecified_user.refresh_from_db()
        manually_registered_user.refresh_from_db()
        email_registered_user.refresh_from_db()
        mobile_registered_user.refresh_from_db()
        self.assertEqual(admin.registered_user.is_verified, True)
        self.assertEqual(active_user.registered_user.is_verified, True)
        self.assertEqual(unspecified_user.registered_user.is_verified, True)
        self.assertEqual(manually_registered_user.registered_user.is_verified, True)
        self.assertEqual(email_registered_user.registered_user.is_verified, True)
        self.assertEqual(mobile_registered_user.registered_user.is_verified, False)

    @mock.patch.object(app_settings, 'DELETE_INACTIVE_USERS', 30)
    def test_delete_inactive_users(self, *args):
        today = now()
        inactive_date = today - timedelta(days=60)
        admin = self._create_admin(last_login=inactive_date)
        user1 = self._create_org_user().user
        user2 = self._create_org_user(
            user=self._create_user(username='user2', email='user2@example.com')
        ).user
        user3 = self._create_org_user(
            user=self._create_user(username='user3', email='user3@example.com')
        ).user
        User.objects.filter(id=user1.id).update(last_login=today)
        User.objects.filter(id=user2.id).update(last_login=inactive_date)
        User.objects.filter(id=user3.id).update(
            last_login=None, date_joined=inactive_date
        )

        tasks.delete_inactive_users.delay()
        self.assertEqual(User.objects.filter(id__in=[admin.id, user1.id]).count(), 2)
        self.assertEqual(User.objects.filter(id__in=[user2.id, user3.id]).count(), 0)
