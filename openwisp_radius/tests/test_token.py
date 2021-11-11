from datetime import datetime, timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from openwisp_utils.tests import capture_any_output, capture_stdout

from .. import exceptions
from .. import settings as app_settings
from ..utils import load_model
from . import _TEST_DATE
from .mixins import BaseTestCase

User = get_user_model()
PhoneToken = load_model('PhoneToken')
RadiusToken = load_model('RadiusToken')
RegisteredUser = load_model('RegisteredUser')


class TestRadiusToken(BaseTestCase):
    def test_string_representation(self):
        radiustoken = RadiusToken(key='test key')
        self.assertEqual(str(radiustoken), radiustoken.key)

    def test_create_radius_token_model(self):
        u = User.objects.create(username='test', email='test@test.org', password='test')
        obj = RadiusToken.objects.create(user=u, organization=self._get_org())
        self.assertEqual(str(obj), obj.key)
        self.assertEqual(obj.user, u)


class TestPhoneToken(BaseTestCase):
    def setUp(self):
        super().setUp()
        radius_settings = self.default_org.radius_settings
        radius_settings.sms_verification = True
        radius_settings.sms_sender = '+595972157632'
        radius_settings.save()

    def _create_token(
        self, user=None, ip='127.0.0.1', phone_number='+393664351808', created=None
    ):
        if not user:
            opts = {
                'username': 'tester',
                'email': 'tester@tester.com',
                'password': 'tester',
                'phone_number': '+393664351805',
                'is_active': False,
            }
            user = self._create_user(**opts)
            self._create_org_user(**{'user': user})
        token = PhoneToken(user=user, ip=ip, phone_number=phone_number)
        if created:
            token.created = created
            token.modified = created
        token.full_clean()
        token.save()
        return token

    @capture_any_output()
    def test_is_already_verified(self):
        token = self._create_token()
        RegisteredUser.objects.create(
            user=token.user, method='mobile_phone', is_verified=True
        )
        token.refresh_from_db()

        with self.subTest('existing token, running validation again should not fail'):
            self.assertEqual(token.full_clean(), None)

        with self.subTest('new token with verified user, validation should not fail'):
            self._create_token(user=token.user)
            qs = PhoneToken.objects.all()
            self.assertEqual(qs.count(), 2)

    def test_valid_until(self):
        token = PhoneToken()
        expected = timezone.now() + timedelta(
            minutes=app_settings.SMS_TOKEN_DEFAULT_VALIDITY
        )
        self.assertIsInstance(token.valid_until, datetime)
        self.assertEqual(
            token.valid_until.replace(microsecond=0), expected.replace(microsecond=0)
        )

    def test_token(self):
        token = PhoneToken()
        self.assertIsNotNone(token.token)
        self.assertEqual(len(token.token), app_settings.SMS_TOKEN_LENGTH)
        self.assertIsInstance(token.token, str)
        self.assertIsInstance(int(token.token), int)

    @capture_stdout()
    def test_is_valid(self):
        token = self._create_token()
        self.assertTrue(token.is_valid(token.token))
        self.assertEqual(token.attempts, 1)
        self.assertTrue(token.verified)

    @capture_any_output()
    def test_max_attempts(self):
        token = self._create_token()
        self.assertEqual(token.attempts, 0)
        self.assertFalse(token.is_valid('000000'))
        self.assertEqual(token.attempts, 1)
        self.assertFalse(token.verified)
        self.assertFalse(token.is_valid('000000'))
        self.assertEqual(token.attempts, 2)
        self.assertFalse(token.verified)
        self.assertFalse(token.is_valid('000000'))
        self.assertEqual(token.attempts, 3)
        self.assertFalse(token.verified)
        try:
            token.is_valid('000000')
        except exceptions.MaxAttemptsException:
            self.assertEqual(token.attempts, 4)
            self.assertFalse(token.verified)
        else:
            self.fail('Exception not raised')

    @freeze_time(_TEST_DATE)
    @capture_any_output()
    def test_expired(self):
        token = self._create_token()
        token.valid_until = timezone.now() - timedelta(days=1)
        token.save()
        try:
            token.is_valid(token.token)
        except exceptions.ExpiredTokenException:
            self.assertEqual(token.attempts, 1)
            self.assertFalse(token.verified)
        else:
            self.fail('Exception not raised')

    def _create_tokens_limit_test(self):
        token = self._create_token()
        # old tokens, should not influence the query
        self._create_token(user=token.user, created=token.created - timedelta(days=1))
        self._create_token(user=token.user, created=token.created - timedelta(days=7))
        # tokens of today, should be filtered by the query
        self._create_token(user=token.user, created=token.created - timedelta(hours=2))
        self._create_token(
            user=token.user, created=token.created - timedelta(minutes=5)
        )
        return token.user

    def _test_user_limit(self):
        user = self._create_tokens_limit_test()
        try:
            self._create_token(user=user)
        except ValidationError as e:
            self.assertIn('Maximum daily', str(e.message_dict))
        else:
            self.fail('ValidationError not raised')

    @freeze_time(_TEST_DATE)
    @capture_any_output()
    def test_user_limit_timezone_causes_change_of_date(self):
        self._test_user_limit()

    @freeze_time('2019-04-20T15:05:13-04:00')
    @capture_any_output()
    def test_user_limit(self):
        self._test_user_limit()

    @freeze_time(_TEST_DATE)
    @capture_any_output()
    def test_ip_limit(self):
        self._create_tokens_limit_test()
        opts = {
            'username': 'user2',
            'email': 'test2@test.com',
            'password': 'tester',
            'phone_number': '+393664351806',
            'is_active': False,
        }
        user2 = self._create_user(**opts)
        self._create_org_user(**{'user': user2})
        self._create_token(user=user2, phone_number='+393664351801')
        try:
            self._create_token(user=user2, phone_number='+393664351802')
        except ValidationError as e:
            self.assertIn('IP address', str(e.message_dict))
        else:
            self.fail('ValidationError not raised')

    @capture_any_output()
    def test_user_without_phone(self):
        user = self._create_user(
            **{'username': 'tester', 'password': 'tester', 'is_active': False}
        )
        try:
            self._create_token(user=user, phone_number=None)
        except ValidationError as e:
            self.assertIn(
                'This field cannot be null.',
                str(e.message_dict['phone_number']),
            )
        else:
            self.fail('ValidationError not raised')

    @mock.patch('openwisp_radius.utils.SmsMessage.send')
    def test_send_token_called_once(self, send_messages_mock):
        token = self._create_token()
        token.valid_until += timedelta(hours=1)  # change anything to save
        token.save()
        send_messages_mock.assert_called_once()
