from datetime import datetime, timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from .. import exceptions
from .. import settings as app_settings
from ..utils import load_model
from . import _TEST_DATE
from .mixins import BaseTestCase

User = get_user_model()
PhoneToken = load_model('PhoneToken')
RadiusToken = load_model('RadiusToken')


class TestRadiusToken(BaseTestCase):
    def test_string_representation(self):
        radiustoken = RadiusToken(key='test key')
        self.assertEqual(str(radiustoken), radiustoken.key)

    def test_create_radius_token_model(self):
        u = User.objects.create(username='test', email='test@test.org', password='test')
        obj = RadiusToken.objects.create(user=u)
        self.assertEqual(str(obj), obj.key)
        self.assertEqual(obj.user, u)


class TestPhoneToken(BaseTestCase):
    def setUp(self):
        super().setUp()
        radius_settings = self.default_org.radius_settings
        radius_settings.sms_verification = True
        radius_settings.sms_sender = '+595972157632'
        radius_settings.save()

    def _create_token(self, user=None, ip='127.0.0.1', created=None):
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
        token = PhoneToken(user=user, ip=ip)
        if created:
            token.created = created
            token.modified = created
        token.full_clean()
        token.save()
        return token

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

    def test_is_valid(self):
        token = self._create_token()
        self.assertTrue(token.is_valid(token.token))
        self.assertEqual(token.attempts, 1)
        self.assertTrue(token.verified)

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
    def test_user_limit_timezone_causes_change_of_date(self):
        self._test_user_limit()

    @freeze_time('2019-04-20T15:05:13-04:00')
    def test_user_limit(self):
        self._test_user_limit()

    @freeze_time(_TEST_DATE)
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
        self._create_token(user=user2)
        try:
            self._create_token(user=user2)
        except ValidationError as e:
            self.assertIn('ip address', str(e.message_dict))
        else:
            self.fail('ValidationError not raised')

    def test_user_without_phone(self):
        user = self._create_user(
            **{'username': 'tester', 'password': 'tester', 'is_active': False}
        )
        try:
            self._create_token(user=user)
        except ValidationError as e:
            self.assertIn('does not have a phone number', str(e.message_dict))
        else:
            self.fail('ValidationError not raised')

    @mock.patch('openwisp_radius.utils.SmsMessage.send')
    def test_send_token_called_once(self, send_messages_mock):
        token = self._create_token()
        token.valid_until += timedelta(hours=1)  # change anything to save
        token.save()
        send_messages_mock.assert_called_once()
