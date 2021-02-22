import json
from datetime import timedelta
from unittest import mock

import swapper
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils.timezone import localtime
from freezegun import freeze_time
from rest_framework.authtoken.models import Token

from openwisp_utils.tests import capture_any_output, capture_stderr

from ... import settings as app_settings
from ...utils import load_model
from .. import _TEST_DATE
from ..mixins import ApiTokenMixin, BaseTestCase

User = get_user_model()
PhoneToken = load_model('PhoneToken')
RadiusToken = load_model('RadiusToken')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')


class TestApiValidateToken(ApiTokenMixin, BaseTestCase):
    def _get_url(self):
        return reverse('radius:validate_auth_token', args=[self.default_org.slug])

    def _test_validate_auth_token_helper(self, user):
        url = self._get_url()
        token = Token.objects.create(user=user)
        # empty payload
        response = self.client.post(url)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['response_code'], 'BLANK_OR_INVALID_TOKEN')
        # invalid token
        payload = dict(token='some-random-string')
        response = self.client.post(url, payload)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['response_code'], 'BLANK_OR_INVALID_TOKEN')
        # valid token
        payload = dict(token=token.key)
        response = self.client.post(url, payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data['response_code'], 'AUTH_TOKEN_VALIDATION_SUCCESSFUL'
        )
        self.assertEqual(response.data['auth_token'], token.key)
        self.assertEqual(
            response.data['radius_user_token'], RadiusToken.objects.first().key,
        )
        user = token.user
        self.assertEqual(user, RadiusToken.objects.first().user)
        self.assertEqual(
            response.data['username'], user.username,
        )
        self.assertEqual(
            response.data['is_active'], user.is_active,
        )
        if user.is_active:
            phone_number = user.phone_number
        else:
            phone_number = PhoneToken.objects.filter(user=user).first().phone_number

        self.assertEqual(
            response.data['phone_number'], str(phone_number),
        )
        self.assertEqual(
            response.data['email'], user.email,
        )

    def test_validate_auth_token_with_active_user(self):
        user = self._get_user_with_org()
        self._test_validate_auth_token_helper(user)

    @capture_any_output()
    def test_validate_auth_token_with_inactive_user(self):
        user = self._get_user_with_org()
        user.is_active = False
        user.save()
        user.refresh_from_db()
        phone_token = PhoneToken(
            user=user, ip='127.0.0.1', phone_number='+237675578296'
        )
        phone_token.full_clean()
        phone_token.save()
        self._test_validate_auth_token_helper(user)

    @freeze_time(_TEST_DATE)
    def test_user_auth_updates_last_login(self):
        admin = self._get_admin()
        token = Token.objects.create(user=admin)
        payload = dict(token=token.key)
        self.assertEqual(admin.last_login, None)
        response = self.client.post(self._get_url(), payload)
        self.assertEqual(response.status_code, 200)
        admin.refresh_from_db()
        self.assertIsNotNone(admin.last_login)
        self.assertEqual(localtime(admin.last_login).isoformat(), _TEST_DATE)


class TestApiPhoneToken(ApiTokenMixin, BaseTestCase):

    _test_email = 'test@openwisp.org'

    def setUp(self):
        super().setUp()
        radius_settings = self.default_org.radius_settings
        radius_settings.sms_verification = True
        radius_settings.needs_identity_verification = True
        radius_settings.sms_sender = '+595972157632'
        radius_settings.sms_meta_data = {
            'clientId': 3,
            'clientSecret': 'p8pVUoqz7T4ArPEu1rcgzlsYJmnGCkkWHs2WAqqm',
        }
        radius_settings.full_clean()
        radius_settings.save()

    def test_register_phone_required(self):
        self.assertEqual(User.objects.count(), 0)
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        r = self.client.post(
            url,
            {
                'username': self._test_email,
                'email': self._test_email,
                'password1': 'password',
                'password2': 'password',
                'phone_number': '',
            },
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('phone_number', r.data)

    def test_register_201(self):
        # ensure session authentication does not interfere with the API
        # otherwise users being logged in the admin and testing the API
        # will get failures. Rather than telling them to log out from the admin
        # we'll handle this case and avoid the issue altogether
        self._superuser_login()
        self.assertEqual(User.objects.count(), 1)
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        phone_number = '+393664255801'
        r = self.client.post(
            url,
            {
                'username': self._test_email,
                'email': self._test_email,
                'password1': 'password',
                'password2': 'password',
                'phone_number': phone_number,
            },
        )
        self.assertEqual(r.status_code, 201)
        self.assertIn('key', r.data)
        self.assertEqual(User.objects.count(), 2)
        user = User.objects.get(email=self._test_email)
        self.assertTrue(user.is_member(self.default_org))
        self.assertEqual(user.phone_number, phone_number)
        self.assertFalse(user.is_active)

    def test_register_400_duplicate_phone_number(self):
        self.test_register_201()
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        r = self.client.post(
            url,
            {
                'username': 'test2@test.org',
                'email': 'test2@test.org',
                'password1': 'password',
                'password2': 'password',
                'phone_number': '+393664255801',
            },
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('phone_number', r.data)
        self.assertEqual(User.objects.count(), 2)

    def test_create_phone_token_401(self):
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 401)

    @mock.patch('openwisp_radius.utils.SmsMessage.send')
    def test_create_phone_token_201(self, send_messages_mock):
        self.test_register_201()
        token = Token.objects.last()
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(r.status_code, 201)
        phonetoken = PhoneToken.objects.first()
        self.assertIsNotNone(phonetoken)
        send_messages_mock.assert_called_once()

    @capture_any_output()
    def test_create_phone_token_400_not_member(self):
        self.test_register_201()
        OrganizationUser.objects.all().delete()
        token = Token.objects.last()
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(r.status_code, 400)
        self.assertIn('non_field_errors', r.data)
        self.assertIn('is not member', str(r.data['non_field_errors']))

    @capture_any_output()
    def test_create_phone_token_400_validation_error(self):
        user = self._get_user_with_org()
        user.is_active = False
        user.save()
        token = Token.objects.create(user=user)
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(r.status_code, 400)
        self.assertIn('phone_number', r.data)
        self.assertIn('This field cannot be null.', str(r.data['phone_number']))

    @capture_any_output()
    def test_create_phone_token_201_user_already_active(self):
        self.test_register_201()
        token = Token.objects.last()
        token.user.is_active = True
        token.user.save()
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(r.status_code, 201)

    @freeze_time(_TEST_DATE)
    @capture_any_output()
    def test_create_phone_token_400_limit_reached(self):
        self.test_register_201()
        token = Token.objects.last()
        token_header = f'Bearer {token.key}'
        max_value = app_settings.SMS_TOKEN_MAX_USER_DAILY
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        for n in range(1, max_value + 2):
            r = self.client.post(url, HTTP_AUTHORIZATION=token_header)
            if n > max_value:
                self.assertEqual(r.status_code, 400)
                self.assertIn('non_field_errors', r.data)
                self.assertIn('Maximum', str(r.data['non_field_errors']))
            else:
                self.assertEqual(r.status_code, 201)

    @capture_any_output()
    def test_validate_phone_token_200(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token = PhoneToken.objects.filter(user=user).last()
        # generate entropy to ensure correct token is used
        PhoneToken.objects.create(
            user=user, ip=phone_token.ip, phone_number=phone_token.phone_number,
        )
        phone_token = PhoneToken.objects.create(
            user=user, ip=phone_token.ip, phone_number=phone_token.phone_number
        )
        self.assertEqual(phone_token.attempts, 0)
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(
            url,
            json.dumps({'code': phone_token.token}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 200)
        phone_token.refresh_from_db()
        self.assertEqual(phone_token.attempts, 1)
        user.refresh_from_db()
        self.assertTrue(user.is_active)

    @capture_any_output()
    def test_validate_phone_token_400_not_member(self):
        self.test_create_phone_token_201()
        OrganizationUser.objects.all().delete()
        token = Token.objects.last()
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(r.status_code, 400)
        self.assertIn('non_field_errors', r.data)
        self.assertIn('is not member', str(r.data['non_field_errors']))

    def test_validate_phone_token_400_invalid(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token = PhoneToken.objects.filter(user=user).last()
        self.assertEqual(phone_token.attempts, 0)
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(
            url, {'code': '123456'}, HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        phone_token.refresh_from_db()
        self.assertEqual(phone_token.attempts, 1)
        self.assertIn('non_field_errors', r.data)
        self.assertIn('Invalid code', str(r.data['non_field_errors']))

    @capture_any_output()
    def test_validate_phone_token_400_expired(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token = PhoneToken.objects.filter(user=user).last()
        phone_token.valid_until -= timedelta(days=3)
        phone_token.save()
        self.assertEqual(phone_token.attempts, 0)
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(
            url,
            {'code': phone_token.token},
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        phone_token.refresh_from_db()
        self.assertEqual(phone_token.attempts, 1)
        self.assertIn('non_field_errors', r.data)
        self.assertIn(
            'This verification code has expired', str(r.data['non_field_errors'])
        )

    @capture_any_output()
    def test_validate_phone_token_400_max_attempts(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token = PhoneToken.objects.filter(user=user).last()
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        max_value = app_settings.SMS_TOKEN_MAX_ATTEMPTS + 1
        for n in range(1, max_value + 2):
            r = self.client.post(
                url, {'code': '123456'}, HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
            )
            self.assertEqual(r.status_code, 400)
            phone_token.refresh_from_db()
            self.assertEqual(phone_token.attempts, n)
            if n > max_value:
                self.assertIn('non_field_errors', r.data)
                self.assertIn(
                    'Maximum number of allowed attempts',
                    str(r.data['non_field_errors']),
                )
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    def test_validate_phone_token_401(self):
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(url)
        self.assertEqual(r.status_code, 401)

    @capture_any_output()
    def test_validate_phone_token_400_user_already_active(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user.is_active = True
        user.save()
        user_token = Token.objects.filter(user=user).last()
        phone_token = PhoneToken.objects.filter(user=user).last()
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(
            url,
            {'code': phone_token.token},
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('non_field_errors', r.data)
        self.assertIn('already active', str(r.data['non_field_errors']))

    def test_validate_phone_token_400_no_token(self):
        self.test_register_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        self.assertEqual(PhoneToken.objects.count(), 0)
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(
            url, {'code': '123456'}, HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('non_field_errors', r.data)
        self.assertIn(
            'No verification code found in the system', str(r.data['non_field_errors'])
        )

    def test_validate_phone_token_400_code_blank(self):
        self.test_register_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(
            url, {'code': ''}, HTTP_AUTHORIZATION=f'Bearer {user_token.key}'
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('code', r.data)

    def test_validate_phone_token_400_missing_code(self):
        self.test_register_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {user_token.key}')
        self.assertEqual(r.status_code, 400)
        self.assertIn('code', r.data)

    @capture_any_output()
    def test_change_phone_number_200(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token_qs = PhoneToken.objects.filter(user=user)
        self.assertEqual(phone_token_qs.count(), 1)
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        new_phone_number = '+595972157444'
        r = self.client.post(
            url,
            json.dumps({'phone_number': new_phone_number}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(phone_token_qs.count(), 2)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(user.phone_number, user.phone_number)

        code = phone_token_qs.first().token
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        r = self.client.post(
            url,
            json.dumps({'code': code}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(phone_token_qs.count(), 2)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertEqual(user.phone_number, new_phone_number)

    def test_change_phone_number_400_same_number(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token_qs = PhoneToken.objects.filter(user=user)
        self.assertEqual(phone_token_qs.count(), 1)
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        new_phone_number = '+393664255801'
        r = self.client.post(
            url,
            json.dumps({'phone_number': new_phone_number}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(phone_token_qs.count(), 1)
        self.assertIn('phone_number', r.data)
        self.assertIn('must be different', str(r.data['phone_number']))

    def test_change_phone_number_400_not_blank(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token_qs = PhoneToken.objects.filter(user=user)
        self.assertEqual(phone_token_qs.count(), 1)
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        r = self.client.post(
            url,
            json.dumps({'phone_number': ''}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(phone_token_qs.count(), 1)
        self.assertIn('phone_number', r.data)
        self.assertIn('not be blank', str(r.data['phone_number']))

    def test_change_phone_number_400_required(self):
        self.test_create_phone_token_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token_qs = PhoneToken.objects.filter(user=user)
        self.assertEqual(phone_token_qs.count(), 1)
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        r = self.client.post(
            url,
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(phone_token_qs.count(), 1)
        self.assertIn('phone_number', r.data)
        self.assertIn('required', str(r.data['phone_number']))

    def test_phone_number_restriction_in_signup(self):
        app_settings.ALLOWED_MOBILE_PREFIXES = ['+33']
        self.assertEqual(User.objects.all().count(), 0)
        user_param = {
            'username': 'test',
            'email': 'test@email.com',
            'password1': 'password',
            'password2': 'password',
        }
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        msg = 'This international mobile prefix is not allowed.'

        with self.subTest('test create user with number allowed at global level'):
            user_param.update({'phone_number': '+33675579231'})
            r = self.client.post(url, user_param)
            self.assertEqual(r.status_code, 201)
            self.assertEqual(User.objects.all().count(), 1)
            self.assertIn('key', r.data)

        with self.subTest('test create user with number not allowed at org level'):
            user_param.update(
                {
                    'email': 'test1@email.com',
                    'username': 'test1',
                    'phone_number': '+44 7795 106991',
                }
            )
            r = self.client.post(url, user_param)
            self.assertEqual(r.status_code, 400)
            self.assertIn(msg, str(r.data['phone_number']))
            self.assertEqual(User.objects.all().count(), 1)

        with self.subTest('test create user with number allowed at org level'):
            radius_settings = self.default_org.radius_settings
            radius_settings.allowed_mobile_prefixes = '+1,+44'
            radius_settings.full_clean()
            radius_settings.save()
            user_param.update(
                {
                    'email': 'test1@email.com',
                    'username': 'test1',
                    'phone_number': '+44 7795 106991',
                }
            )
            r = self.client.post(url, user_param)
            self.assertEqual(r.status_code, 201)
            self.assertEqual(User.objects.all().count(), 2)
            self.assertIn('key', r.data)

        with self.subTest('test create user with number not allowed'):
            user_param.update(
                {
                    'email': 'test2@email.com',
                    'username': 'test2',
                    'phone_number': '+237675752913',
                }
            )
            r = self.client.post(url, user_param)
            self.assertEqual(r.status_code, 400)
            self.assertIn(msg, str(r.data['phone_number']))
            self.assertEqual(User.objects.all().count(), 2)

        app_settings.ALLOWED_MOBILE_PREFIXES = []

    @capture_any_output()
    def test_change_phone_number_restriction(self):
        self.test_register_201()
        app_settings.ALLOWED_MOBILE_PREFIXES = ['+33']
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token_qs = PhoneToken.objects.filter(user=user)
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        msg = 'This international mobile prefix is not allowed.'

        self.assertEqual(phone_token_qs.count(), 0)

        with self.subTest('test change number not allowed at global level'):
            r = self.client.post(
                url,
                json.dumps({'phone_number': '+237675579231'}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
            )
            self.assertEqual(r.status_code, 400)
            self.assertIn(msg, str(r.data['phone_number']))
            self.assertEqual(phone_token_qs.count(), 0)

        with self.subTest('test change number allowed at global level'):
            phone_number = '+33675579245'
            r = self.client.post(
                url,
                json.dumps({'phone_number': phone_number}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(phone_token_qs.count(), 1)
            code = phone_token_qs.get(user=user, phone_number=phone_number).token
            r = self.client.post(
                reverse('radius:phone_token_validate', args=[self.default_org.slug]),
                json.dumps({'code': code}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
            )
            self.assertEqual(r.status_code, 200)
            user.refresh_from_db()
            self.assertEqual(user.phone_number, phone_number)

        with self.subTest('test change number not allowed at org level'):
            r = self.client.post(
                url,
                json.dumps({'phone_number': '+44 7795 106991'}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
            )
            self.assertEqual(r.status_code, 400)
            self.assertIn(msg, str(r.data['phone_number']))
            self.assertEqual(phone_token_qs.count(), 1)

        with self.subTest('test change number allowed at org level'):
            radius_settings = self.default_org.radius_settings
            radius_settings.allowed_mobile_prefixes = '+1,+44'
            radius_settings.full_clean()
            radius_settings.save()
            phone_number = '+44 7795 106991'
            r = self.client.post(
                url,
                json.dumps({'phone_number': phone_number}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(phone_token_qs.count(), 2)
            code = phone_token_qs.get(user=user, phone_number=phone_number).token
            r = self.client.post(
                reverse('radius:phone_token_validate', args=[self.default_org.slug]),
                json.dumps({'code': code}),
                content_type='application/json',
                HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
            )
            self.assertEqual(r.status_code, 200)
            user.refresh_from_db()
            self.assertEqual(user.phone_number, phone_number)

        app_settings.ALLOWED_MOBILE_PREFIXES = []

    def _test_change_phone_number_sms_on_helper(self, is_active):
        self.test_register_201()
        user = User.objects.get(email=self._test_email)
        user_token = Token.objects.filter(user=user).last()
        phone_token_qs = PhoneToken.objects.filter(user=user)
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        old_phone_number = '+237675582041'
        user.phone_number = old_phone_number
        user.is_active = is_active
        user.save()
        new_phone_number = '+237675582042'

        self.assertEqual(phone_token_qs.count(), 0)

        r = self.client.post(
            url,
            json.dumps({'phone_number': new_phone_number}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(phone_token_qs.count(), 1)
        self.assertEqual(phone_token_qs.first().phone_number, new_phone_number)
        user.refresh_from_db()
        self.assertEqual(user.phone_number, old_phone_number)
        self.assertFalse(user.is_active)

    @capture_any_output()
    def test_active_user_change_phone_number_sms_on(self):
        self._test_change_phone_number_sms_on_helper(True)

    @capture_any_output()
    def test_inactive_user_change_phone_number_sms_on(self):
        self._test_change_phone_number_sms_on_helper(False)

    def _create_user_helper(self, options):
        self._superuser_login()
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        r = self.client.post(url, options)
        self.assertEqual(r.status_code, 201)
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r1 = self.client.post(
            url,
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {r.data["key"]}',
        )
        self.assertEqual(r1.status_code, 201)

    def _test_phone_number_unique_helper(self, phone_number):
        user = User.objects.get(email='user2@gmail.com')
        user_token = Token.objects.filter(user=user).last()
        phone_token_qs = PhoneToken.objects.filter(user=user)
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        self.assertEqual(phone_token_qs.count(), 1)

        r = self.client.post(
            url,
            json.dumps({'phone_number': phone_number}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {user_token.key}',
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('phone_number', r.data)
        self.assertEqual(phone_token_qs.count(), 1)

    @capture_any_output()
    def test_phone_token_phone_number_unique(self):
        self._create_user_helper(
            {
                'username': 'user1',
                'email': 'user1@gmail.com',
                'password1': 'password',
                'password2': 'password',
                'phone_number': '+237678879231',
            }
        )
        self._create_user_helper(
            {
                'username': 'user2',
                'email': 'user2@gmail.com',
                'password1': 'password',
                'password2': 'password',
                'phone_number': '+237674479231',
            }
        )
        self._test_phone_number_unique_helper('+237678879231')

    @capture_any_output()
    def test_user_phone_number_unique(self):
        User.objects.create_user(
            username='user1',
            email='email1@gmail.com',
            password='pass',
            phone_number='+23767779235',
        )
        self._create_user_helper(
            {
                'username': 'user2',
                'email': 'user2@gmail.com',
                'password1': 'password',
                'password2': 'password',
                'phone_number': '+237674479231',
            }
        )
        user = User.objects.get(email='user2@gmail.com')
        user.is_active = True
        user.save()
        user.refresh_from_db()
        # Testing for Phone token validation error due to same phone number ,
        self._test_phone_number_unique_helper('+23767779235')
        # is_active state of user should not change because an error
        # occurred during phone token creation.
        self.assertTrue(user.is_active)


class TestIsSmsVerificationEnabled(ApiTokenMixin, BaseTestCase):

    _test_email = 'test@openwisp.org'

    def setUp(self):
        super().setUp()
        radius_settings = self.default_org.radius_settings
        radius_settings.sms_verification = False
        radius_settings.full_clean()
        radius_settings.save()

    def test_register_201_phone_number_empty(self):
        self._superuser_login()
        self.assertEqual(User.objects.count(), 1)
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        phone_number = '+393664255801'
        r = self.client.post(
            url,
            {
                'username': self._test_email,
                'email': self._test_email,
                'password1': 'password',
                'password2': 'password',
                'phone_number': phone_number,
            },
        )
        self.assertEqual(r.status_code, 201)
        self.assertIn('key', r.data)
        self.assertEqual(User.objects.count(), 2)
        user = User.objects.get(email=self._test_email)
        self.assertTrue(user.is_member(self.default_org))
        self.assertEqual(user.phone_number, None)
        self.assertTrue(user.is_active)

    @capture_stderr()
    def test_create_phone_token_403(self):
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIn('SMS verification is not enabled', str(r.data))

    @capture_stderr()
    def test_validate_phone_token_403(self):
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIn('SMS verification is not enabled', str(r.data))

    @capture_stderr()
    def test_change_phone_number_403(self):
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIn('SMS verification is not enabled', str(r.data))

    @capture_stderr()
    def test_missing_radius_settings(self):
        self.default_org.radius_settings.delete()
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 500)
        self.assertIn('Could not complete operation', str(r.data))
