import json
import os
import sys
from unittest import mock

import swapper
from allauth.account.forms import default_token_generator
from allauth.account.utils import user_pk_to_url_str
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core import mail
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from openwisp_radius.api.serializers import RadiusUserSerializer
from openwisp_utils.tests import capture_any_output, capture_stderr

from ... import settings as app_settings
from ...utils import load_model
from ..mixins import ApiTokenMixin, BaseTestCase
from .test_freeradius_api import AcctMixin

User = get_user_model()
RadiusToken = load_model('RadiusToken')
RadiusBatch = load_model('RadiusBatch')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
Organization = swapper.load_model('openwisp_users', 'Organization')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')

START_DATE = '2019-04-20T22:14:09+01:00'


class TestApi(AcctMixin, ApiTokenMixin, BaseTestCase):
    def setUp(self):
        cache.clear()
        super().setUp()

    def _radius_batch_post_request(self, data, username='admin', password='tester'):
        if username == 'admin':
            self._get_admin()
        login_payload = {'username': username, 'password': password}
        login_url = reverse('radius:user_auth_token', args=[self.default_org.slug])
        login_response = self.client.post(login_url, data=login_payload)
        header = f'Bearer {login_response.json()["key"]}'
        url = reverse('radius:batch')
        return self.client.post(url, data, HTTP_AUTHORIZATION=header)

    def test_batch_bad_request_400(self):
        self.assertEqual(RadiusBatch.objects.count(), 0)
        data = self._radius_batch_prefix_data(number_of_users=-1)
        response = self._radius_batch_post_request(data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(RadiusBatch.objects.count(), 0)

    def test_batch_csv_201(self):
        self.assertEqual(RadiusBatch.objects.count(), 0)
        self.assertEqual(User.objects.count(), 0)
        text = 'user,cleartext$abcd,email@gmail.com,firstname,lastname'
        path_csv = f'{settings.MEDIA_ROOT}/test_csv1.csv'
        with open(path_csv, 'wb') as file:
            text2 = text.encode('utf-8')
            file.write(text2)
        with open(path_csv, 'rb') as file:
            data = self._radius_batch_csv_data(csvfile=file)
            response = self._radius_batch_post_request(data)
        os.remove(path_csv)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(RadiusBatch.objects.count(), 1)
        self.assertEqual(User.objects.count(), 2)

    def test_batch_prefix_201(self):
        self.assertEqual(RadiusBatch.objects.count(), 0)
        self.assertEqual(User.objects.count(), 0)
        response = self._radius_batch_post_request(self._radius_batch_prefix_data())
        self.assertEqual(response.status_code, 201)
        self.assertEqual(RadiusBatch.objects.count(), 1)
        self.assertEqual(User.objects.count(), 4)

    def test_radius_batch_permissions(self):
        self._get_admin()
        self._create_org_user(user=self._get_operator())
        self._create_org_user(user=self._get_user())
        self.assertEqual(User.objects.count(), 3)
        data = self._radius_batch_prefix_data()
        add_radbatch_perm = Permission.objects.get(codename='add_radiusbatch')
        with self.subTest('Test w/o login'):
            response = self.client.post(reverse('radius:batch'), data)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(User.objects.count(), 3)
        with self.subTest('Test as superuser'):
            response = self._radius_batch_post_request(data)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(User.objects.count(), 6)
        with self.subTest('Test as operator w/o permission'):
            data.update(name='test2')
            operator = self._get_operator()
            response = self._radius_batch_post_request(data, operator.username)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(User.objects.count(), 6)
        with self.subTest('Test as operator w/ permission'):
            data.update(name='test3')
            operator.user_permissions.add(add_radbatch_perm)
            response = self._radius_batch_post_request(data, operator.username)
            self.assertEqual(response.status_code, 201)
            self.assertEqual(User.objects.count(), 9)
        with self.subTest('Test as user w/o permission'):
            data.update(name='test4')
            user = self._get_user()
            response = self._radius_batch_post_request(data, user.username)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(User.objects.count(), 9)
        with self.subTest('Test as user w/ permission'):
            data.update(name='test5')
            user.user_permissions.add(add_radbatch_perm)
            response = self._radius_batch_post_request(data, user.username)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(User.objects.count(), 9)

    def test_api_batch_user_creation_no_users(self):
        data = self._radius_batch_prefix_data(
            **{'csvfile': '', 'number_of_users': '', 'modified': ''}
        )
        response = self._radius_batch_post_request(data)
        self.assertEqual(response.status_code, 400)
        self.assertIn(b'The field number_of_users cannot be empty', response.content)

    def test_register_201(self):
        # ensure session authentication does not interfere with the API
        # otherwise users being logged in the admin and testing the API
        # will get failures. Rather than telling them to log out from the admin
        # we'll handle this case and avoid the issue altogether
        r = self._register_user()
        self.assertEqual(r.status_code, 201)  # redundant but left for clarity
        self.assertIn('key', r.data)
        self.assertIn('radius_user_token', r.data)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(RadiusToken.objects.count(), 1)
        radius_token = RadiusToken.objects.get()
        self.assertEqual(r.data['radius_user_token'], radius_token.key)
        user = User.objects.get(email=self._test_email)
        self.assertTrue(user.is_member(self.default_org))
        self.assertTrue(user.is_active)
        self.assertFalse(user.registered_user.is_verified)

    def test_register_400_password(self):
        response = self._register_user(
            extra_params={'password1': 'password1', 'password2': 'password2'},
            expect_201=False,
        )
        self.assertEqual(response.status_code, 400)
        expected_response = {
            'non_field_errors': ["The two password fields didn't match."]
        }
        self.assertEqual(response.json(), expected_response)

    def test_register_400_duplicate_user(self):
        self.test_register_201()
        r = self._register_user(expect_201=False, expect_users=None)
        self.assertEqual(r.status_code, 400)
        self.assertIn('username', r.data)
        self.assertIn('email', r.data)

    def test_register_duplicate_same_org(self):
        self.test_register_201()
        response = self._register_user(expect_201=False, expect_users=None)
        self.assertIn('username', response.data)
        self.assertIn('email', response.data)

    @mock.patch('openwisp_radius.settings.ALLOWED_MOBILE_PREFIXES', ['+33'])
    def test_register_duplicate_different_org(self):
        self.default_org.radius_settings.sms_verification = True
        self.default_org.radius_settings.save()

        init_user_count = User.objects.count()
        org_user_count = OrganizationUser.objects.count()
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        params = {
            'username': self._test_email,
            'email': self._test_email,
            'phone_number': '+33675579231',
            'password1': 'password',
            'password2': 'password',
        }
        response = self.client.post(url, data=params)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(User.objects.count(), init_user_count + 1)
        self.assertEqual(OrganizationUser.objects.count(), org_user_count + 1)

        org2 = self._get_org(org_name='org2')
        url = reverse('radius:rest_register', args=[org2.slug])
        radius_settings = org2.radius_settings
        radius_settings.sms_verification = True
        radius_settings.save()

        with self.subTest('Test existing email'):
            options = params.copy()
            options['phone_number'] = '+33675579231'
            options['username'] = 'test2'

            response = self.client.post(url, data=options)
            self.assertEqual(response.status_code, 409)
            expected_response_data = {
                'details': 'A user like the one being registered already exists.',
                'organizations': [
                    {'slug': self.default_org.slug, 'name': self.default_org.name}
                ],
            }
            self.assertDictEqual(response.data, expected_response_data)
            self.assertEqual(User.objects.count(), init_user_count + 1)
            self.assertEqual(OrganizationUser.objects.count(), org_user_count + 1)

        with self.subTest('Test existing username'):
            options = params.copy()
            options['phone_number'] = '+339876543211'
            options['email'] = 'test2@example.com'

            response = self.client.post(url, data=options)
            self.assertEqual(response.status_code, 409)
            expected_response_data = {
                'details': 'A user like the one being registered already exists.',
                'organizations': [
                    {'slug': self.default_org.slug, 'name': self.default_org.name}
                ],
            }
            self.assertDictEqual(response.data, expected_response_data)
            self.assertEqual(User.objects.count(), init_user_count + 1)
            self.assertEqual(OrganizationUser.objects.count(), org_user_count + 1)

        with self.subTest('Test existing phone_number'):
            options = params.copy()
            options['username'] = options['phone_number']
            options.pop('email')

            response = self.client.post(url, data=options)
            self.assertEqual(response.status_code, 409)
            expected_response_data = {
                'details': 'A user like the one being registered already exists.',
                'organizations': [
                    {'slug': self.default_org.slug, 'name': self.default_org.name}
                ],
            }
            self.assertDictEqual(response.data, expected_response_data)
            self.assertEqual(User.objects.count(), init_user_count + 1)
            self.assertEqual(OrganizationUser.objects.count(), org_user_count + 1)

        self.default_org.radius_settings.sms_verification = False
        self.default_org.radius_settings.save()

    def test_radius_user_serializer(self):
        self._register_user()
        try:
            user = User.objects.select_related('radius_token', 'registered_user').get(
                email=self._test_email
            )
            admin = User.objects.select_related('radius_token', 'registered_user').get(
                username='admin'
            )
        except User.DoesNotExist as e:
            self.fail(f'user not found: {e}')

        with self.assertNumQueries(0):
            data = RadiusUserSerializer(user).data

        with self.subTest('test full data'):
            self.assertEqual(
                data,
                {
                    'username': user.username,
                    'email': user.email,
                    'phone_number': user.phone_number,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'birth_date': user.birth_date,
                    'location': user.location,
                    'is_active': user.is_active,
                    'is_verified': user.registered_user.is_verified,
                    'method': user.registered_user.method,
                    'radius_user_token': user.radius_token.key,
                },
            )

        with self.subTest('test partial data'):
            data = RadiusUserSerializer(admin).data
            self.assertEqual(
                data,
                {
                    'username': admin.username,
                    'email': admin.email,
                    'phone_number': admin.phone_number,
                    'first_name': admin.first_name,
                    'last_name': admin.last_name,
                    'birth_date': '1987-03-23',
                    'location': '',
                    'is_active': admin.is_active,
                    'is_verified': None,
                    'method': None,
                    'radius_user_token': None,
                },
            )

    @mock.patch.object(
        app_settings,
        'OPTIONAL_REGISTRATION_FIELDS',
        {
            'first_name': 'disabled',
            'last_name': 'allowed',
            'birth_date': 'disabled',
            'location': 'mandatory',
        },
    )
    def test_optional_fields_registration(self):
        self._superuser_login()
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        params = {
            'username': self._test_email,
            'email': self._test_email,
            'password1': 'password',
            'password2': 'password',
            'first_name': 'first name',
            'location': 'test location',
            'last_name': 'last name',
            'birth_date': '1998-08-19',
        }
        r = self.client.post(url, params)
        self.assertEqual(r.status_code, 201)
        self.assertIn('key', r.data)
        user = User.objects.get(email=self._test_email)
        self.assertEqual(user.first_name, '')
        self.assertEqual(user.last_name, 'last name')
        self.assertEqual(user.location, 'test location')
        self.assertIsNone(user.birth_date)

        with self.subTest('test org level setting'):
            self.default_org.radius_settings.birth_date = 'mandatory'
            self.default_org.radius_settings.full_clean()
            self.default_org.radius_settings.save()
            params['username'] = 'test'
            params['email'] = 'test@gmail.com'
            params['location'] = ''
            r = self.client.post(url, params)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(len(r.data.keys()), 1)
            self.assertIn('location', r.data)
            self.assertEqual(r.data['location'], 'This field is required.')
            user_count = User.objects.filter(email='test@gmail.com').count()
            self.assertEqual(user_count, 0)

    @capture_any_output()
    def test_register_error_missing_radius_settings(self):
        self.assertEqual(User.objects.count(), 0)
        self.default_org.radius_settings.delete()
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        r = self.client.post(
            url,
            {
                'username': self._test_email,
                'email': self._test_email,
                'password1': 'password',
                'password2': 'password',
            },
        )
        self.assertEqual(r.status_code, 500)
        self.assertIn('Could not complete operation', r.data['detail'])

    def test_register_404(self):
        url = reverse(
            'radius:rest_register', args=['00000000-0000-0000-0000-000000000000']
        )
        r = self.client.post(
            url,
            {
                'username': self._test_email,
                'email': self._test_email,
                'password1': 'password',
                'password2': 'password',
            },
        )
        self.assertEqual(r.status_code, 404)

    def test_register_verification_field(self):
        self._superuser_login()
        self.default_org.radius_settings.needs_identity_verification = True
        self.default_org.radius_settings.full_clean()
        self.default_org.radius_settings.save()
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        params = {
            'username': self._test_email,
            'email': self._test_email,
            'password1': 'password',
            'password2': 'password',
        }
        # Ensure no user is created and error is raised
        users_count = User.objects.count()
        r = self.client.post(url, params)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data['method'], 'This field is required.')
        self.assertEqual(User.objects.count(), users_count)

        with self.subTest('method `mobile` when verification optional'):
            self.default_org.radius_settings.needs_identity_verification = False
            self.default_org.radius_settings.save()
            params['username'] = 'test2'
            params['email'] = 'test2@gmail.com'
            params['method'] = 'mobile_phone'
            r = self.client.post(url, params)
            self.assertEqual(r.status_code, 201)
            self.assertEqual(User.objects.count(), 2)

    @override_settings(
        ACCOUNT_EMAIL_VERIFICATION='mandatory', ACCOUNT_EMAIL_REQUIRED=True
    )
    def test_email_verification_sent(self):
        self.assertEqual(User.objects.count(), 0)
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        r = self.client.post(
            url,
            {
                'username': self._test_email,
                'email': self._test_email,
                'password1': 'password',
                'password2': 'password',
            },
        )
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.data['detail'], 'Verification e-mail sent.')

    if (sys.version_info.major, sys.version_info.minor) > (3, 6):

        @override_settings(REST_USE_JWT=True)
        def test_registration_with_jwt(self):
            user_count = User.objects.all().count()
            url = reverse('radius:rest_register', args=[self.default_org.slug])
            r = self.client.post(
                url,
                {
                    'username': self._test_email,
                    'email': self._test_email,
                    'password1': 'password',
                    'password2': 'password',
                },
            )
            self.assertEqual(r.status_code, 201)
            self.assertIn('access_token', r.data)
            self.assertIn('refresh_token', r.data)
            self.assertEqual(User.objects.all().count(), user_count + 1)

    def test_api_batch_add_users(self):
        response = self._radius_batch_post_request(self._radius_batch_prefix_data())
        users = response.json()['users']
        for user in users:
            test_user = User.objects.get(pk=user['id'])
            with self.subTest(test_user=test_user):
                self.assertTrue(test_user.is_member(self.default_org))

    def test_api_batch_pdf_link(self):
        response = self._radius_batch_post_request(self._radius_batch_prefix_data())
        pdf_link = response.json()['pdf_link']
        with self.subTest('No Login'):
            pdf_response = self.client.get(pdf_link)
            self.assertEqual(pdf_response.status_code, 401)
        with self.subTest('Login: normal user'):
            self.client.force_login(self._get_user())
            pdf_response = self.client.get(pdf_link)
            self.assertEqual(pdf_response.status_code, 403)
        with self.subTest('Login: operator without permission'):
            operator = self._get_operator()
            self.client.force_login(operator)
            pdf_response = self.client.get(pdf_link)
            self.assertEqual(pdf_response.status_code, 403)
        with self.subTest('Login: operator without organization'):
            view_radbatch_perm = Permission.objects.get(codename='view_radiusbatch')
            operator.user_permissions.add(view_radbatch_perm)
            pdf_response = self.client.get(pdf_link)
            self.assertEqual(pdf_response.status_code, 403)
        with self.subTest('Login: operator not is_admin rejected'):
            user = self._create_org_user(organization=self.default_org, user=operator)
            pdf_response = self.client.get(pdf_link)
            self.assertEqual(pdf_response.status_code, 403)
        with self.subTest('Login: operator allowed'):
            user.delete()
            self._create_org_user(
                **{'organization': self.default_org, 'user': operator, 'is_admin': True}
            )
            pdf_response = self.client.get(pdf_link)
            self.assertEqual(pdf_response.status_code, 200)
        with self.subTest('Login: superuser allowed'):
            self.client.force_login(self._get_admin())
            pdf_response = self.client.get(pdf_link)
            self.assertEqual(pdf_response.status_code, 200)

    def test_batch_csv_pdf_link_404(self):
        self.assertEqual(RadiusBatch.objects.count(), 0)
        self.assertEqual(User.objects.count(), 0)
        path_csv = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'static', 'test_batch.csv'
        )
        with open(path_csv, 'rt') as file:
            data = self._radius_batch_csv_data(csvfile=file)
            response = self._radius_batch_post_request(data)
        self.assertEqual(response.status_code, 201)
        response_json = json.loads(response.content)
        org = Organization.objects.get(pk=response_json['organization'])
        pdf_url = reverse(
            'radius:download_rad_batch_pdf',
            args=[org.slug, response_json['id']],
        )
        self._superuser_login()
        self.assertEqual(response_json['pdf_link'], None)
        pdf_response = self.client.get(pdf_url)
        self.assertEqual(pdf_response.status_code, 404)

    def test_download_non_existing_radbatch_404(self):
        url = reverse(
            'radius:download_rad_batch_pdf',
            args=[self.default_org.slug, '00000000-0000-0000-0000-000000000000'],
        )
        self._superuser_login()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_download_non_existing_organization_404(self):
        radbatch = self._create_radius_batch(
            name='test', strategy='prefix', prefix='test-prefix5'
        )
        url = reverse(
            'radius:download_rad_batch_pdf',
            args=['non-existent-org', radbatch.pk],
        )
        self._superuser_login()
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_download_different_organization_radiusbatch_403(self):
        org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        radbatch = self._create_radius_batch(
            name='test', strategy='prefix', prefix='test-prefix5', organization=org2
        )
        url = reverse(
            'radius:download_rad_batch_pdf',
            args=[self.default_org.slug, radbatch.pk],
        )
        operator = self._get_operator()
        self._create_org_user(user=operator)
        self.client.force_login(self._get_operator())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    @capture_any_output()
    def test_api_password_change(self):
        test_user = User.objects.create_user(
            username='test_name',
            password='test_password',
        )
        self._create_org_user(organization=self.default_org, user=test_user)
        login_payload = {'username': 'test_name', 'password': 'test_password'}
        login_url = reverse('radius:user_auth_token', args=[self.default_org.slug])
        login_response = self.client.post(login_url, data=login_payload)
        token = login_response.json()['key']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

        # invalid organization
        password_change_url = reverse(
            'radius:rest_password_change',
            args=['random-valid-slug'],
        )
        new_password_payload = {
            'current_password': 'test_password',
            'new_password': 'test_new_password',
            'confirm_password': 'test_new_password',
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 404)

        # user not a member of the organization
        test_user1 = User.objects.create_user(
            username='test_name1', password='test_password1', email='test1@email.com'
        )
        token1 = Token.objects.create(user=test_user1)
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token1}')
        password_change_url = reverse(
            'radius:rest_password_change', args=[self.default_org.slug]
        )
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 400)

        # pass1 and pass2 are not equal
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        password_change_url = reverse(
            'radius:rest_password_change', args=[self.default_org.slug]
        )
        new_password_payload = {
            'current_password': 'test_password',
            'new_password': 'test_new_password',
            'confirm_password': 'test_new_password_different',
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            'The two password fields didn’t match.',
            str(response.data['confirm_password']),
        )

        # current password is not the actual password
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        password_change_url = reverse(
            'radius:rest_password_change', args=[self.default_org.slug]
        )
        new_password_payload = {
            'current_password': 'wrong_password',
            'new_password': 'test_new_password',
            'confirm_password': 'test_new_password',
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            'Your old password was entered incorrectly. Please enter it again.',
            str(response.data['current_password']),
        )

        # new password is same as the current password
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        password_change_url = reverse(
            'radius:rest_password_change', args=[self.default_org.slug]
        )
        new_password_payload = {
            'current_password': 'test_password',
            'new_password': 'test_password',
            'confirm_password': 'test_password',
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            'New password cannot be the same as your old password.',
            str(response.data['new_password']),
        )

        # Password successfully changed
        new_password_payload = {
            'current_password': 'test_password',
            'new_password': 'test_new_password',
            'confirm_password': 'test_new_password',
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Password updated successfully', str(response.data['message']))

        # user should not be able to login using old password
        login_response = self.client.post(login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 400)

        # new password should work
        login_payload['password'] = new_password_payload['new_password']
        login_response = self.client.post(login_url, data=login_payload)
        token = login_response.json()['key']
        self.assertEqual(login_response.status_code, 200)

        # authorization required
        client.credentials(HTTP_AUTHORIZATION='Token wrong')
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 401)

    @capture_any_output()
    def test_api_password_reset(self):
        test_user = User.objects.create_user(
            username='test_name', password='test_password', email='test@email.com'
        )
        self._create_org_user(organization=self.default_org, user=test_user)
        mail_count = len(mail.outbox)
        reset_payload = {'email': 'test@email.com'}

        # wrong org
        password_reset_url = reverse(
            'radius:rest_password_reset', args=['wrong-slug-name']
        )
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(response.status_code, 404)

        password_reset_url = reverse(
            'radius:rest_password_reset', args=[self.default_org.slug]
        )

        # no payload
        response = self.client.post(password_reset_url, data={})
        self.assertEqual(response.status_code, 400)

        # email does not exist in database
        reset_payload = {'email': 'wrong@email.com'}
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(response.status_code, 404)

        # email not registered with org
        User.objects.create_user(
            username='test_name1', password='test_password', email='test1@email.com'
        )
        reset_payload = {'email': 'test1@email.com'}
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(response.status_code, 400)

        # valid payload
        reset_payload = {'email': 'test@email.com'}
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(len(mail.outbox), mail_count + 1)
        email = mail.outbox.pop()
        self.assertIn(
            "<p> Please click on the button below to open a page where you can",
            ' '.join(email.alternatives[0][0].split()),
        )
        self.assertRegex(
            ''.join(email.alternatives[0][0].splitlines()),
            '<a href=".*">.*Reset password.*<\/a>',
        )
        self.assertNotIn('<img src=""', email.alternatives[0][0])
        url_kwargs = {
            'uid': user_pk_to_url_str(test_user),
            'token': default_token_generator.make_token(test_user),
        }
        password_confirm_url = reverse(
            'radius:rest_password_reset_confirm', args=[self.default_org.slug]
        )

        # wrong token
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': url_kwargs['uid'],
            'token': '-wrong-token-',
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 400)

        # wrong uid
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': '-wrong-uid-',
            'token': url_kwargs['token'],
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 404)

        # wrong token and uid
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': '-wrong-uid-',
            'token': '-wrong-token-',
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 404)

        # valid payload
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': url_kwargs['uid'],
            'token': url_kwargs['token'],
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 200)
        self.assertIn(
            'Password reset e-mail has been sent.', str(response.data['detail'])
        )

        # user should not be able to login with old password
        login_payload = {'username': 'test_name', 'password': 'test_password'}
        login_url = reverse('radius:user_auth_token', args=[self.default_org.slug])
        login_response = self.client.post(login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 400)

        # user should be able to login with new password
        login_payload = {'username': 'test_name', 'password': 'test_new_password'}
        login_response = self.client.post(login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 200)

    def test_api_password_reset_405(self):
        password_reset_url = reverse(
            'radius:rest_password_reset', args=[self.default_org.slug]
        )
        response = self.client.get(password_reset_url)
        self.assertEqual(response.status_code, 405)

    def test_user_accounting_list_200(self):
        auth_url = reverse('radius:user_auth_token', args=[self.default_org.slug])
        self._get_org_user()
        response = self.client.post(
            auth_url, {'username': 'tester', 'password': 'tester'}
        )
        authorization = f'Bearer {response.data["key"]}'
        stop_time = '2018-03-02T11:43:24.020460+01:00'
        data1 = self.acct_post_data
        data1.update(
            dict(
                session_id='35000006',
                unique_id='75058e50',
                input_octets=9900909,
                output_octets=1513075509,
                username='tester',
                stop_time=stop_time,
            )
        )
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(
            dict(
                session_id='40111116',
                unique_id='12234f69',
                input_octets=3000909,
                output_octets=1613176609,
                username='tester',
            )
        )
        self._create_radius_accounting(**data2)
        data3 = self.acct_post_data
        data3.update(
            dict(
                session_id='89897654',
                unique_id='99144d60',
                input_octets=4440909,
                output_octets=1119074409,
                username='admin',
                stop_time=stop_time,
            )
        )
        self._create_radius_accounting(**data3)
        url = reverse('radius:user_accounting', args=[self.default_org.slug])
        response = self.client.get(
            f'{url}?page_size=1&page=1',
            HTTP_AUTHORIZATION=authorization,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['output_octets'], data2['output_octets'])
        self.assertEqual(item['input_octets'], data2['input_octets'])
        self.assertEqual(item['nas_ip_address'], '172.16.64.91')
        self.assertEqual(item['calling_station_id'], '5c:7d:c1:72:a7:3b')
        self.assertIsNone(item['stop_time'])
        response = self.client.get(
            f'{url}?page_size=1&page=2',
            HTTP_AUTHORIZATION=authorization,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['output_octets'], data1['output_octets'])
        self.assertEqual(item['nas_ip_address'], '172.16.64.91')
        self.assertEqual(item['input_octets'], data1['input_octets'])
        self.assertEqual(item['called_station_id'], '00-27-22-F3-FA-F1:hostname')
        self.assertIsNotNone(item['stop_time'])
        response = self.client.get(
            f'{url}?page_size=1&page=3',
            HTTP_AUTHORIZATION=authorization,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 404)

    @mock.patch.object(EmailMultiAlternatives, 'send')
    def _test_user_reset_password_helper(self, is_active, mocked_send):
        user = self._create_user(
            username='active_user',
            password='passowrd',
            email='active@gmail.com',
            is_active=is_active,
        )
        org = self._get_org()
        self._create_org_user(user=user, organization=org)
        path = reverse('radius:rest_password_reset', args=[org.slug])
        r = self.client.post(path, {'email': user.email})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data['detail'], 'Password reset e-mail has been sent.')
        mocked_send.assert_called_once()

    def test_active_user_reset_password(self):
        self._test_user_reset_password_helper(True)

    def test_inactive_user_reset_password(self):
        self._test_user_reset_password_helper(False)

    @capture_stderr()
    def test_organization_registration_enabled(self):
        org = self._get_org()
        settings_obj = OrganizationRadiusSettings.objects.get(organization=org)
        url = reverse('radius:rest_register', args=[org.slug])

        with self.subTest('Test registration endpoint enabled by default'):
            r = self.client.post(
                url,
                {
                    'username': 'test@openwisp.org',
                    'email': 'test@openwisp.org',
                    'password1': 'password',
                    'password2': 'password',
                },
            )
            self.assertEqual(r.status_code, 201)
            self.assertIn('key', r.data)

        with self.subTest('Test registration endpoint disabled for org'):
            settings_obj.registration_enabled = False
            settings_obj.save()
            r = self.client.post(
                url,
                {
                    'username': 'test2@openwisp.org',
                    'email': 'test2@openwisp.org',
                    'password1': 'password',
                    'password2': 'password',
                },
            )
            self.assertEqual(r.status_code, 403)

        with self.subTest('Test registration endpoint user global setting'):
            settings_obj.registration_enabled = None
            settings_obj.save()
            r = self.client.post(
                url,
                {
                    'username': 'test3@openwisp.org',
                    'email': 'test3@openwisp.org',
                    'password1': 'password',
                    'password2': 'password',
                },
            )
            self.assertEqual(r.status_code, 201)
            self.assertIn('key', r.data)
