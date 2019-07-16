from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode
from django_freeradius.tests.base.test_api import BaseTestApi, BaseTestApiReject, BaseTestApiUserToken
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from openwisp_users.models import Organization, OrganizationUser

from ..models import RadiusAccounting, RadiusBatch, RadiusPostAuth
from .mixins import ApiTokenMixin, BaseTestCase

User = get_user_model()


class TestApi(ApiTokenMixin, BaseTestApi, BaseTestCase):
    radius_postauth_model = RadiusPostAuth
    radius_accounting_model = RadiusAccounting
    radius_batch_model = RadiusBatch
    user_model = User

    def assertAcctData(self, ra, data):
        # we don't expect the organization field
        # because it will be inferred from the auth token
        self.assertNotIn('organization', data)
        # but we still want to ensure the
        # organization is filled correctly
        data['organization'] = self.default_org
        return super().assertAcctData(ra, data)

    def test_accounting_start_201(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        data['organization'] = str(self.default_org.pk)
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 403)
        self.assertIn('setting the organization', response.data['detail'])

    def test_register_201(self):
        self.assertEqual(User.objects.count(), 0)
        url = reverse('freeradius:rest_register', args=[self.default_org.slug])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 201)
        self.assertIn('key', r.data)
        self.assertEqual(User.objects.count(), 1)
        user = User.objects.first()
        self.assertIn((self.default_org.pk,), user.organizations_pk)

    def test_register_404(self):
        url = reverse('freeradius:rest_register', args=['madeup'])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 404)

    @override_settings(
        ACCOUNT_EMAIL_VERIFICATION='mandatory',
        ACCOUNT_EMAIL_REQUIRED=True
    )
    def test_email_verification_sent(self):
        self.assertEqual(User.objects.count(), 0)
        url = reverse('freeradius:rest_register', args=[self.default_org.slug])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.data['detail'], "Verification e-mail sent.")

    @override_settings(REST_USE_JWT=True)
    def test_registration_with_jwt(self):
        user_count = User.objects.all().count()
        url = reverse('freeradius:rest_register', args=[self.default_org.slug])
        r = self.client.post(url, {
            'username': 'test@test.org',
            'email': 'test@test.org',
            'password1': 'password',
            'password2': 'password'
        })
        self.assertEqual(r.status_code, 201)
        self.assertIn('token', r.data)
        self.assertEqual(User.objects.all().count(), user_count + 1)

    def test_api_show_only_token_org(self):
        org = Organization.objects.create(name='org1')
        self.assertEqual(self.radius_accounting_model.objects.count(), 0)
        nas_ip = '127.0.0.1'
        test1 = self.radius_accounting_model(session_id='asd1',
                                             organization=org,
                                             nas_ip_address=nas_ip,
                                             unique_id='123')
        test1.full_clean()
        test1.save()
        test2 = self.radius_accounting_model(session_id='asd2',
                                             organization=self.default_org,
                                             nas_ip_address=nas_ip,
                                             unique_id='1234')
        test2.full_clean()
        test2.save()
        data = self.client.get(self._acct_url,
                               HTTP_AUTHORIZATION=self.auth_header)
        self.assertEqual(len(data.json()), 1)
        self.assertEqual(data.json()[0]['organization'], str(self.default_org.pk))

    def test_api_batch_add_users(self):
        post_url = '{}{}'.format(reverse('freeradius:batch'), self.token_querystring)
        response = self.client.post(post_url, {
            'name': 'test_name',
            'prefix': 'test',
            'number_of_users': 5,
            'strategy': 'prefix',
        })
        users = response.json()['users']
        for user in users:
            test_user = self.user_model.objects.get(pk=user['id'])
            with self.subTest(test_user=test_user):
                self.assertIn((self.default_org.pk,), test_user.organizations_pk)

    def test_api_password_change(self):
        test_user = self.user_model.objects.create_user(
            username='test_name',
            password='test_password',
        )
        self.default_org.add_user(test_user)
        login_payload = {
            'username': 'test_name',
            'password': 'test_password'
        }
        login_url = reverse('freeradius:user_auth_token', args=(self.default_org.slug,))
        login_response = self.client.post(login_url, data=login_payload)
        token = login_response.json()['key']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Token {}'.format(token))

        # invalid organization
        password_change_url = reverse('freeradius:rest_password_change', args=('invalid-org',))
        new_password_payload = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password'
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 404)

        # user not a member of the organization
        test_user1 = self.user_model.objects.create_user(
            username='test_name1',
            password='test_password1',
            email='test1@email.com'
        )
        token1 = Token.objects.create(user=test_user1)
        client.credentials(HTTP_AUTHORIZATION='Token {}'.format(token1))
        password_change_url = reverse('freeradius:rest_password_change', args=(self.default_org.slug,))
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 400)

        # pass1 and pass2 are not equal
        client.credentials(HTTP_AUTHORIZATION='Token {}'.format(token))
        password_change_url = reverse('freeradius:rest_password_change', args=(self.default_org.slug,))
        new_password_payload = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password_different'
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn("The two password fields didn't match.", response.data['new_password2'])

        # Password successfully changed
        new_password_payload = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password'
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn('New password has been saved.', response.data['detail'])

        # user should not be able to login using old password
        login_response = self.client.post(login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 400)

        # new password should work
        login_payload['password'] = new_password_payload['new_password1']
        login_response = self.client.post(login_url, data=login_payload)
        token = login_response.json()['key']
        self.assertEqual(login_response.status_code, 200)

    def test_api_password_reset(self):
        test_user = self.user_model.objects.create_user(
            username='test_name',
            password='test_password',
            email='test@email.com'
        )
        self.default_org.add_user(test_user)
        mail_count = len(mail.outbox)
        reset_payload = {'email': 'test@email.com'}

        # wrong org
        password_reset_url = reverse('freeradius:rest_password_reset', args=['wrong-org'])
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(response.status_code, 404)

        password_reset_url = reverse('freeradius:rest_password_reset', args=[self.default_org.slug])

        # no payload
        response = self.client.post(password_reset_url, data={})
        self.assertEqual(response.status_code, 400)

        # email does not exist in database
        reset_payload = {'email': 'wrong@email.com'}
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(response.status_code, 404)

        # email not registered with org
        self.user_model.objects.create_user(
            username='test_name1',
            password='test_password',
            email='test1@email.com'
        )
        reset_payload = {'email': 'test1@email.com'}
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(response.status_code, 400)

        # valid payload
        reset_payload = {'email': 'test@email.com'}
        response = self.client.post(password_reset_url, data=reset_payload)
        self.assertEqual(len(mail.outbox), mail_count + 1)

        url_kwargs = {
            'uid': urlsafe_base64_encode(force_bytes(test_user.pk)),
            'token': default_token_generator.make_token(test_user)
        }
        password_confirm_url = reverse('freeradius:rest_password_reset_confirm', args=[self.default_org.slug])

        # wrong token
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': force_text(url_kwargs['uid']),
            'token': '-wrong-token-'
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 400)

        # wrong uid
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': '-wrong-uid-',
            'token': url_kwargs['token']
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 404)

        # wrong token and uid
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': '-wrong-uid-',
            'token': '-wrong-token-'
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 404)

        # valid payload
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': force_text(url_kwargs['uid']),
            'token': url_kwargs['token']
        }
        confirm_response = self.client.post(password_confirm_url, data=data)
        self.assertEqual(confirm_response.status_code, 200)
        self.assertIn('Password has been reset with the new password.', confirm_response.data['detail'])

        # user should not be able to login with old password
        login_payload = {
            'username': 'test_name',
            'password': 'test_password'
        }
        login_url = reverse('freeradius:user_auth_token', args=(self.default_org.slug,))
        login_response = self.client.post(login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 400)

        # user should be able to login with new password
        login_payload = {
            'username': 'test_name',
            'password': 'test_new_password'
        }
        login_response = self.client.post(login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 200)


class TestApiReject(ApiTokenMixin,
                    BaseTestApiReject,
                    BaseTestCase):
    pass


class TestApiUserToken(ApiTokenMixin,
                       BaseTestApiUserToken,
                       BaseTestCase):
    user_model = User

    def _get_url(self):
        return reverse('freeradius:user_auth_token',
                       args=[self.default_org.slug])

    def test_user_auth_token_400_organization(self):
        url = self._get_url()
        opts = dict(username='tester',
                    password='tester')
        self._create_user(**opts)
        OrganizationUser.objects.all().delete()
        r = self.client.post(url, opts)
        self.assertEqual(r.status_code, 400)
        self.assertIn('is not member',
                      r.json()['non_field_errors'][0])

    def test_user_auth_token_404(self):
        url = reverse('freeradius:user_auth_token',
                      args=['wrong'])
        opts = dict(username='tester',
                    password='tester')
        r = self.client.post(url, opts)
        self.assertEqual(r.status_code, 404)
