import json
import os
import sys
import uuid
from unittest import mock

import swapper
from dateutil import parser
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives
from django.test import override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode
from django.utils.timezone import now
from freezegun import freeze_time
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from openwisp_utils.tests import capture_any_output, capture_stderr

from ... import settings as app_settings
from ...utils import load_model
from ..mixins import ApiTokenMixin, BaseTestCase
from .. import _TEST_DATE, FileMixin

User = get_user_model()
RadiusToken = load_model('RadiusToken')
RadiusBatch = load_model('RadiusBatch')
RadiusAccounting = load_model('RadiusAccounting')
RadiusPostAuth = load_model('RadiusPostAuth')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
Organization = swapper.load_model('openwisp_users', 'Organization')

START_DATE = '2019-04-20T22:14:09+01:00'


class TestApi(ApiTokenMixin, FileMixin, BaseTestCase):
    _test_email = 'test@openwisp.org'
    _acct_url = reverse('radius:accounting')

    def setUp(self):
        cache.clear()
        super().setUp()

    def test_invalid_token(self):
        self._get_org_user()
        auth_header = self.auth_header.replace(' ', '')  # removes spaces in token
        response = self._authorize_user(auth_header=auth_header)
        self.assertEqual(response.status_code, 400)

    def test_disabled_user_login(self):
        user = self._create_user(
            **{
                'username': 'barbar',
                'email': 'barbar@email.com',
                'password': 'molly',
                'is_active': False,
            }
        )
        self._create_org_user(**{'user': user})
        response = self._authorize_user(
            username='barbar', password='molly', auth_header=self.auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)

    @capture_any_output()
    def test_authorize_no_token_403(self):
        self._get_org_user()
        response = self._authorize_user()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            (
                'Radius token does not exist. Obtain a new radius token or provide '
                'the organization UUID and API token.'
            ),
        )

    @capture_any_output()
    def test_authorize_no_username_403(self):
        self._get_org_user()
        self._login_and_obtain_auth_token()
        response = self.client.get(reverse('radius:authorize'))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], 'username field is required.')

    def test_authorize_200(self):
        self._get_org_user()
        response = self._authorize_user(auth_header=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    def test_authorize_unverified_user(self):
        self._get_org_user()
        org_settings = OrganizationRadiusSettings.objects.get(
            organization=self._get_org()
        )
        org_settings.needs_identity_verification = True
        org_settings.save()
        response = self._authorize_user(auth_header=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)

    def _test_authorize_with_user_auth_helper(self, username, password):
        r = self._authorize_user(
            username=username, password=password, auth_header=self.auth_header
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {'control:Auth-Type': 'Accept'})

    def test_authorize_with_user_auth(self):
        user = self._create_user(
            username='tester',
            email='tester@gmail.com',
            phone_number='+237675679231',
            password='tester',
        )

        self._create_org_user(organization=self._get_org(), user=user)

        with self.subTest('Test authorize with username'):
            self._test_authorize_with_user_auth_helper('tester', 'tester')

        with self.subTest('Test authorize with email'):
            self._test_authorize_with_user_auth_helper('tester@gmail.com', 'tester')

        with self.subTest('Test authorize with phone_number'):
            self._test_authorize_with_user_auth_helper('+237675679231', 'tester')

    def test_authorize_user_with_email_as_username(self):
        user = self._create_user(
            username='tester',
            email='tester@gmail.com',
            phone_number='+237675679231',
            password='tester',
        )
        user1 = self._create_user(
            username='tester@gmail.com',
            email='tester1@gmail.com',
            phone_number='+237675679232',
            password='tester1',
        )
        self._create_org_user(organization=self._get_org(), user=user)
        self._create_org_user(organization=self._get_org(), user=user1)

        self._test_authorize_with_user_auth_helper(user.email, 'tester')

    def test_authorize_user_with_phone_number_as_username(self):
        user = self._create_user(
            username='tester',
            email='tester@gmail.com',
            phone_number='+237675679231',
            password='tester',
        )
        user1 = self._create_user(
            username='+237675679231',
            email='tester1@gmail.com',
            phone_number='+237675679232',
            password='tester1',
        )
        self._create_org_user(organization=self._get_org(), user=user)
        self._create_org_user(organization=self._get_org(), user=user1)

        self._test_authorize_with_user_auth_helper(user.phone_number, 'tester')

    def test_authorize_200_querystring(self):
        self._get_org_user()
        post_url = f'{reverse("radius:authorize")}{self.token_querystring}'
        response = self.client.post(
            post_url, {'username': 'tester', 'password': 'tester'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    def test_authorize_failed(self):
        response = self._authorize_user(
            username='baldo', password='ugo', auth_header=self.auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)

    def test_authorize_fail_auth_details_incomplete(self):
        for querystring in [
            f'?token={self.default_org.radius_settings.token}',
            f'?uuid={str(self.default_org.pk)}',
        ]:
            with self.subTest(querystring):
                post_url = f'{reverse("radius:authorize")}{querystring}'
                response = self.client.post(
                    post_url, {'username': 'tester', 'password': 'tester'}
                )
                self.assertEqual(response.status_code, 403)

    def test_authorize_wrong_password(self):
        self._get_org_user()
        response = self._authorize_user(password='wrong', auth_header=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)

    def test_authorize_radius_token_200(self):
        self._get_org_user()
        rad_token = self._login_and_obtain_auth_token()
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    def test_authorize_with_password_after_radius_token_expires(self):
        self.test_authorize_radius_token_200()
        self.assertFalse(RadiusToken.objects.get(user__username='tester').can_auth)
        response = self._authorize_user()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    def test_user_auth_token_disposed_after_auth(self):
        app_settings.DISPOSABLE_RADIUS_USER_TOKEN = True
        self._get_org_user()
        rad_token = self._login_and_obtain_auth_token()
        # Success but disable radius_token for authorization
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'{"control:Auth-Type":"Accept"}')
        # Ensure cannot authorize with radius_token
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'')
        # Ensure can authorize with password
        response = self._authorize_user()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'{"control:Auth-Type":"Accept"}')

    def test_user_auth_token_obtain_auth_token_renew(self):
        self._get_org_user()
        rad_token = self._login_and_obtain_auth_token()
        # Authorization works
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'{"control:Auth-Type":"Accept"}')
        # Renew and authorize again
        second_rad_token = self._login_and_obtain_auth_token()
        response = self._authorize_user(password=second_rad_token)
        self.assertEqual(response.content, b'{"control:Auth-Type":"Accept"}')
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(rad_token, second_rad_token)

    def test_postauth_accept_201(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params()
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        params['password'] = ''
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)

    def test_authorize_radius_token_unverified_user(self):
        user = self._get_org_user()
        org_settings = OrganizationRadiusSettings.objects.get(
            organization=user.organization
        )
        org_settings.needs_identity_verification = True
        org_settings.save()
        response = self.client.post(
            reverse('radius:user_auth_token', args=[user.organization.slug]),
            data={'username': 'tester', 'password': 'tester'},
        )
        self.assertEqual(response.status_code, 401)

    def test_postauth_radius_token_expired_201(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        self.assertEqual(RadiusToken.objects.all().count(), 0)
        self._get_org_user()
        self._create_radius_token(can_auth=False)
        params = self._get_postauth_params(**{'username': 'tester', 'password': ''})
        response = self.client.post(reverse('radius:postauth'), params)
        self.assertEqual(RadiusToken.objects.all().count(), 1)
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)

    def test_postauth_radius_token_accept_201(self):
        self._get_org_user()
        self._login_and_obtain_auth_token()
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params(
            **{'username': 'tester', 'password': 'tester'}
        )
        response = self.client.post(reverse('radius:postauth'), params)
        params['password'] = ''
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)

    def test_postauth_accept_201_querystring(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params()
        post_url = f'{reverse("radius:postauth")}{self.token_querystring}'
        response = self.client.post(post_url, params)
        params['password'] = ''
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)

    def test_postauth_reject_201(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = {'username': 'molly', 'password': 'barba', 'reply': 'Access-Reject'}
        params = self._get_postauth_params(**params)
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(
            RadiusPostAuth.objects.filter(username='molly', password='barba').count(),
            1,
        )

    def test_postauth_reject_201_empty_fields(self):
        params = {
            'reply': 'Access-Reject',
            'called_station_id': '',
            'calling_station_id': '',
        }
        params = self._get_postauth_params(**params)
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)

    def test_postauth_400(self):
        response = self.client.post(
            reverse('radius:postauth'), {}, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        self.assertEqual(response.status_code, 400)

    @capture_any_output()
    def test_postauth_no_token_403(self):
        response = self.client.post(reverse('radius:postauth'), {'username': 'tester'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            (
                'Radius token does not exist. Obtain a new radius token or provide '
                'the organization UUID and API token.'
            ),
        )

    def test_postauth_long_password_access_reject(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params(
            **{'password': get_random_string(length=128), 'reply': 'Access-Reject'}
        )
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusPostAuth.objects.count(), 1)
        pa = RadiusPostAuth.objects.first()
        with self.subTest('Ensure validation does not fail'):
            pa.full_clean()
        with self.subTest('Ensure max length is honored'):
            self.assertEqual(
                len(pa.password), RadiusPostAuth._meta.get_field('password').max_length
            )

    def test_postauth_long_password_access_accept(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params(
            **{'password': get_random_string(length=128), 'reply': 'Access-Accept'}
        )
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusPostAuth.objects.count(), 1)
        pa = RadiusPostAuth.objects.first()
        with self.subTest('Ensure validation does not fail'):
            pa.full_clean()
        with self.subTest('Ensure password is not saved'):
            self.assertEqual(len(pa.password), 0)

    _acct_url = reverse('radius:accounting')
    _acct_initial_data = {
        'unique_id': '75058e50',
        'session_id': '35000006',
        'nas_ip_address': '172.16.64.91',
        'session_time': 0,
        'input_octets': 0,
        'output_octets': 0,
    }
    _acct_post_data = {
        'username': 'admin',
        'realm': '',
        'nas_port_id': '1',
        'nas_port_type': 'Async',
        'session_time': '261',
        'authentication': 'RADIUS',
        'input_octets': '1111909',
        'output_octets': '1511074444',
        'called_station_id': '00-27-22-F3-FA-F1:hostname',
        'calling_station_id': '5c:7d:c1:72:a7:3b',
        'terminate_cause': 'User_Request',
        'service_type': 'Login-User',
        'framed_protocol': 'test',
        'framed_ip_address': '127.0.0.1',
        'framed_ipv6_address': '::1',
        'framed_ipv6_prefix': '0::/64',
        'framed_interface_id': '0000:0000:0000:0001',
        'delegated_ipv6_prefix': '0::/64',
    }

    @property
    def acct_post_data(self):
        """ returns a copy of self._acct_data """
        data = self._acct_initial_data.copy()
        data.update(self._acct_post_data.copy())
        return data

    def post_json(self, data):
        """
        performs a post using application/json as content type
        emulating the exact behaviour of freeradius 3
        """
        return self.client.post(
            self._acct_url,
            data=json.dumps(data),
            HTTP_AUTHORIZATION=self.auth_header,
            content_type='application/json',
        )

    def _prep_start_acct_data(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        return self._get_accounting_params(**data)

    def assertAcctData(self, ra, data):
        """
        compares the values in data (dict)
        with the values of a RadiusAccounting instance
        to ensure they match
        """
        # we don't expect the organization field
        # because it will be inferred from the auth token
        self.assertNotIn('organization', data)
        # but we still want to ensure the
        # organization is filled correctly
        data['organization'] = self.default_org
        for key, _ in data.items():
            if key in ('status_type', 'framed_ipv6_address'):
                continue
            ra_value = getattr(ra, key)
            data_value = data[key]
            _type = type(ra_value)
            if _type != type(data_value):
                data_value = _type(data_value)
            self.assertEqual(ra_value, data_value, msg=key)

    @capture_any_output()
    def test_accounting_no_token_403(self):
        response = self.client.post(self._acct_url, {'username': 'tester'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            (
                'Radius token does not exist. Obtain a new radius token or provide '
                'the organization UUID and API token.'
            ),
        )

    @freeze_time(START_DATE)
    def test_accounting_start_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        data = self._prep_start_acct_data()
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertAcctData(ra, data)

    def test_accounting_start_radius_token_201(self):
        self._get_org_user()
        self._login_and_obtain_auth_token()
        data = self._prep_start_acct_data()
        data.update(username='tester')
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        response = self.client.post(
            self._acct_url, data=json.dumps(data), content_type='application/json',
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)

    def test_accounting_start_radius_token_expired_200(self):
        self._get_org_user()
        self._create_radius_token(can_auth=False)
        self._create_radius_accounting(**self._acct_initial_data)
        data = self._prep_start_acct_data()
        data.update(username='tester')
        response = self.client.post(
            self._acct_url, data=json.dumps(data), content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'')

    @freeze_time(START_DATE)
    def test_accounting_start_200_querystring(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        data = self._prep_start_acct_data()
        post_url = f'{self._acct_url}{self.token_querystring}'
        response = self.client.post(
            post_url, json.dumps(data), content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_start_coova_chilli(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = {
            'status_type': 'Start',
            'session_id': '5a4f59aa00000001',
            'unique_id': 'd11a8069e261040d8b01b9135bdb8dc9',
            'username': 'username',
            'realm': '',
            'nas_ip_address': '192.168.182.1',
            'nas_port_id': '1',
            'nas_port_type': 'Wireless-802.11',
            'session_time': '',
            'authentication': '',
            'input_octets': '',
            'output_octets': '',
            'called_station_id': 'C0-4A-00-EE-D1-0D',
            'calling_station_id': 'A4-02-B9-D3-FD-29',
            'terminate_cause': '',
            'service_type': '',
            'framed_protocol': '',
            'framed_ip_address': '192.168.182.3',
            'framed_ipv6_address': '::ffff:c0a8:b603',
            'framed_ipv6_prefix': '0::/64',
            'framed_interface_id': '0000:ffff:c0a8:b603',
            'delegated_ipv6_prefix': '0::/64',
        }
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra = RadiusAccounting.objects.last()
        ra.refresh_from_db()
        data['session_time'] = 0
        data['input_octets'] = 0
        data['output_octets'] = 0
        self.assertEqual(ra.session_time, 0)
        self.assertEqual(ra.input_octets, 0)
        self.assertEqual(ra.output_octets, 0)
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_start_201(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = self.acct_post_data
        data['status_type'] = 'Start'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        self.assertAcctData(RadiusAccounting.objects.first(), data)

    @freeze_time(START_DATE)
    def test_accounting_update_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        data = self.acct_post_data
        data['status_type'] = 'Interim-Update'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertEqual(ra.update_time.timetuple(), now().timetuple())
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_update_201(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = self.acct_post_data
        data['status_type'] = 'Interim-Update'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra = RadiusAccounting.objects.first()
        self.assertEqual(ra.update_time.timetuple(), now().timetuple())
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    def test_accounting_stop_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        # reload date object in order to store ra.start_time
        ra.refresh_from_db()
        start_time = ra.start_time
        data = self.acct_post_data
        data['status_type'] = 'Stop'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertEqual(ra.update_time.timetuple(), now().timetuple())
        self.assertEqual(ra.stop_time.timetuple(), now().timetuple())
        self.assertEqual(ra.start_time, start_time)
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_stop_201(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = self.acct_post_data
        data['status_type'] = 'Stop'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra = RadiusAccounting.objects.first()
        self.assertEqual(ra.update_time.timetuple(), now().timetuple())
        self.assertEqual(ra.stop_time.timetuple(), now().timetuple())
        self.assertEqual(ra.start_time.timetuple(), now().timetuple())
        self.assertAcctData(ra, data)

    def test_user_auth_token_disabled_on_stop(self):
        self._get_org_user()
        radtoken = self._create_radius_token(can_auth=True)
        # Send Accounting stop request
        data = self.acct_post_data
        data.update(username='tester', status_type='Stop')
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        radtoken.refresh_from_db()
        self.assertFalse(radtoken.can_auth)

    @freeze_time(START_DATE)
    def test_user_auth_token_org_accounting_stop(self):
        self._get_org_user()
        self.org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        self._create_org_user(**{'organization': self.org2})
        # Start Accounting with first organzation
        response = self.client.post(
            reverse('radius:user_auth_token', args=[self.default_org.slug]),
            {'username': 'tester', 'password': 'tester'},
        )
        data = self._prep_start_acct_data()
        data.update(username='tester')
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        # Get radius token with second organization
        response = self.client.post(
            reverse('radius:user_auth_token', args=[self.org2.slug]),
            {'username': 'tester', 'password': 'tester'},
        )
        # Test RadiusAccounting is terminated with correct cause
        self.assertEqual(
            RadiusAccounting.objects.filter(
                username='tester',
                organization=self.default_org,
                terminate_cause='NAS_Request',
                stop_time__isnull=False,
            ).count(),
            1,
        )

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_radius_accounting_nas_stop_regression(self):
        # create a first RadiusAccounting object to ensure
        # we'll have 2 records when the next test method is executed
        unique_id = uuid.uuid4().hex
        data = self._prep_start_acct_data()
        data.update(
            username='tester',
            stop_time=START_DATE,
            terminate_cause='User-Request',
            unique_id=unique_id,
            session_id=unique_id,
        )
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.test_user_auth_token_org_accounting_stop()

    @freeze_time(START_DATE)
    def test_accounting_400_missing_status_type(self):
        data = self._get_accounting_params(**self.acct_post_data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('status_type', response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    @freeze_time(START_DATE)
    def test_accounting_400_invalid_status_type(self):
        data = self.acct_post_data
        data['status_type'] = 'INVALID'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('status_type', response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    @freeze_time(START_DATE)
    def test_accounting_400_validation_error(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        del data['nas_ip_address']
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('nas_ip_address', response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    def test_accounting_list_200(self):
        data1 = self.acct_post_data
        data1.update(
            dict(
                session_id='35000006',
                unique_id='75058e50',
                input_octets=9900909,
                output_octets=1513075509,
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
            )
        )
        self._create_radius_accounting(**data3)
        response = self.client.get(
            f'{self._acct_url}?page_size=1&page=1', HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['output_octets'], data3['output_octets'])
        self.assertEqual(item['input_octets'], data3['input_octets'])
        self.assertEqual(item['nas_ip_address'], '172.16.64.91')
        self.assertEqual(item['calling_station_id'], '5c:7d:c1:72:a7:3b')
        response = self.client.get(
            f'{self._acct_url}?page_size=1&page=2', HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['output_octets'], data2['output_octets'])
        self.assertEqual(item['nas_ip_address'], '172.16.64.91')
        self.assertEqual(item['input_octets'], data2['input_octets'])
        self.assertEqual(item['called_station_id'], '00-27-22-F3-FA-F1:hostname')
        response = self.client.get(
            f'{self._acct_url}?page_size=1&page=3', HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['username'], 'admin')
        self.assertEqual(item['calling_station_id'], '5c:7d:c1:72:a7:3b')
        self.assertEqual(item['output_octets'], data1['output_octets'])
        self.assertEqual(item['input_octets'], data1['input_octets'])

    def test_accounting_filter_username(self):
        data1 = self.acct_post_data
        data1.update(dict(username='test_user', unique_id='75058e50'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(dict(username='admin', unique_id='99144d60'))
        self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?username=test_user', HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['username'], 'test_user')

    def test_accounting_filter_called_station_id(self):
        data1 = self.acct_post_data
        data1.update(dict(called_station_id='E0-CA-40-EE-D1-0D', unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(dict(called_station_id='C0-CA-40-FE-E1-9D', unique_id='85144d60'))
        self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?called_station_id=E0-CA-40-EE-D1-0D',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['called_station_id'], 'E0-CA-40-EE-D1-0D')

    def test_accounting_filter_calling_station_id(self):
        data1 = self.acct_post_data
        data1.update(dict(calling_station_id='4c:8d:c2:80:a7:4c', unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(dict(calling_station_id='5c:6d:c2:80:a7:4c', unique_id='85144d60'))
        self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?calling_station_id=4c:8d:c2:80:a7:4c',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['calling_station_id'], '4c:8d:c2:80:a7:4c')

    @freeze_time(START_DATE)
    def test_accounting_filter_start_time(self):
        data1 = self.acct_post_data
        data1.update(dict(unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(
            dict(start_time='2018-03-02T00:43:24.020460+01:00', unique_id='85144d60')
        )
        ra = self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?start_time=2018-03-01',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 2)
        self.assertEqual(response.status_code, 200)
        item = response.data[-1]
        self.assertEqual(parser.parse(item['start_time']), ra.start_time)

    @freeze_time(START_DATE)
    def test_accounting_filter_stop_time(self):
        data1 = self.acct_post_data
        data1.update(
            dict(
                start_time=START_DATE,
                stop_time=START_DATE.replace('04-20', '04-21'),
                unique_id='99144d60',
            )
        )
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        stop_time = '2018-03-02T11:43:24.020460+01:00'
        data2.update(
            dict(
                start_time='2018-03-02T10:43:24.020460+01:00',
                stop_time=stop_time,
                unique_id='85144d60',
            )
        )
        ra = self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?stop_time=2018-03-02 21:43:25',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(parser.parse(item['stop_time']), ra.stop_time)

    def test_accounting_filter_is_open(self):
        data1 = self.acct_post_data
        data1.update(dict(stop_time=None, unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(
            dict(stop_time='2018-03-02T00:43:24.020460+01:00', unique_id='85144d60')
        )
        ra = self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?is_open=true', HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['stop_time'], None)
        response = self.client.get(
            f'{self._acct_url}?is_open=false', HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(parser.parse(item['stop_time']), ra.stop_time)

    @freeze_time(START_DATE)
    def test_coova_accounting_on_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = {
            'status_type': 'Accounting-On',
            'session_id': '',
            'unique_id': '569533dad629d47d8b122826d3ed7f3d',
            'username': '',
            'realm': '',
            'nas_ip_address': '192.168.182.1',
            'nas_port_id': '',
            'nas_port_type': 'Wireless-802.11',
            'session_time': '',
            'authentication': '',
            'input_octets': '',
            'output_octets': '',
            'called_station_id': 'C0-4A-00-EE-D1-0D',
            'calling_station_id': '00-00-00-00-00-00',
            'terminate_cause': '',
            'service_type': '',
            'framed_protocol': '',
            'framed_ip_address': '',
            'framed_ipv6_address': '',
            'framed_ipv6_prefix': '',
            'framed_interface_id': '',
            'delegated_ipv6_prefix': '',
        }
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    @freeze_time(START_DATE)
    def test_coova_accounting_off_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = {
            'status_type': 'Accounting-Off',
            'session_id': '',
            'unique_id': '569533dad629d47d8b122826d3ed7f3d',
            'username': '',
            'realm': '',
            'nas_ip_address': '192.168.182.1',
            'nas_port_id': '',
            'nas_port_type': 'Wireless-802.11',
            'session_time': '',
            'authentication': '',
            'input_octets': '',
            'output_octets': '',
            'called_station_id': 'C0-4A-00-EE-D1-0D',
            'calling_station_id': '00-00-00-00-00-00',
            'terminate_cause': '0',
            'service_type': '',
            'framed_protocol': '',
            'framed_ip_address': '',
            'framed_ipv6_address': '',
            'framed_ipv6_prefix': '',
            'framed_interface_id': '',
            'delegated_ipv6_prefix': '',
        }
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, None)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

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

    def test_get_authorize_view(self):
        url = f'{reverse("radius:authorize")}{self.token_querystring}'
        r = self.client.get(url, HTTP_ACCEPT='text/html')
        self.assertEqual(r.status_code, 405)
        expected = f'<form action="{reverse("radius:authorize")}'
        self.assertIn(expected, r.content.decode())

    def test_accounting_start_403(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        data['organization'] = str(self.default_org.pk)
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 403)
        self.assertIn('setting the organization', str(response.data['detail']))

    def test_register_201(self):
        # ensure session authentication does not interfere with the API
        # otherwise users being logged in the admin and testing the API
        # will get failures. Rather than telling them to log out from the admin
        # we'll handle this case and avoid the issue altogether
        self._superuser_login()
        self.assertEqual(User.objects.count(), 1)
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
        self.assertIn('key', r.data)
        self.assertIn('radius_user_token', r.data)
        self.assertEqual(User.objects.count(), 2)
        self.assertEqual(RadiusToken.objects.count(), 1)
        radius_token = RadiusToken.objects.get()
        self.assertEqual(r.data['radius_user_token'], radius_token.key)
        user = User.objects.get(email=self._test_email)
        self.assertTrue(user.is_member(self.default_org))
        self.assertTrue(user.is_active)

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

    def test_api_show_only_token_org(self):
        org = Organization.objects.create(name='org1')
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        nas_ip = '127.0.0.1'
        test1 = RadiusAccounting(
            session_id='asd1', organization=org, nas_ip_address=nas_ip, unique_id='123'
        )
        test1.full_clean()
        test1.save()
        test2 = RadiusAccounting(
            session_id='asd2',
            organization=self.default_org,
            nas_ip_address=nas_ip,
            unique_id='1234',
        )
        test2.full_clean()
        test2.save()
        data = self.client.get(self._acct_url, HTTP_AUTHORIZATION=self.auth_header)
        self.assertEqual(len(data.json()), 1)
        self.assertEqual(data.json()[0]['organization'], str(self.default_org.pk))

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
            os.path.dirname(os.path.abspath(__file__)), 'static', 'test_batch.csv'
        )
        with open(path_csv, 'rt') as file:
            data = self._radius_batch_csv_data(csvfile=file)
            response = self._radius_batch_post_request(data)
        self.assertEqual(response.status_code, 201)
        response_json = json.loads(response.content)
        org = Organization.objects.get(pk=response_json['organization'])
        pdf_url = reverse(
            'radius:download_rad_batch_pdf', args=[org.slug, response_json['id']],
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
            'radius:download_rad_batch_pdf', args=['non-existent-org', radbatch.pk],
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
            'radius:download_rad_batch_pdf', args=[self.default_org.slug, radbatch.pk],
        )
        operator = self._get_operator()
        self._create_org_user(user=operator)
        self.client.force_login(self._get_operator())
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    @capture_any_output()
    def test_api_password_change(self):
        test_user = User.objects.create_user(
            username='test_name', password='test_password',
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
            'radius:rest_password_change', args=['random-valid-slug'],
        )
        new_password_payload = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
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
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password_different',
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            'The two password fields didn’t match.',
            str(response.data['new_password2']).replace("'", "’"),
        )

        # Password successfully changed
        new_password_payload = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
        }
        response = client.post(password_change_url, data=new_password_payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn('New password has been saved.', str(response.data['detail']))

        # user should not be able to login using old password
        login_response = self.client.post(login_url, data=login_payload)
        self.assertEqual(login_response.status_code, 400)

        # new password should work
        login_payload['password'] = new_password_payload['new_password1']
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

        url_kwargs = {
            'uid': urlsafe_base64_encode(force_bytes(test_user.pk)),
            'token': default_token_generator.make_token(test_user),
        }
        password_confirm_url = reverse(
            'radius:rest_password_reset_confirm', args=[self.default_org.slug]
        )

        # wrong token
        data = {
            'new_password1': 'test_new_password',
            'new_password2': 'test_new_password',
            'uid': force_text(url_kwargs['uid']),
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
            'uid': force_text(url_kwargs['uid']),
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
            f'{url}?page_size=1&page=1', HTTP_AUTHORIZATION=authorization,
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
            f'{url}?page_size=1&page=2', HTTP_AUTHORIZATION=authorization,
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
            f'{url}?page_size=1&page=3', HTTP_AUTHORIZATION=authorization,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 404)

    def test_user_accounting_list_empty_diff_organization(self):
        self.test_accounting_start_200()
        self._get_org_user()
        with self.subTest("Auth Token"):
            self._login_and_obtain_auth_token(username='tester')
            response = self.client.get(f'{self._acct_url}?username=tester')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()), 0)
        with self.subTest("HTTP Auth"):
            response = self.client.get(
                f'{self._acct_url}?username=tester', HTTP_AUTHORIZATION=self.auth_header
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()), 0)

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
            settings_obj = OrganizationRadiusSettings.objects.get(organization=org)
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
