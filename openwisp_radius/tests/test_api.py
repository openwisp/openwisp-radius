import json
import os
import uuid
from datetime import timedelta
from unittest import mock

import swapper
from dateutil import parser
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.test import override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode
from django.utils.timezone import localtime, now
from freezegun import freeze_time
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from openwisp_radius.api import views as api_views

from .. import settings as app_settings
from ..utils import load_model
from . import _TEST_DATE, FileMixin
from .mixins import ApiTokenMixin, BaseTestCase

User = get_user_model()
PhoneToken = load_model('PhoneToken')
RadiusToken = load_model('RadiusToken')
RadiusAccounting = load_model('RadiusAccounting')
RadiusPostAuth = load_model('RadiusPostAuth')
RadiusBatch = load_model('RadiusBatch')
RadiusUserGroup = load_model('RadiusUserGroup')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
Organization = swapper.load_model('openwisp_users', 'Organization')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')

START_DATE = '2019-04-20T22:14:09+01:00'


class TestApi(ApiTokenMixin, FileMixin, BaseTestCase):
    _test_email = 'test@openwisp.org'

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


class TestApiReject(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        app_settings.API_AUTHORIZE_REJECT = True

    @classmethod
    def tearDownClass(cls):
        app_settings.API_AUTHORIZE_REJECT = False

    def test_disabled_user_login(self):
        User.objects.create_user(username='barbar', password='molly', is_active=False)
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'barbar', 'password': 'molly'},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, {'control:Auth-Type': 'Reject'})

    def test_authorize_401(self):
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'baldo', 'password': 'ugo'},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, {'control:Auth-Type': 'Reject'})


class TestAutoGroupname(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app_settings.API_ACCOUNTING_AUTO_GROUP = True

    def test_automatic_groupname_account_enabled(self):
        user = User.objects.create_superuser(
            username='username1', email='admin@admin.com', password='qwertyuiop'
        )
        usergroup1 = self._create_radius_usergroup(
            groupname='group1', priority=2, username='testgroup1'
        )
        usergroup2 = self._create_radius_usergroup(
            groupname='group2', priority=1, username='testgroup2'
        )
        user.radiususergroup_set.set([usergroup1, usergroup2])
        self.client.post(
            f'{reverse("radius:accounting")}{self.token_querystring}',
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': 'username1',
            },
        )
        accounting_created = RadiusAccounting.objects.get(username='username1')
        self.assertEqual(accounting_created.groupname, 'group2')
        user.delete()


class TestAutoGroupnameDisabled(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app_settings.API_ACCOUNTING_AUTO_GROUP = False

    def test_account_creation_api_automatic_groupname_disabled(self):
        user = User.objects.create_superuser(
            username='username1', email='admin@admin.com', password='qwertyuiop'
        )
        usergroup1 = self._create_radius_usergroup(
            groupname='group1', priority=2, username='testgroup1'
        )
        usergroup2 = self._create_radius_usergroup(
            groupname='group2', priority=1, username='testgroup2'
        )
        user.radiususergroup_set.set([usergroup1, usergroup2])
        url = f'{reverse("radius:accounting")}{self.token_querystring}'
        self.client.post(
            url,
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': 'username1',
            },
        )
        accounting_created = RadiusAccounting.objects.get(username='username1')
        self.assertIsNone(accounting_created.groupname)
        user.delete()


class TestApiUserToken(ApiTokenMixin, BaseTestCase):
    def _get_url(self):
        return reverse('radius:user_auth_token', args=[self.default_org.slug])

    def test_user_auth_token_200(self):
        url = self._get_url()
        self._get_org_user()
        response = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['key'], Token.objects.first().key)
        self.assertEqual(
            response.data['radius_user_token'], RadiusToken.objects.first().key,
        )
        self.assertTrue(response.data['is_active'])

    def test_user_auth_token_with_second_organization(self):
        api_views.renew_required = False
        self._get_org_user()
        self.org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        self._create_org_user(**{'organization': self.org2})
        for org_slug in [self.default_org.slug, self.org2.slug]:
            with self.subTest(org_slug):
                # Get token for organizations
                response = self.client.post(
                    reverse('radius:user_auth_token', args=[org_slug]),
                    {'username': 'tester', 'password': 'tester'},
                )
                self.assertEqual(response.status_code, 200)
                # Check authorization accepts for both organizations
                response = self.client.post(
                    reverse('radius:authorize'),
                    {'username': 'tester', 'password': 'tester'},
                )
                self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})
        api_views.renew_required = True

    def test_user_auth_token_400_credentials(self):
        url = self._get_url()
        r = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('Unable to log in', r.json()['non_field_errors'][0])

    def test_user_auth_token_400_organization(self):
        url = self._get_url()
        self._get_org_user()
        OrganizationUser.objects.all().delete()
        r = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('is not member', r.json()['non_field_errors'][0])

    def test_user_auth_token_404(self):
        url = reverse(
            'radius:user_auth_token', args=['00000000-0000-0000-0000-000000000000']
        )
        r = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 404)

    @freeze_time(_TEST_DATE)
    def test_user_auth_updates_last_login(self):
        admin = self._get_admin()
        login_payload = {'username': 'admin', 'password': 'tester'}
        login_url = reverse('radius:user_auth_token', args=[self.default_org.slug])
        self.assertEqual(admin.last_login, None)
        response = self.client.post(login_url, data=login_payload)
        self.assertEqual(response.status_code, 200)
        admin.refresh_from_db()
        self.assertIsNotNone(admin.last_login)
        self.assertEqual(localtime(admin.last_login).isoformat(), _TEST_DATE)

    def test_user_auth_token_inactive_user(self):
        url = self._get_url()
        organization_user = self._get_org_user()
        organization_user.user.is_active = False
        organization_user.user.save()
        response = self.client.post(url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.data['is_active'])


class TestClientIpApi(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        self._get_org_user()
        self.params = {'username': 'tester', 'password': 'tester'}
        self.fail_msg = (
            'Request rejected: Client IP address (127.0.0.1) is not in '
            'the list of IP addresses allowed to consume the freeradius API.'
        )
        self.freeradius_hosts_path = 'openwisp_radius.settings.FREERADIUS_ALLOWED_HOSTS'
        self.client.post(
            reverse('radius:user_auth_token', args=[self._get_org().slug]), self.params
        )

    def test_cache(self):
        def authorize_and_asset(numOfQueries, ip_list):
            with self.assertNumQueries(numOfQueries):
                response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})
            self.assertEqual(cache.get(f'ip-{org.pk}'), ip_list)

        cache.clear()
        org = self._get_org()
        self.assertEqual(cache.get(f'ip-{org.pk}'), None)
        with self.subTest('Without Cache'):
            authorize_and_asset(4, [])
        with self.subTest('With Cache'):
            authorize_and_asset(2, [])
        with self.subTest('Organization Settings Updated'):
            radsetting = OrganizationRadiusSettings.objects.get(organization=org)
            radsetting.freeradius_allowed_hosts = '127.0.0.1,192.0.2.0'
            radsetting.save()
            authorize_and_asset(2, ['127.0.0.1', '192.0.2.0'])
        with self.subTest('Cache Deleted'):
            cache.clear()
            authorize_and_asset(4, ['127.0.0.1', '192.0.2.0'])

    def test_ip_from_setting_valid(self):
        response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    def test_ip_from_setting_invalid(self):
        with mock.patch(self.freeradius_hosts_path, ['localhost']):
            response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], self.fail_msg)

    def test_ip_from_radsetting_valid(self):
        with mock.patch(self.freeradius_hosts_path, []):
            radsetting = OrganizationRadiusSettings.objects.get(
                organization=self._get_org()
            )
        radsetting.freeradius_allowed_hosts = '127.0.0.1'
        radsetting.save()
        response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})

    def test_ip_from_radsetting_invalid(self):
        radsetting = OrganizationRadiusSettings.objects.get(
            organization=self._get_org()
        )
        radsetting.freeradius_allowed_hosts = '127.0.0.500'
        radsetting.save()
        with mock.patch(self.freeradius_hosts_path, []):
            response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], self.fail_msg)

    def test_ip_from_radsetting_not_exist(self):
        org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        self._create_org_user(**{'organization': org2})
        self.client.post(reverse('radius:user_auth_token', args=[org2.slug]))
        with self.subTest('FREERADIUS_ALLOWED_HOSTS is 127.0.0.1'):
            response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, {'control:Auth-Type': 'Accept'})
        with self.subTest('Empty Settings'), mock.patch(self.freeradius_hosts_path, []):
            response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.data['detail'], self.fail_msg)


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


class TestOgranizationRadiusSettings(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        cache.clear()
        self.org = self._create_org(**{'name': 'test', 'slug': 'test'})

    def test_string_representation(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(str(rad), rad.organization.name)

    def test_default_token(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(32, len(rad.token))

    def test_bad_token(self):
        try:
            rad = OrganizationRadiusSettings(
                token='bad.t.o.k.e.n', organization=self.org
            )
            rad.full_clean()
        except ValidationError as e:
            self.assertEqual(
                e.message_dict['token'][0],
                'This value must not contain spaces, dots or slashes.',
            )

    def test_cache(self):
        rad = OrganizationRadiusSettings.objects.create(
            token='12345', organization=self.org
        )
        self._get_org_user()
        token_querystring = f'?token={rad.token}&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        # Clear cache before sending request
        cache.clear()
        self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        with self.subTest('Cache & token match'):
            self.assertEqual(rad.token, cache.get(rad.organization.pk))
        with self.subTest('Force changed corrupt cache returns 403'):
            cache.set(rad.organization.pk, 'wrong-value')
            response = self.client.post(
                post_url, {'username': 'tester', 'password': 'tester'}
            )
            self.assertEqual(response.status_code, 403)
        with self.subTest('Updated cache with radius setting token'):
            rad.token = '1234567'
            rad.save()
            self.assertEqual(rad.token, cache.get(rad.organization.pk))
        with self.subTest('Cache Miss: radius settings deleted'):
            rad.delete()
            self.assertEqual(None, cache.get(rad.organization.pk))

    def test_no_org_radius_setting(self):
        self._get_org_user()
        token_querystring = f'?token=12345&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        r = self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data, {'detail': 'Token authentication failed'})

    def test_uuid_in_cache(self):
        rad = OrganizationRadiusSettings.objects.create(
            token='12345', organization=self.org
        )
        cache.set('uuid', str(self.org.pk), 30)
        self._get_org_user()
        token_querystring = f'?token={rad.token}&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        r = self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 200)

    def test_default_organisation_radius_settings(self):
        org = self._get_org()
        self.assertTrue(hasattr(org, 'radius_settings'))
        self.assertIsInstance(org.radius_settings, OrganizationRadiusSettings)

    def test_sms_phone_required(self):
        radius_settings = OrganizationRadiusSettings(
            organization=self.org, sms_verification=True, sms_sender=''
        )
        try:
            radius_settings.full_clean()
        except ValidationError as e:
            self.assertIn('sms_sender', e.message_dict)
        else:
            self.fail('ValidationError not raised')


class TestApiPhoneToken(ApiTokenMixin, BaseTestCase):

    _test_email = 'test@openwisp.org'

    def setUp(self):
        super().setUp()
        radius_settings = self.default_org.radius_settings
        radius_settings.sms_verification = True
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

    def test_create_phone_token_400_not_member(self):
        self.test_register_201()
        OrganizationUser.objects.all().delete()
        token = Token.objects.last()
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(r.status_code, 400)
        self.assertIn('non_field_errors', r.data)
        self.assertIn('is not member', str(r.data['non_field_errors']))

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

    def test_create_phone_token_201_user_already_active(self):
        self.test_register_201()
        token = Token.objects.last()
        token.user.is_active = True
        token.user.save()
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        r = self.client.post(url, HTTP_AUTHORIZATION=f'Bearer {token.key}')
        self.assertEqual(r.status_code, 201)

    @freeze_time(_TEST_DATE)
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

    def test_active_user_change_phone_number_sms_on(self):
        self._test_change_phone_number_sms_on_helper(True)

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

    def test_create_phone_token_403(self):
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIn('SMS verification is not enabled', str(r.data))

    def test_validate_phone_token_403(self):
        url = reverse('radius:phone_token_validate', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIn('SMS verification is not enabled', str(r.data))

    def test_change_phone_number_403(self):
        url = reverse('radius:phone_number_change', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 403)
        self.assertIn('SMS verification is not enabled', str(r.data))

    def test_missing_radius_settings(self):
        self.default_org.radius_settings.delete()
        url = reverse('radius:phone_token_create', args=[self.default_org.slug])
        with self.assertNumQueries(1):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 500)
        self.assertIn('Could not complete operation', str(r.data))
