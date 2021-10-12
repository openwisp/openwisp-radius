import csv
import io
import os
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from openwisp_users.tests.utils import TestOrganizationMixin

from ..base.models import _encode_secret
from ..utils import load_model

# it's 21 of April on UTC, this date is fabricated on purpose
# to test possible timezone related bugs in the date filtering
_TEST_DATE = '2019-04-20T22:14:09-04:00'
_RADACCT = {
    'username': 'bob',
    'nas_ip_address': '127.0.0.1',
    'start_time': '2017-06-10 10:50:00',
    'authentication': 'RADIUS',
    'connection_info_start': 'f',
    'connection_info_stop': 'hgh',
    'input_octets': '1',
    'output_octets': '4',
    'session_id': uuid4().int,
}

Nas = load_model('Nas')
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
RadiusReply = load_model('RadiusReply')
RadiusToken = load_model('RadiusToken')
RadiusCheck = load_model('RadiusCheck')
RadiusGroup = load_model('RadiusGroup')
RadiusPostAuth = load_model('RadiusPostAuth')
RadiusUserGroup = load_model('RadiusUserGroup')
RadiusGroupCheck = load_model('RadiusGroupCheck')
RadiusGroupReply = load_model('RadiusGroupReply')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
User = get_user_model()


class CreateRadiusObjectsMixin(TestOrganizationMixin):
    def _get_org(self, org_name='test org'):
        organization = super()._get_org(org_name)
        OrganizationRadiusSettings.objects.get_or_create(
            organization_id=organization.pk
        )
        return organization

    def _get_user_with_org(self):
        # Used where User model instance is required
        # but User shall be a member of 'default' org.
        self._get_org_user()
        return self._get_user()

    def _get_defaults(self, opts, model=None):
        options = {}
        if not model or hasattr(model, 'organization'):
            options.update({'organization': self._get_org()})
        options.update(opts)
        return options

    def _create_radius_check(self, **kwargs):
        if kwargs.get('value'):
            kwargs['value'] = _encode_secret(kwargs['attribute'], kwargs.get('value'))
        options = self._get_defaults(kwargs)
        rc = RadiusCheck(**options)
        rc.full_clean()
        rc.save()
        return rc

    def _create_radius_accounting(self, **kwargs):
        options = self._get_defaults(kwargs)
        ra = RadiusAccounting(**options)
        ra.full_clean()
        ra.save()
        return ra

    def _create_radius_reply(self, **kwargs):
        options = self._get_defaults(kwargs)
        rr = RadiusReply(**options)
        rr.full_clean()
        rr.save()
        return rr

    def _create_nas(self, **kwargs):
        options = self._get_defaults(kwargs)
        n = Nas(**options)
        n.full_clean()
        n.save()
        return n

    def _create_radius_group(self, **kwargs):
        options = self._get_defaults(kwargs)
        rg = RadiusGroup(**options)
        rg.full_clean()
        rg.save()
        return rg

    def _create_radius_groupcheck(self, **kwargs):
        options = self._get_defaults(kwargs, model=RadiusGroupCheck)
        c = RadiusGroupCheck(**options)
        c.full_clean()
        c.save()
        return c

    def _create_radius_groupreply(self, **kwargs):
        options = self._get_defaults(kwargs, model=RadiusGroupReply)
        r = RadiusGroupReply(**options)
        r.full_clean()
        r.save()
        return r

    def _create_radius_usergroup(self, **kwargs):
        options = self._get_defaults(kwargs, model=RadiusUserGroup)
        ug = RadiusUserGroup(**options)
        ug.full_clean()
        ug.save()
        return ug

    def _create_radius_postauth(self, **kwargs):
        options = self._get_defaults(kwargs)
        rp = RadiusPostAuth(**options)
        rp.full_clean()
        rp.save()
        return rp

    def _create_radius_batch(self, **kwargs):
        options = self._get_defaults(kwargs)
        rb = RadiusBatch(**options)
        rb.full_clean()
        rb.save()
        return rb

    def _create_radius_token(self, **kwargs):
        options = {'user': self._get_user(), 'can_auth': True, 'key': '1234'}
        options.update(self._get_defaults(kwargs))
        radtoken = RadiusToken(**options)
        radtoken.full_clean()
        radtoken.save()
        return radtoken


class PostParamsMixin(object):
    def _get_post_defaults(self, opts, model=None):
        options = {}
        options.update(**opts)
        return options

    def _get_postauth_params(self, **kwargs):
        params = {
            'username': 'molly',
            'password': 'barbar',
            'reply': 'Access-Accept',
            'called_station_id': '00-11-22-33-44-55:hostname',
            'calling_station_id': '00:26:b9:20:5f:10',
        }
        params.update(kwargs)
        return self._get_post_defaults(params)

    def _get_accounting_params(self, **kwargs):
        return self._get_post_defaults(kwargs)


class FileMixin(object):
    def _get_path(self, file):
        d = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(d, file)

    def _get_csvfile(self, rows):
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_NONNUMERIC)
        for row in rows:
            writer.writerow(row)
        return SimpleUploadedFile(
            'test.csv',
            bytes(output.getvalue(), encoding='utf8'),
            content_type='text/csv',
        )

    def _get_openvpn_status(self):
        with open(self._get_path('static/openvpn.status')) as file:
            status = file.read()
        return status

    def _get_openvpn_status_mock(self):
        return patch(
            'openwisp_radius.management.commands.base.convert_called_station_id'
            '.BaseConvertCalledStationIdCommand._get_raw_management_info',
            return_value=self._get_openvpn_status(),
        )


class CallCommandMixin(object):
    def _call_command(self, command, **kwargs):
        call_command(command, **kwargs)
