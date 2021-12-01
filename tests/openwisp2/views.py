import logging
import uuid
from urllib.parse import urlparse

import requests
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.urls import reverse
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt

from openwisp_radius.utils import load_model

RadiusAccounting = load_model('RadiusAccounting')
RadiusToken = load_model('RadiusToken')
User = get_user_model()
logger = logging.getLogger('django.server')


def post_accounting_data(request, data):
    parsed_url = urlparse(request.build_absolute_uri())
    if parsed_url.netloc and parsed_url.scheme:
        url = '{}://{}{}'.format(
            parsed_url.scheme, parsed_url.netloc, reverse('radius:accounting')
        )
        try:
            requests.post(url=url, data=data, timeout=2)
        except Exception as err:
            logger.warning(err)


@csrf_exempt
@xframe_options_exempt
def captive_portal_login(request):
    logger.info(f'Captive portal login mock view called with: {request.POST}')
    password = request.POST.get('auth_pass') or request.POST.get('password')
    radius_token = (
        RadiusToken.objects.filter(key=password).select_related('user').first()
    )
    if (
        radius_token
        and not RadiusAccounting.objects.filter(
            username=radius_token.user.username, stop_time=None
        ).exists()
    ):
        id_ = uuid.uuid4().hex
        username = radius_token.user.username
        data = dict(
            status_type='Start',
            username=radius_token.user.username,
            organization_id=radius_token.organization_id,
            unique_id=id_,
            session_id=id_,
            nas_ip_address='127.0.0.1',
            calling_station_id='00:00:00:00:00:00',
            called_station_id='11:00:00:00:00:11',
            session_time=0,
            input_octets=0,
            output_octets=0,
        )
        post_accounting_data(request, data)
        logger.info(f'RadiusAccounting session {id_} created for {username}')
    return HttpResponse('logged in')


@csrf_exempt
@xframe_options_exempt
def captive_portal_logout(request):
    logger.info(f'Captive portal logout mock view called with: {request.POST}')
    session_id = request.POST.get('logout_id')
    if session_id:
        try:
            ra = RadiusAccounting.objects.get(session_id=session_id)
        except RadiusAccounting.DoesNotExist:
            ra = None
        if ra:
            data = dict(
                status_type='Stop',
                session_id=session_id,
                username=ra.username,
                terminate_cause='User-Request',
                nas_ip_address='127.0.0.1',
                unique_id=session_id,
            )
            post_accounting_data(request, data)
            logger.info(
                f'RadiusAccounting session {ra.session_id} terminated by {ra.username}'
            )
    return HttpResponse('logged out in')
