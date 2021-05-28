import logging
import uuid
from datetime import datetime

from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt

from openwisp_radius.utils import load_model

RadiusAccounting = load_model('RadiusAccounting')
RadiusToken = load_model('RadiusToken')
User = get_user_model()
logger = logging.getLogger('django.server')


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
        ra = RadiusAccounting(
            username=radius_token.user.username,
            organization_id=radius_token.organization_id,
            unique_id=id_,
            session_id=id_,
            nas_ip_address='127.0.0.1',
        )
        ra.full_clean()
        ra.save()
        logger.info(
            f'RadiusAccounting session {ra.session_id} created for {ra.username}'
        )
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
            ra.stop_time = datetime.utcnow()
            ra.terminate_cause = 'User-Request'
            ra.save()
            logger.info(
                f'RadiusAccounting session {ra.session_id} terminated by {ra.username}'
            )
    return HttpResponse('logged out in')
