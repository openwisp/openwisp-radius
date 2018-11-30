from datetime import date

from django.conf import settings
from django.contrib.sites.models import Site
from django.urls import reverse
from django.utils.text import slugify
from plans.contrib import get_user_language
from plans.models import Order, PlanPricing, UserPlan

from openwisp_radius.utils import load_model

from . import settings as app_settings
from .mail import send_template_email
from .models import Payment

RadiusGroup = load_model('RadiusGroup')
RadiusGroupCheck = load_model('RadiusGroupCheck')
RadiusGroupReply = load_model('RadiusGroupReply')


def get_or_create_temporary_radius_group(organization):
    """
    gets or creates temporary radius group used while paying
    """
    rg, created = RadiusGroup.objects.get_or_create(
        name='{}-temporary'.format(organization.slug),
        organization=organization
    )
    for check in app_settings.TEMP_GROUP_CHECKS:
        opts = check.copy()
        opts.update({'group': rg,
                     'groupname': rg.name})
        RadiusGroupCheck.objects.get_or_create(**opts)
    for reply in app_settings.TEMP_GROUP_REPLIES:
        opts = reply.copy()
        opts.update({'group': rg,
                     'groupname': rg.name})
        RadiusGroupReply.objects.get_or_create(**opts)
    return rg


def get_or_create_paid_plan_radius_group(organization, plan):
    """
    gets or creates radius group related to plan
    """
    opts = dict(name='{}-{}'.format(organization.slug, slugify(plan.name)),
                organization=organization)
    rg = (RadiusGroup.objects.filter(**opts).first()
          or RadiusGroup(**opts))  # noqa
    if rg._state.adding:
        rg.description = rg.description or plan.description
        rg.full_clean()
        rg.save()
    return rg


def manage_expired_subscriptions():
    expired_user_plans = UserPlan.objects.filter(expire__lt=date.today(),
                                                 active=True)
    for user_plan in expired_user_plans:
        user_plan.active = False
        user_plan.save()
        user = user_plan.user
        plan_slug = user_plan.plan
        radius_user_groups = user.radiususergroup_set \
                                 .filter(groupname__contains=slugify(plan_slug)) \
                                 .select_related('group')
        for rug in radius_user_groups:
            org = rug.group.organization
            temporary = get_or_create_temporary_radius_group(org)
            rug.group = temporary
            rug.full_clean()
            rug.save()
            last_order = user.order_set.last()
            try:
                plan_pricing = PlanPricing.objects.get(plan=last_order.plan,
                                                       pricing=last_order.pricing)
            except (AttributeError, PlanPricing.DoesNotExist):
                plan_pricing = user_plan.plan.planpricing_set.first()
            payment = create_order(user, plan_pricing, None, org)
            site = Site.objects.first()
            url = reverse('subscriptions:process_payment', args=[payment.pk])
            protocol = 'https' if not settings.DEBUG else 'https'
            url = '{0}://{1}{2}'.format(protocol, site.domain, url)
            mail_context = {
                'user': user,
                'plan': plan_pricing.plan,
                'pricing': plan_pricing.pricing,
                'url': url,
                'site_name': site.name
            }
            language_code = get_user_language(user)
            send_template_email([user.email],
                                'mail/subscription_expired_subject.txt',
                                'mail/subscription_expired_body.txt',
                                mail_context,
                                language_code)


def create_order(user, plan_pricing, ip_address, organization):
    order = Order(user=user,
                  plan=plan_pricing.plan,
                  pricing=plan_pricing.pricing,
                  created=user.date_joined,
                  amount=plan_pricing.price,
                  tax=app_settings.TAX,
                  currency=app_settings.CURRENCY)
    order.full_clean()
    order.save()
    payment = Payment(organization=organization,
                      order=order,
                      currency=order.currency,
                      total=order.total(),
                      tax=order.tax_total(),
                      customer_ip_address=ip_address)
    payment.full_clean()
    payment.save()
    return payment
