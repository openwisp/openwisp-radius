"""
Receiver functions for django signals (eg: post_save)
"""
import logging

from django.utils.text import slugify
from plans.models import Plan, PlanPricing

from openwisp_radius.utils import load_model
from openwisp_users.models import Organization

from .utils import get_or_create_paid_plan_radius_group, get_or_create_temporary_radius_group

RadiusGroup = load_model('RadiusGroup')
RadiusUserGroup = load_model('RadiusUserGroup')
logger = logging.getLogger(__name__)


def _create_radius_groups_for_plan(plan, organization):
    get_or_create_paid_plan_radius_group(organization, plan)
    get_or_create_temporary_radius_group(organization)


def auto_radius_groups_on_plan_creation(instance, created, **kwargs):
    """
    Creates necessary Radius Groups when a paid plan is created
    """
    if not created or instance.price <= 0:
        return
    for org in Organization.objects.all():
        _create_radius_groups_for_plan(instance.plan, org)


def auto_radius_groups_on_org_creation(instance, created, **kwargs):
    """
    Creates necessary Radius Groups when an organization is created
    """
    if not created:
        return
    for plan_pricing in PlanPricing.objects.all():
        if plan_pricing.price <= 0:
            continue
        _create_radius_groups_for_plan(plan_pricing.plan, instance)


def auto_rename_radius_groups(instance, **kwargs):
    """
    Automatically renames radius groups when plans are renamed
    """
    if instance._state.adding:
        return
    current = Plan.objects.get(pk=instance.pk)
    for org in Organization.objects.all():
        groupname = '{}-{}'.format(org.slug, slugify(current.name))
        try:
            rg = RadiusGroup.objects.get(name=groupname)
        except RadiusGroup.DoesNotExist:
            logger.exception('Failed renaming! Group {} not found'.format(groupname))
            continue
        rg.name = '{}-{}'.format(org.slug, slugify(instance.name))
        rg.full_clean()
        rg.save()
