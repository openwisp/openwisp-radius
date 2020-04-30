"""
Receiver functions for django signals (eg: post_save)
"""
from .utils import create_default_groups, load_model


def set_default_group_handler(sender, instance, created, **kwargs):
    if created:
        RadiusGroup = load_model('RadiusGroup')
        RadiusUserGroup = load_model('RadiusUserGroup')
        queryset = RadiusGroup.objects.filter(
            default=True, organization_id=instance.organization.pk
        )
        if queryset.exists() and not instance.user.radiususergroup_set.exists():
            ug = RadiusUserGroup(user=instance.user, group=queryset.first())
            ug.full_clean()
            ug.save()


def create_default_groups_handler(sender, instance, created, **kwargs):
    if created:
        create_default_groups(organization=instance)


def organization_pre_save(instance, **kwargs):
    if instance._state.adding:
        return
    Organization = instance.__class__
    current = Organization.objects.get(pk=instance.pk)
    # TODO: this is a (hopefully) short-term necessary (ugly) hack
    # in the long term we will need to avoid relying on this
    # and find a solution to manage group check queries
    # of different organizations in a way that doesn't require
    # group names to be unique to each org
    if instance.slug != current.slug:
        instance.__old_slug = current.slug


def organization_post_save(instance, **kwargs):
    if instance._state.adding or not hasattr(instance, '__old_slug'):
        return
    RadiusGroup = load_model('RadiusGroup')
    for rg in RadiusGroup.objects.filter(organization=instance):
        rg.name = rg.name.replace(instance.__old_slug, instance.slug)
        rg.full_clean()
        rg.save()
