import csv

import django
from django.contrib import admin
from django.core.files.temp import NamedTemporaryFile
from django.core.management import call_command
from django.test import RequestFactory
from django.urls import reverse

from openwisp_users.tests.test_admin import TestBasicUsersIntegration
from openwisp_utils.tests import capture_stdout

from ..admin import (
    OrganizationRadiusSettingsInline,
    RadiusTokenInline,
    RadiusUserGroupInline,
    RegisteredUserInline,
)
from ..utils import load_model
from .mixins import GetEditFormInlineMixin

RadiusToken = load_model("RadiusToken")
RadiusGroup = load_model("RadiusGroup")
RadiusUserGroup = load_model("RadiusUserGroup")
RegisteredUser = load_model("RegisteredUser")


class TestUsersIntegration(GetEditFormInlineMixin, TestBasicUsersIntegration):
    """
    tests integration with openwisp_users
    """

    is_integration_test = True

    def test_radiustoken_inline_excluded_fields(self):
        user = self._create_user()
        inline = RadiusTokenInline(user.__class__, admin.site)
        request = RequestFactory().get(
            reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        )

        with self.subTest("add"):
            excluded = inline.get_exclude(request)
            self.assertIn("password_based", excluded)
            self.assertIn("key", excluded)

        RadiusToken.objects.create(user=user, organization=self._get_org())

        with self.subTest("change"):
            excluded = inline.get_exclude(request, user)
            self.assertIn("password_based", excluded)
            self.assertNotIn("key", excluded)

    def test_radiustoken_inline(self):
        admin = self._create_admin()
        self.client.force_login(admin)
        user = self._create_user()
        org = self._get_org()
        self._create_org_user(organization=org, user=user)
        params = user.__dict__
        params.pop("phone_number")
        params.pop("password", None)
        params.pop("_password", None)
        params.pop("bio", None)
        params.pop("last_login", None)
        params.pop("password_updated", None)
        params.pop("password_based_token", None)
        params.pop("birth_date", None)
        params.pop("expiration_date", None)
        params = self._additional_params_pop(params)
        params.update(self._get_user_edit_form_inline_params(user, org))
        url = reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        response = self.client.get(
            url,
        )
        self.assertContains(response, 'id="id_radius_token-__prefix__-organization"')
        self.assertNotContains(
            response, 'id="id_radius_token-__prefix__-password_based"'
        )
        # TODO: Remove this while dropping support for Django 4.2
        if django.VERSION < (5, 1):
            self.assertNotContains(response, 'id="id_radius_token-__prefix__-key"')
        else:
            # On Django 5.1+, the empty form include hidden field for the
            # primary key of the related object ("key" field for RadiusToken).
            self.assertContains(
                response,
                '<input type="hidden" name="radius_token-__prefix__-key"'
                ' id="id_radius_token-__prefix__-key">',
            )

        # Create a radius token
        params.update(
            {
                "radius_token-0-organization": str(org.id),
                "radius_token-0-user": str(user.id),
                "radius_token-0-can_auth": True,
                "radius_token-TOTAL_FORMS": "1",
                "_continue": True,
            }
        )
        response = self.client.post(url, params, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(RadiusToken.objects.count(), 1)
        self.assertNotContains(response, 'id="id_radius_token-0-password_based"')
        radius_token = user.radius_token.key
        key_input = (
            '<input type="text" name="radius_token-0-key"'
            f' value="{radius_token}"'
            ' class="readonly vTextField" readonly'
            ' maxlength="40" id="id_radius_token-0-key">'
        )
        self.assertContains(
            response,
            key_input,
            html=True,
        )

        # Delete user radius token
        params.update(
            {
                "radius_token-0-DELETE": "on",
                "radius_token-INITIAL_FORMS": "1",
                "radius_token-0-key": radius_token,
            }
        )
        response = self.client.post(url, params, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(RadiusToken.objects.count(), 0)

    @capture_stdout()
    def test_export_users_command(self):
        temp_file = NamedTemporaryFile(delete=False)
        org_user = self._create_org_user()
        user = org_user.user
        org2 = self._create_org(name="Test Organization 2")
        self._create_org_user(organization=org2, user=user)
        org1_reg_user = RegisteredUser.objects.create(
            user=user,
            organization=org_user.organization,
            method="mobile_phone",
            is_verified=False,
        )
        org2_reg_user = RegisteredUser.objects.create(
            user=user,
            organization=org2,
            method="mobile_phone",
            is_verified=True,
        )
        with self.assertNumQueries(3):
            call_command("export_users", filename=temp_file.name)

        with open(temp_file.name, "r") as file:
            csv_reader = csv.reader(file)
            csv_data = list(csv_reader)

        self.assertEqual(len(csv_data), 2)
        self.assertIn(
            "registered_users (organization_id, method, is_verified)", csv_data[0]
        )
        self.assertEqual(
            csv_data[1][-1],
            (
                f"({org1_reg_user.organization_id},{org1_reg_user.method},"
                f"{org1_reg_user.is_verified})"
                "\n"
                f"({org2_reg_user.organization_id},{org2_reg_user.method},"
                f"{org2_reg_user.is_verified})"
            ),
        )

    def test_radiususergroup_inline(self):
        """
        Ensures that adding OrganizationUser and default
        RadiusUserGroup (of the same organization) in the same
        transaction does not cause any errors.
        """
        admin = self._create_admin()
        self.client.force_login(admin)
        user = self._create_user()
        org = self._get_org()
        default_radius_group = RadiusGroup.objects.get(organization=org, default=True)
        params = user.__dict__
        params.pop("phone_number")
        params.pop("password", None)
        params.pop("_password", None)
        params.pop("password_based_token", None)
        params.pop("bio", None)
        params.pop("last_login", None)
        params.pop("password_updated", None)
        params.pop("birth_date", None)
        params.pop("expiration_date", None)
        params = self._additional_params_pop(params)
        params.update(self._get_user_edit_form_inline_params(user, org))
        params.update(
            {
                # OrganizationUser inline
                f"{self.app_label}_organizationuser-TOTAL_FORMS": 1,
                f"{self.app_label}_organizationuser-INITIAL_FORMS": 0,
                f"{self.app_label}_organizationuser-MIN_NUM_FORMS": 0,
                f"{self.app_label}_organizationuser-MAX_NUM_FORMS": 1000,
                f"{self.app_label}_organizationuser-0-is_admin": False,
                f"{self.app_label}_organizationuser-0-id": "",
                f"{self.app_label}_organizationuser-0-organization": str(org.pk),
                f"{self.app_label}_organizationuser-0-user": str(user.pk),
                # RadiusUserGroup inline
                "radiususergroup_set-TOTAL_FORMS": 1,
                "radiususergroup_set-INITIAL_FORMS": 0,
                "radiususergroup_set-MIN_NUM_FORMS": 0,
                "radiususergroup_set-MAX_NUM_FORMS": 1000,
                "radiususergroup_set-0-priority": 1,
                "radiususergroup_set-0-id": "",
                "radiususergroup_set-0-group": str(default_radius_group.pk),
                "radiususergroup_set-0-user": str(user.pk),
            }
        )

        url = reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        response = self.client.post(
            url,
            params,
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(user.organizations_dict.keys()), 1)
        self.assertEqual(user.radiususergroup_set.count(), 1)

    def test_registered_user_inline_add_form_organization_field_excludes_disabled_org(
        self,
    ):
        admin_user = self._create_admin()
        user = self._create_user()
        active_org = self._get_org()
        disabled_org = self._create_org(
            name="disabled-registered-user-org", is_active=False
        )
        request = RequestFactory().get(
            reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        )
        request.user = admin_user
        inline = RegisteredUserInline(user.__class__, admin.site)
        formset = inline.get_formset(request, user)
        queryset = formset.form.base_fields["organization"].queryset
        self.assertEqual(queryset.filter(pk=active_org.pk).exists(), True)
        self.assertEqual(queryset.filter(pk=disabled_org.pk).exists(), False)

    def test_registered_user_inline_change_form_readonly_for_disabled_org(self):
        admin_user = self._create_admin()
        user = self._create_user()
        active_org = self._get_org()
        disabled_org = self._create_org(
            name="disabled-registered-user-change-org", is_active=False
        )
        active_registered_user = RegisteredUser.objects.create(
            user=user, organization=active_org, method="email"
        )
        disabled_registered_user = RegisteredUser.objects.create(
            user=user, organization=disabled_org, method="email"
        )
        request = RequestFactory().get(
            reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        )
        request.user = admin_user
        inline = RegisteredUserInline(user.__class__, admin.site)
        formset_class = inline.get_formset(request, user)
        formset = formset_class(instance=user, prefix="registered_users")
        forms_by_pk = {form.instance.pk: form for form in formset.forms}

        with self.subTest("organization is active"):
            form = forms_by_pk[active_registered_user.pk]
            for field_name in ("organization", "method", "is_verified"):
                self.assertEqual(form.fields[field_name].disabled, False)

        with self.subTest("organization is disabled"):
            form = forms_by_pk[disabled_registered_user.pk]
            for field_name in ("organization", "method", "is_verified"):
                self.assertEqual(form.fields[field_name].disabled, True)

    def test_radiususergroup_inline_group_field_excludes_disabled_org(self):
        admin_user = self._create_admin()
        user = self._create_user()
        active_org = self._get_org()
        disabled_org = self._create_org(name="disabled-usergroup-org", is_active=False)
        disabled_group = RadiusGroup.objects.get(
            organization=disabled_org, default=True
        )
        active_group = RadiusGroup.objects.get(organization=active_org, default=True)
        request = RequestFactory().get(
            reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        )
        request.user = admin_user
        inline = RadiusUserGroupInline(user.__class__, admin.site)
        formset = inline.get_formset(request, user)
        queryset = formset.form.base_fields["group"].queryset
        self.assertEqual(queryset.filter(pk=active_group.pk).exists(), True)
        self.assertEqual(queryset.filter(pk=disabled_group.pk).exists(), False)

    def test_radiususergroup_inline_change_form_readonly_for_disabled_org(self):
        admin_user = self._create_admin()
        user = self._create_user()
        active_org = self._get_org()
        disabled_org = self._create_org(
            name="disabled-usergroup-change-org", is_active=False
        )
        active_group = RadiusGroup.objects.get(organization=active_org, default=True)
        disabled_group = RadiusGroup.objects.get(
            organization=disabled_org, default=True
        )
        active_user_group = RadiusUserGroup.objects.create(
            user=user, group=active_group
        )
        disabled_user_group = RadiusUserGroup.objects.create(
            user=user, group=disabled_group
        )
        request = RequestFactory().get(
            reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        )
        request.user = admin_user
        inline = RadiusUserGroupInline(user.__class__, admin.site)
        formset_class = inline.get_formset(request, user)
        formset = formset_class(instance=user, prefix="radiususergroup_set")
        forms_by_pk = {form.instance.pk: form for form in formset.forms}

        with self.subTest("organization is active"):
            form = forms_by_pk[active_user_group.pk]
            for field_name in ("group", "priority"):
                self.assertEqual(form.fields[field_name].disabled, False)

        with self.subTest("organization is disabled"):
            form = forms_by_pk[disabled_user_group.pk]
            for field_name in ("group", "priority"):
                self.assertEqual(form.fields[field_name].disabled, True)

    def test_registered_user_inline_disallows_add_without_active_org(self):
        user = self._create_user()
        org = self._get_org()
        org.is_active = False
        org.save()
        operator = self._create_user(
            username="disabled-org-operator", email="disabled-org-operator@example.com"
        )
        self._create_org_user(user=operator, organization=org, is_admin=True)
        request = RequestFactory().get(
            reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        )
        request.user = operator
        inline = RegisteredUserInline(user.__class__, admin.site)
        self.assertEqual(inline.has_add_permission(request, user), False)

    def test_organization_radius_settings_inline_disabled_organization_readonly(self):
        admin_user = self._create_admin()
        org = self._get_org()
        org.is_active = False
        org.save()
        request = RequestFactory().get(
            reverse(f"admin:{self.app_label}_organization_change", args=[org.pk])
        )
        request.user = admin_user
        inline = OrganizationRadiusSettingsInline(org.__class__, admin.site)
        self.assertEqual(inline.has_add_permission(request, org), False)
        self.assertEqual(inline.has_change_permission(request, org), False)

    def test_user_admin_change_with_disabled_org_registered_user_membership(self):
        admin_user = self._create_admin()
        self.client.force_login(admin_user)
        org = self._create_org(name="disabled-registereduser-membership-org")
        user = self._create_user(
            username="memberofdisabledregistered",
            email="memberofdisabledregistered@example.com",
        )
        registered_user = RegisteredUser.objects.create(
            user=user, organization=org, method="mobile_phone", is_verified=True
        )
        org.is_active = False
        org.save()
        path = reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        inline_prefix = "registered_users"

        params = user.__dict__.copy()
        params["groups"] = []
        params.pop("phone_number", None)
        params.pop("password", None)
        params.pop("_password", None)
        params.pop("password_based_token", None)
        params.pop("bio", None)
        params.pop("last_login", None)
        params.pop("password_updated", None)
        params.pop("birth_date", None)
        params.pop("expiration_date", None)
        params = self._additional_params_pop(params)
        params.update(self._get_user_edit_form_inline_params(user, org))
        params.update(
            {
                f"{self.app_label}_organizationuser-TOTAL_FORMS": 0,
                f"{self.app_label}_organizationuser-INITIAL_FORMS": 0,
                f"{self.app_label}_organizationuser-MIN_NUM_FORMS": 0,
                f"{self.app_label}_organizationuser-MAX_NUM_FORMS": 1000,
            }
        )
        params["first_name"] = "Changed"
        params.update(
            {
                f"{inline_prefix}-TOTAL_FORMS": 1,
                f"{inline_prefix}-INITIAL_FORMS": 1,
                f"{inline_prefix}-MIN_NUM_FORMS": 0,
                f"{inline_prefix}-MAX_NUM_FORMS": 1000,
                f"{inline_prefix}-0-id": str(registered_user.pk),
                f"{inline_prefix}-0-organization": str(org.pk),
                f"{inline_prefix}-0-method": registered_user.method,
                f"{inline_prefix}-0-is_verified": registered_user.is_verified,
            }
        )
        response = self.client.post(path, params, follow=True)
        self.assertNotContains(response, "Please correct the error")
        self.assertNotContains(response, "Select a valid choice")
        user.refresh_from_db()
        self.assertEqual(user.first_name, "Changed")
        registered_user.refresh_from_db()
        self.assertEqual(registered_user.organization_id, org.pk)

    def test_user_admin_no_op_save_with_disabled_org_inline_memberships(self):
        admin_user = self._create_admin()
        self.client.force_login(admin_user)
        org = self._create_org(name="disabled-user-admin-inlines-org")
        group = RadiusGroup.objects.get(organization=org, default=True)
        user = self._create_user(
            username="disabled-org-inlines-user",
            email="disabled-org-inlines-user@example.com",
        )
        registered_user = RegisteredUser.objects.create(
            user=user, organization=org, method="mobile_phone", is_verified=True
        )
        user_group = RadiusUserGroup.objects.create(user=user, group=group)
        org.is_active = False
        org.save()

        params = user.__dict__.copy()
        params["groups"] = []
        params.pop("phone_number", None)
        params.pop("password", None)
        params.pop("_password", None)
        params.pop("password_based_token", None)
        params.pop("bio", None)
        params.pop("last_login", None)
        params.pop("password_updated", None)
        params.pop("birth_date", None)
        params.pop("expiration_date", None)
        params = self._additional_params_pop(params)
        params.update(self._get_user_edit_form_inline_params(user, org))
        params.update(
            {
                f"{self.app_label}_organizationuser-TOTAL_FORMS": 0,
                f"{self.app_label}_organizationuser-INITIAL_FORMS": 0,
                f"{self.app_label}_organizationuser-MIN_NUM_FORMS": 0,
                f"{self.app_label}_organizationuser-MAX_NUM_FORMS": 1000,
            }
        )

        url = reverse(f"admin:{self.app_label}_user_change", args=[user.pk])
        response = self.client.post(url, params, follow=True)
        self.assertNotContains(response, "Please correct the error")
        self.assertNotContains(response, "Select a valid choice")
        registered_user.refresh_from_db()
        user_group.refresh_from_db()
        self.assertEqual(registered_user.organization_id, org.pk)
        self.assertEqual(user_group.group_id, group.pk)


del TestBasicUsersIntegration
