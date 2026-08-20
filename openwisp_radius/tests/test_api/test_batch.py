import swapper
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework import status

from ...utils import load_model
from ..mixins import ApiTokenMixin, BaseTestCase

User = get_user_model()
RadiusBatch = load_model("RadiusBatch")
OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")


class TestBatch(ApiTokenMixin, BaseTestCase):
    def _get_auth_header(self, username="admin", password="tester"):
        if username == "admin":
            self._get_admin()
        login_payload = {"username": username, "password": password}
        login_url = reverse("radius:user_auth_token", args=[self.default_org.slug])
        login_response = self.client.post(login_url, data=login_payload)
        return f"Bearer {login_response.json()['key']}"

    def _create_prefix_batch(self, name="test-prefix-batch", organization=None):
        if organization is None:
            organization = self.default_org
        batch = RadiusBatch(
            name=name,
            strategy="prefix",
            prefix="test",
            organization=organization,
            status=RadiusBatch.COMPLETED,
        )
        batch.save()
        return batch

    def _create_staff_user(self, username="staffuser", org=None):
        user = User.objects.create_user(
            username=username,
            email=f"{username}@test.com",
            password="tester",
            is_staff=True,
            is_superuser=False,
        )
        if org:
            OrganizationUser.objects.create(user=user, organization=org, is_admin=True)
        return user

    def test_batch_list_200(self):
        self._create_prefix_batch(name="batch-a")
        self._create_prefix_batch(name="batch-b")
        header = self._get_auth_header()
        response = self.client.get(reverse("radius:batch"), HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["count"], 2)

    def test_batch_list_permissions(self):
        self._get_admin()
        staff = self._create_staff_user("liststaff", org=self.default_org)
        self._create_prefix_batch()
        with self.subTest("w/o login"):
            response = self.client.get(reverse("radius:batch"))
            self.assertEqual(response.status_code, 401)
        with self.subTest("superuser"):
            header = self._get_auth_header()
            response = self.client.get(
                reverse("radius:batch"), HTTP_AUTHORIZATION=header
            )
            self.assertEqual(response.status_code, 200)
        with self.subTest("staff w/ managed org"):
            header = self._get_auth_header(staff.username, "tester")
            response = self.client.get(
                reverse("radius:batch"), HTTP_AUTHORIZATION=header
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["count"], 1)
        with self.subTest("non-staff user"):
            regular = User.objects.create_user(
                username="regular", email="regular@test.com", password="tester"
            )
            header = self._get_auth_header(regular.username, "tester")
            response = self.client.get(
                reverse("radius:batch"), HTTP_AUTHORIZATION=header
            )
            self.assertEqual(response.status_code, 403)

    def test_batch_list_filter_strategy(self):
        self._create_prefix_batch(name="prefix-batch")
        RadiusBatch.objects.create(
            name="csv-batch",
            strategy="csv",
            organization=self.default_org,
            status=RadiusBatch.COMPLETED,
        )
        header = self._get_auth_header()
        url = reverse("radius:batch")
        with self.subTest("filter prefix"):
            response = self.client.get(
                url, {"strategy": "prefix"}, HTTP_AUTHORIZATION=header
            )
            names = [b["name"] for b in response.json()["results"]]
            self.assertIn("prefix-batch", names)
            self.assertNotIn("csv-batch", names)
        with self.subTest("filter csv"):
            response = self.client.get(
                url, {"strategy": "csv"}, HTTP_AUTHORIZATION=header
            )
            names = [b["name"] for b in response.json()["results"]]
            self.assertIn("csv-batch", names)
            self.assertNotIn("prefix-batch", names)

    def test_batch_list_search_name(self):
        self._create_prefix_batch(name="alpha-batch")
        self._create_prefix_batch(name="beta-batch")
        header = self._get_auth_header()
        response = self.client.get(
            reverse("radius:batch"),
            {"search": "alpha"},
            HTTP_AUTHORIZATION=header,
        )
        names = [b["name"] for b in response.json()["results"]]
        self.assertIn("alpha-batch", names)
        self.assertNotIn("beta-batch", names)

    def test_batch_list_no_user_credentials(self):
        self._create_prefix_batch()
        header = self._get_auth_header()
        response = self.client.get(reverse("radius:batch"), HTTP_AUTHORIZATION=header)
        batch_data = response.json()["results"][0]
        self.assertNotIn("user_credentials", batch_data)

    def test_batch_list_exposes_download_links(self):
        batch = self._create_prefix_batch()
        header = self._get_auth_header()
        response = self.client.get(reverse("radius:batch"), HTTP_AUTHORIZATION=header)
        batch_data = response.json()["results"][0]
        self.assertIsNotNone(batch_data["pdf_link"])
        self.assertIn(str(batch.pk), batch_data["pdf_link"])
        self.assertIsNone(batch_data["csv_link"])

    def test_batch_csv_link_in_list_and_detail(self):
        csv_content = b"user,cleartext$abcd,email@gmail.com,firstname,lastname"
        csv_file = SimpleUploadedFile("test_csv_link.csv", csv_content)
        batch = RadiusBatch(
            name="csv-link-test",
            strategy="csv",
            csvfile=csv_file,
            organization=self.default_org,
            status=RadiusBatch.COMPLETED,
        )
        batch.save()
        header = self._get_auth_header()
        with self.subTest("list"):
            resp = self.client.get(reverse("radius:batch"), HTTP_AUTHORIZATION=header)
            batch_data = resp.json()["results"][0]
            self.assertIsNotNone(batch_data["csv_link"])
            self.assertIn(str(batch.pk), batch_data["csv_link"])
            self.assertIsNone(batch_data["pdf_link"])
        with self.subTest("detail"):
            resp = self.client.get(
                reverse("radius:batch_detail", args=[batch.pk]),
                HTTP_AUTHORIZATION=header,
            )
            data = resp.json()
            self.assertIsNotNone(data["csv_link"])
            self.assertIn(str(batch.pk), data["csv_link"])

    def test_batch_detail_200(self):
        batch = self._create_prefix_batch()
        header = self._get_auth_header()
        url = reverse("radius:batch_detail", args=[batch.pk])
        response = self.client.get(url, HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["id"], str(batch.pk))
        self.assertEqual(data["name"], "test-prefix-batch")
        self.assertEqual(data["strategy"], "prefix")
        self.assertEqual(data["status"], RadiusBatch.COMPLETED)
        self.assertNotIn("user_credentials", data)
        self.assertIsNotNone(data["pdf_link"])

    def test_batch_detail_permissions(self):
        self._get_admin()
        staff = self._create_staff_user("detailstaff", org=self.default_org)
        batch = self._create_prefix_batch()
        with self.subTest("w/o login"):
            response = self.client.get(reverse("radius:batch_detail", args=[batch.pk]))
            self.assertEqual(response.status_code, 401)
        with self.subTest("superuser"):
            header = self._get_auth_header()
            response = self.client.get(
                reverse("radius:batch_detail", args=[batch.pk]),
                HTTP_AUTHORIZATION=header,
            )
            self.assertEqual(response.status_code, 200)
        with self.subTest("staff w/ managed org"):
            header = self._get_auth_header(staff.username, "tester")
            response = self.client.get(
                reverse("radius:batch_detail", args=[batch.pk]),
                HTTP_AUTHORIZATION=header,
            )
            self.assertEqual(response.status_code, 200)
        with self.subTest("staff w/o managed org"):
            no_org_staff = self._create_staff_user("noorgstaff")
            header = self._get_auth_header(no_org_staff.username, "tester")
            response = self.client.get(
                reverse("radius:batch_detail", args=[batch.pk]),
                HTTP_AUTHORIZATION=header,
            )
            self.assertEqual(response.status_code, 404)

    def test_batch_detail_cross_org_404(self):
        org2 = self._create_org(**{"name": "other", "slug": "other"})
        batch = self._create_prefix_batch(organization=org2)
        staff = self._create_staff_user("crossorgstaff", org=self.default_org)
        header = self._get_auth_header(staff.username, "tester")
        url = reverse("radius:batch_detail", args=[batch.pk])
        response = self.client.get(url, HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, 404)

    def test_batch_detail_404(self):
        header = self._get_auth_header()
        url = reverse(
            "radius:batch_detail",
            args=["00000000-0000-0000-0000-000000000000"],
        )
        response = self.client.get(url, HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, 404)

    def test_batch_delete_204(self):
        batch = self._create_prefix_batch()
        batch_id = batch.pk
        header = self._get_auth_header()
        url = reverse("radius:batch_detail", args=[batch_id])
        response = self.client.delete(url, HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(RadiusBatch.objects.filter(pk=batch_id).exists())

    def test_batch_delete_permissions(self):
        self._get_admin()
        staff = self._create_staff_user("deletestaff", org=self.default_org)
        delete_perm = Permission.objects.get(codename="delete_radiusbatch")
        with self.subTest("w/o login"):
            batch = self._create_prefix_batch(name="batch-noauth")
            response = self.client.delete(
                reverse("radius:batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 401)
        with self.subTest("superuser"):
            batch = self._create_prefix_batch(name="batch-super")
            header = self._get_auth_header()
            response = self.client.delete(
                reverse("radius:batch_detail", args=[batch.pk]),
                HTTP_AUTHORIZATION=header,
            )
            self.assertEqual(response.status_code, 204)
        with self.subTest("staff w/o delete permission"):
            batch = self._create_prefix_batch(name="batch-noperm")
            header = self._get_auth_header(staff.username, "tester")
            response = self.client.delete(
                reverse("radius:batch_detail", args=[batch.pk]),
                HTTP_AUTHORIZATION=header,
            )
            self.assertEqual(response.status_code, 403)
        with self.subTest("staff w/ delete permission"):
            batch = self._create_prefix_batch(name="batch-withperm")
            staff.user_permissions.add(delete_perm)
            header = self._get_auth_header(staff.username, "tester")
            response = self.client.delete(
                reverse("radius:batch_detail", args=[batch.pk]),
                HTTP_AUTHORIZATION=header,
            )
            self.assertEqual(response.status_code, 204)

    def test_batch_delete_processing_409(self):
        batch = self._create_prefix_batch()
        batch.status = RadiusBatch.PROCESSING
        batch.save(update_fields=["status"])
        header = self._get_auth_header()
        url = reverse("radius:batch_detail", args=[batch.pk])
        response = self.client.delete(url, HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertTrue(RadiusBatch.objects.filter(pk=batch.pk).exists())

    def test_batch_delete_cross_org_404(self):
        org2 = self._create_org(**{"name": "other", "slug": "other"})
        batch = self._create_prefix_batch(organization=org2)
        staff = self._create_staff_user("delcrossorg", org=self.default_org)
        delete_perm = Permission.objects.get(codename="delete_radiusbatch")
        staff.user_permissions.add(delete_perm)
        header = self._get_auth_header(staff.username, "tester")
        url = reverse("radius:batch_detail", args=[batch.pk])
        response = self.client.delete(url, HTTP_AUTHORIZATION=header)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(RadiusBatch.objects.filter(pk=batch.pk).exists())

    def test_batch_delete_pending_and_failed_allowed(self):
        for batch_status in [RadiusBatch.PENDING, RadiusBatch.FAILED]:
            with self.subTest(status=batch_status):
                batch = self._create_prefix_batch(name=f"batch-{batch_status}")
                batch.status = batch_status
                batch.save(update_fields=["status"])
                header = self._get_auth_header()
                url = reverse("radius:batch_detail", args=[batch.pk])
                response = self.client.delete(url, HTTP_AUTHORIZATION=header)
                self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
                self.assertFalse(RadiusBatch.objects.filter(pk=batch.pk).exists())
