from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework import status

from ...api.serializers import RadiusBatchSerializer
from ...utils import load_model
from ..mixins import ApiTokenMixin, BaseTestCase

RadiusBatch = load_model("RadiusBatch")


class TestBatch(ApiTokenMixin, BaseTestCase):
    def test_batch_list_200(self):
        self._create_radius_batch(
            name="batch-a",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._create_radius_batch(
            name="batch-b",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._superuser_login()
        with self.assertNumQueries(4):
            response = self.client.get(reverse("radius:batch"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json()["count"], 2)

    def test_batch_list_permissions(self):
        self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        with self.subTest("w/o login"):
            response = self.client.get(reverse("radius:batch"))
            self.assertEqual(response.status_code, 401)

        with self.subTest("superuser"):
            self._superuser_login()
            response = self.client.get(reverse("radius:batch"))
            self.assertEqual(response.status_code, 200)

        with self.subTest("staff w/ managed org"):
            staff = self._create_operator(
                organizations=[self.default_org],
                username="liststaff",
                email="liststaff@test.com",
            )
            self.client.force_login(staff)
            response = self.client.get(reverse("radius:batch"))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["count"], 1)

        with self.subTest("staff w/o view permission"):
            staff = self._create_user(
                username="no-view-list", email="no-view-list@test.com", is_staff=True
            )
            self._create_org_user(user=staff, is_admin=True)
            self.client.force_login(staff)
            response = self.client.get(reverse("radius:batch"))
            self.assertEqual(response.status_code, 403)

        with self.subTest("non-staff user"):
            regular = self._create_user(
                username="regular", email="regular@test.com", password="tester"
            )
            self.client.force_login(regular)
            response = self.client.get(reverse("radius:batch"))
            self.assertEqual(response.status_code, 403)

    def test_batch_list_filter_strategy(self):
        self._create_radius_batch(
            name="prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        csv_content = b"user,cleartext$abcd,email@gmail.com,firstname,lastname"
        csv_file = SimpleUploadedFile("filter_test.csv", csv_content)
        self._create_radius_batch(
            name="csv-batch",
            strategy="csv",
            csvfile=csv_file,
            status=RadiusBatch.COMPLETED,
        )
        self._superuser_login()
        url = reverse("radius:batch")
        with self.subTest("filter prefix"):
            response = self.client.get(url, {"strategy": "prefix"})
            names = [b["name"] for b in response.json()["results"]]
            self.assertIn("prefix-batch", names)
            self.assertNotIn("csv-batch", names)

        with self.subTest("filter csv"):
            response = self.client.get(url, {"strategy": "csv"})
            names = [b["name"] for b in response.json()["results"]]
            self.assertIn("csv-batch", names)
            self.assertNotIn("prefix-batch", names)

    def test_batch_list_filter_organization(self):
        org2 = self._create_org(**{"name": "other", "slug": "other"})
        self._create_radius_batch(
            name="org1-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._create_radius_batch(
            name="org2-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
            organization=org2,
        )
        operator = self._create_operator(
            organizations=[self.default_org],
            username="orgfilterstaff",
            email="orgfilterstaff@test.com",
        )
        self.client.force_login(operator)
        url = reverse("radius:batch")

        with self.subTest("filter managed organization"):
            response = self.client.get(url, {"organization": self.default_org.pk})
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(
                [batch["name"] for batch in response.json()["results"]],
                ["org1-batch"],
            )

        with self.subTest("filter managed organization slug"):
            response = self.client.get(
                url, {"organization_slug": self.default_org.slug}
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(
                [batch["name"] for batch in response.json()["results"]],
                ["org1-batch"],
            )

        with self.subTest("filter unmanaged organization"):
            response = self.client.get(url, {"organization": org2.pk})
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        with self.subTest("filter unmanaged organization slug"):
            response = self.client.get(url, {"organization_slug": org2.slug})
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.json()["results"], [])

    def test_batch_list_search_name(self):
        self._create_radius_batch(
            name="alpha-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._create_radius_batch(
            name="beta-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._superuser_login()
        response = self.client.get(
            reverse("radius:batch"),
            {"search": "alpha"},
        )
        names = [b["name"] for b in response.json()["results"]]
        self.assertIn("alpha-batch", names)
        self.assertNotIn("beta-batch", names)

    def test_batch_list_no_user_credentials(self):
        self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._superuser_login()
        response = self.client.get(reverse("radius:batch"))
        batch_data = response.json()["results"][0]
        self.assertNotIn("user_credentials", batch_data)
        self.assertNotIn("users", batch_data)

    def test_batch_browsable_api_form_scopes_relation_options(self):
        other_org = self._create_org(name="other organization", slug="other-org")
        group = self._create_radius_group(name="managed")
        other_group = self._create_radius_group(
            name="unmanaged", organization=other_org
        )
        operator = self._create_operator(
            organizations=[self.default_org],
            username="batch-form-operator",
            email="batch-form-operator@test.com",
        )
        operator.user_permissions.add(
            Permission.objects.get(codename="add_radiusbatch")
        )
        self.client.force_login(operator)
        response = self.client.get(reverse("radius:batch"), HTTP_ACCEPT="text/html")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        content = response.content.decode()
        self.assertIn('name="organization_slug"', content)
        self.assertIn("Radius group", content)
        self.assertIn(f'value="{self.default_org.slug}"', content)
        self.assertNotIn(f'value="{other_org.slug}"', content)
        self.assertIn(f'value="{group.pk}"', content)
        self.assertNotIn(f'value="{other_group.pk}"', content)
        serializer = RadiusBatchSerializer(context={"request": response.wsgi_request})
        self.assertEqual(serializer.fields["organization_slug"].html_cutoff, 100)
        self.assertEqual(serializer.fields["group"].html_cutoff, 100)

    def test_batch_list_exposes_download_links(self):
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._superuser_login()
        response = self.client.get(reverse("radius:batch"))
        batch_data = response.json()["results"][0]
        self.assertIsNotNone(batch_data["pdf_link"])
        self.assertIn(str(batch.pk), batch_data["pdf_link"])
        self.assertIsNone(batch_data["csv_link"])

    def test_batch_csv_link_in_list_and_detail(self):
        csv_content = b"user,cleartext$abcd,email@gmail.com,firstname,lastname"
        csv_file = SimpleUploadedFile("test_csv_link.csv", csv_content)
        batch = self._create_radius_batch(
            name="csv-link-test",
            strategy="csv",
            csvfile=csv_file,
            status=RadiusBatch.COMPLETED,
        )
        self._superuser_login()
        with self.subTest("list"):
            resp = self.client.get(reverse("radius:batch"))
            batch_data = resp.json()["results"][0]
            self.assertIsNotNone(batch_data["csv_link"])
            self.assertIn(str(batch.pk), batch_data["csv_link"])
            self.assertIsNone(batch_data["pdf_link"])
            response = self.client.get(batch_data["csv_link"])
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        with self.subTest("detail"):
            resp = self.client.get(
                reverse("radius:radius_batch_detail", args=[batch.pk]),
            )
            data = resp.json()
            self.assertIsNotNone(data["csv_link"])
            self.assertIn(str(batch.pk), data["csv_link"])

    def test_batch_detail_200(self):
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        self._superuser_login()
        url = reverse("radius:radius_batch_detail", args=[batch.pk])
        with self.assertNumQueries(4):
            response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["id"], str(batch.pk))
        self.assertEqual(data["name"], "test-prefix-batch")
        self.assertEqual(data["strategy"], "prefix")
        self.assertEqual(data["status"], RadiusBatch.COMPLETED)
        self.assertNotIn("user_credentials", data)
        self.assertIsNotNone(data["pdf_link"])
        self.assertEqual(list(data)[-3:], ["users", "created", "modified"])

    def test_batch_detail_permissions(self):
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        with self.subTest("w/o login"):
            response = self.client.get(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 401)

        with self.subTest("superuser"):
            self._superuser_login()
            response = self.client.get(
                reverse("radius:radius_batch_detail", args=[batch.pk]),
            )
            self.assertEqual(response.status_code, 200)

        with self.subTest("staff w/ managed org"):
            staff = self._create_operator(
                organizations=[self.default_org],
                username="detailstaff",
                email="detailstaff@test.com",
            )
            self.client.force_login(staff)
            response = self.client.get(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 200)

        with self.subTest("staff w/o view permission"):
            staff = self._create_user(
                username="no-view-detail",
                email="no-view-detail@test.com",
                is_staff=True,
            )
            self._create_org_user(user=staff, is_admin=True)
            self.client.force_login(staff)
            response = self.client.get(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 403)

        with self.subTest("staff w/o managed org"):
            org2 = self._create_org(**{"name": "other", "slug": "other"})
            no_org_staff = self._create_operator(
                organizations=[org2],
                username="noorgstaff",
                email="noorgstaff@test.com",
            )
            self.client.force_login(no_org_staff)
            response = self.client.get(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 404)

    def test_batch_detail_cross_org_404(self):
        org2 = self._create_org(**{"name": "other", "slug": "other"})
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
            organization=org2,
        )
        staff = self._create_operator(
            organizations=[self.default_org],
            username="crossorgstaff",
            email="crossorgstaff@test.com",
        )
        self.client.force_login(staff)
        url = reverse("radius:radius_batch_detail", args=[batch.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_batch_detail_404(self):
        self._superuser_login()
        url = reverse(
            "radius:radius_batch_detail",
            args=["00000000-0000-0000-0000-000000000000"],
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_batch_delete_204(self):
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        batch_id = batch.pk
        self._superuser_login()
        url = reverse("radius:radius_batch_detail", args=[batch_id])
        with self.assertNumQueries(9):
            response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(RadiusBatch.objects.filter(pk=batch_id).exists())

    def test_batch_delete_permissions(self):
        operator = self._create_operator(
            organizations=[self.default_org],
            username="deletestaff",
            email="deletestaff@test.com",
        )
        administrator = self._create_administrator(
            organizations=[self.default_org],
            username="deletadmin",
            email="deletadmin@test.com",
        )
        with self.subTest("w/o login"):
            batch = self._create_radius_batch(
                name="batch-noauth",
                strategy="prefix",
                prefix="test",
                status=RadiusBatch.COMPLETED,
            )
            response = self.client.delete(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 401)

        with self.subTest("superuser"):
            batch = self._create_radius_batch(
                name="batch-super",
                strategy="prefix",
                prefix="test",
                status=RadiusBatch.COMPLETED,
            )
            self._superuser_login()
            response = self.client.delete(
                reverse("radius:radius_batch_detail", args=[batch.pk]),
            )
            self.assertEqual(response.status_code, 204)

        with self.subTest("operator w/o delete permission"):
            batch = self._create_radius_batch(
                name="batch-noperm",
                strategy="prefix",
                prefix="test",
                status=RadiusBatch.COMPLETED,
            )
            self.client.force_login(operator)
            response = self.client.delete(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 403)

        with self.subTest("administrator w/ delete permission"):
            batch = self._create_radius_batch(
                name="batch-withperm",
                strategy="prefix",
                prefix="test",
                status=RadiusBatch.COMPLETED,
            )
            self.client.force_login(administrator)
            response = self.client.delete(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            self.assertEqual(response.status_code, 204)

    def test_batch_delete_processing_409(self):
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        batch.status = RadiusBatch.PROCESSING
        batch.save(update_fields=["status"])
        self._superuser_login()
        url = reverse("radius:radius_batch_detail", args=[batch.pk])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(
            response.json()["detail"],
            "The radius batch object is currently being processed and cannot be "
            "deleted.",
        )
        self.assertTrue(RadiusBatch.objects.filter(pk=batch.pk).exists())

    def test_batch_delete_cross_org_404(self):
        org2 = self._create_org(**{"name": "other", "slug": "other"})
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
            organization=org2,
        )
        administrator = self._create_administrator(
            organizations=[self.default_org],
            username="delcrossorg",
            email="delcrossorg@test.com",
        )
        self.client.force_login(administrator)
        url = reverse("radius:radius_batch_detail", args=[batch.pk])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(RadiusBatch.objects.filter(pk=batch.pk).exists())

    def test_batch_delete_pending_and_failed_allowed(self):
        for batch_status in [RadiusBatch.PENDING, RadiusBatch.FAILED]:
            with self.subTest(status=batch_status):
                batch = self._create_radius_batch(
                    name=f"batch-{batch_status}",
                    strategy="prefix",
                    prefix="test",
                    status=batch_status,
                )
                self._superuser_login()
                url = reverse("radius:radius_batch_detail", args=[batch.pk])
                response = self.client.delete(url)
                self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
                self.assertFalse(RadiusBatch.objects.filter(pk=batch.pk).exists())

    def test_batch_read_metadata(self):
        group = self._create_radius_group(
            name="test-group", organization=self.default_org
        )
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
            group=group,
            notes="Internal notes",
        )
        self._superuser_login()

        with self.subTest("list"):
            response = self.client.get(reverse("radius:batch"))
            data = response.json()["results"][0]
            self.assertEqual(data["group"], str(group.pk))
            self.assertEqual(data["notes"], batch.notes)

        with self.subTest("detail"):
            response = self.client.get(
                reverse("radius:radius_batch_detail", args=[batch.pk])
            )
            data = response.json()
            self.assertEqual(data["group"], str(group.pk))
            self.assertEqual(data["notes"], batch.notes)

    def test_batch_detail_paginates_users(self):
        batch = self._create_radius_batch(
            name="test-prefix-batch",
            strategy="prefix",
            prefix="test",
            status=RadiusBatch.COMPLETED,
        )
        User = get_user_model()
        # The response only serializes these fields, so save hooks are unnecessary.
        users = User.objects.bulk_create(
            [
                User(
                    username=f"batch-user-{number}",
                    email=f"batch-user-{number}@test.com",
                )
                for number in range(101)
            ]
        )
        batch.users.add(*users)
        self._superuser_login()
        url = reverse("radius:radius_batch_detail", args=[batch.pk])

        with self.subTest("first page"):
            with self.assertNumQueries(5):
                response = self.client.get(url)
            users = response.json()["users"]
            self.assertEqual(users["count"], 101)
            self.assertEqual(len(users["results"]), 100)
            self.assertIn("page=2", users["next"])
            self.assertIsNone(users["previous"])

        with self.subTest("second page"):
            response = self.client.get(url, {"page": 2})
            users = response.json()["users"]
            self.assertEqual(len(users["results"]), 1)
            self.assertIsNone(users["next"])
            self.assertIsNotNone(users["previous"])

        with self.subTest("custom page size"):
            with self.assertNumQueries(5):
                response = self.client.get(url, {"page_size": 1, "page": 2})
            users = response.json()["users"]
            self.assertEqual(len(users["results"]), 1)
            self.assertIn("page=3", users["next"])
            self.assertIn("page_size=1", users["next"])
