import pytest
from channels.testing import ChannelsLiveServerTestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.test import tag
from django.urls import reverse
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import Select, WebDriverWait

from openwisp_radius import tasks
from openwisp_utils.tests.selenium import SeleniumTestMixin

from ..utils import load_model
from . import CreateRadiusObjectsMixin, FileMixin

User = get_user_model()

OrganizationRadiusSettings = load_model("OrganizationRadiusSettings")
RadiusGroup = load_model("RadiusGroup")


@tag("selenium_tests")
@tag("no_parallel")
class BasicTest(
    SeleniumTestMixin, FileMixin, CreateRadiusObjectsMixin, StaticLiveServerTestCase
):
    # Test case for batch user creation
    def test_batch_user_creation(self):
        """Test the batch user creation feature"""
        org = self._create_org()
        # add org to OrganizationRadiusSettings to avoid non related obj err
        OrganizationRadiusSettings.objects.create(organization=org)
        self.login()  # Log into the admin interface

        # Navigate to the radius batch creation page
        self.open(reverse("admin:openwisp_radius_radiusbatch_add"))

        # Set user strategy for batch creation to 'prefix'
        dropdown = self.wait_for_visibility(By.ID, "id_strategy", 10)
        select = Select(dropdown)
        select.select_by_value("prefix")

        # Fill in the batch details
        self.find_element(By.ID, "id_name", 10).send_keys("Test Batch")
        prefix_field = self.find_element(By.ID, "id_prefix")
        prefix_field.send_keys("test-user-")  # Set a prefix for users to be generated
        organization = self.find_element(By.ID, "select2-id_organization-container", 10)
        organization.click()

        # Select the previously created organization
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and text()='test org']",
            10,
        )
        option.click()

        # Set the number of users to be generated
        self.find_element(By.ID, "id_number_of_users").send_keys("5")

        # Submit the form to create the users
        self.find_element(By.CSS_SELECTOR, "input[type=submit]", 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        # Check if the generated users are listed
        queryset = User.objects.filter(username__startswith="test-user-")
        self.assertEqual(queryset.count(), 5)

    def test_standard_csv_import(self):
        """Test standard user import from CSV with all fields provided"""
        org = self._create_org()
        # add org to OrganizationRadiusSettings to avoid non related obj err
        OrganizationRadiusSettings.objects.create(organization=org)
        self.login()  # Log into the admin interface

        # Get the path of the CSV file for user import
        csv_file = self._get_path("static/selenium/test_standard_csv_import.csv")

        # Navigate to radius batch creation page
        self.open(reverse("admin:openwisp_radius_radiusbatch_add"))

        # Set strategy to CSV for importing users
        dropdown = self.find_element(By.ID, "id_strategy", 10)
        select = Select(dropdown)
        select.select_by_value("csv")

        # Select the organization to associate with the users
        organization = self.find_element(By.ID, "select2-id_organization-container", 10)
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and text()='test org']",
            10,
        )
        option.click()

        # Set batch name and upload CSV file for user import
        self.find_element(By.ID, "id_name", 10).send_keys("Test Batch")
        csv_file_input = self.find_element(By.ID, "id_csvfile", 10)
        csv_file_input.send_keys(csv_file)

        # Submit the form to start the import
        self.find_element(By.CSS_SELECTOR, "input[type=submit]", 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        # Verify that users from the CSV file were created
        queryset = User.objects.filter(username__startswith="user")
        self.assertEqual(queryset.count(), 2)

    def test_import_with_hashed_passwords(self):
        """Test user import with Django-formatted hashed passwords"""
        org = self._create_org()
        # add org to OrganizationRadiusSettings to avoid non related obj err
        OrganizationRadiusSettings.objects.create(organization=org)
        self.login()  # Log into the admin interface

        # Get the path of the CSV file with hashed passwords
        csv_file = self._get_path(
            "static/selenium/test_import_with_hashed_passwords.csv"
        )

        # Navigate to radius batch creation page
        self.open(reverse("admin:openwisp_radius_radiusbatch_add"))

        # Set strategy to CSV for importing users
        dropdown = self.find_element(By.ID, "id_strategy", 10)
        select = Select(dropdown)
        select.select_by_value("csv")

        # Set batch name and select the organization
        self.find_element(By.ID, "id_name", 10).send_keys("Hashed Password Import Test")
        organization = self.find_element(By.ID, "select2-id_organization-container", 10)
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and text()='test org']",
            10,
        )
        option.click()

        # Upload the CSV file with hashed passwords
        csv_file_input = self.find_element(By.ID, "id_csvfile", 10)
        csv_file_input.send_keys(csv_file)

        # Submit the form to import users
        self.find_element(By.CSS_SELECTOR, "input[type=submit]", 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        # Verify that users with hashed passwords are created
        queryset = User.objects.filter(username__startswith="hash_user")
        self.assertEqual(queryset.count(), 2)

    def test_csv_user_generation(self):
        """Test user generation with CSV upload"""
        org = self._create_org()
        # add org to OrganizationRadiusSettings to avoid non related obj err
        OrganizationRadiusSettings.objects.create(organization=org)
        self.login()  # Log into the admin interface

        # Get the path of the CSV file
        csv_file = self._get_path("static/selenium/test_csv_user_generation.csv")

        # Navigate to radius batch creation page
        self.open(reverse("admin:openwisp_radius_radiusbatch_add"))

        # Set strategy to 'csv' for user generation
        dropdown = self.find_element(By.ID, "id_strategy", 10)
        select = Select(dropdown)
        select.select_by_value("csv")

        # Select the organization and upload the CSV
        organization = self.find_element(By.ID, "select2-id_organization-container", 10)
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and text()='test org']",
            10,
        )
        option.click()

        self.find_element(By.ID, "id_name", 10).send_keys("CSV Test")
        csv_file_input = self.find_element(By.ID, "id_csvfile", 10)
        csv_file_input.send_keys(csv_file)

        # Submit the form to generate users via CSV upload
        self.find_element(By.CSS_SELECTOR, "input[type=submit]", 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        # Verify that the users were created
        queryset = User.objects.filter(username__startswith="csv-user")
        self.assertEqual(queryset.count(), 3)

    def test_batch_default_group_selection(self):
        organization = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=organization)
        group = RadiusGroup.objects.get(organization=organization, default=True)
        self.login()
        self.open(reverse("admin:openwisp_radius_radiusbatch_add"))
        WebDriverWait(self.web_driver, 10).until(
            expected_conditions.invisibility_of_element_located(
                (By.CSS_SELECTOR, ".form-row.field-group")
            )
        )
        self.assertFalse(
            self.web_driver.find_element(
                By.CSS_SELECTOR, ".form-row.field-notes"
            ).is_displayed()
        )
        Select(self.find_element(By.ID, "id_strategy", 10)).select_by_value("prefix")
        WebDriverWait(self.web_driver, 10).until(
            expected_conditions.visibility_of_element_located(
                (By.CSS_SELECTOR, ".form-row.field-group")
            )
        )
        self.assertTrue(
            self.find_element(
                By.CSS_SELECTOR, ".form-row.field-notes", 10
            ).is_displayed()
        )
        organization_field = self.find_element(
            By.ID, "select2-id_organization-container", 10
        )
        organization_field.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and text()='test org']",
            10,
        )
        option.click()
        WebDriverWait(self.web_driver, 10).until(
            lambda driver: (
                driver.find_element(By.ID, "id_group").get_attribute("value")
                == str(group.pk)
            )
        )
        self.assertEqual(self.get_browser_errors(), [])

    def test_batch_group_preserved_after_validation_error(self):
        organization = self._create_org()
        OrganizationRadiusSettings.objects.create(organization=organization)
        group = RadiusGroup.objects.create(name="guests", organization=organization)
        self.login()
        self.open(reverse("admin:openwisp_radius_radiusbatch_add"))
        Select(self.find_element(By.ID, "id_strategy", 10)).select_by_value("prefix")
        organization_field = self.find_element(
            By.ID, "select2-id_organization-container", 10
        )
        organization_field.click()
        self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and text()='test org']",
            10,
        ).click()
        WebDriverWait(self.web_driver, 10).until(
            lambda driver: driver.find_element(By.ID, "id_group").get_attribute("value")
        )
        self.web_driver.execute_script(
            "django.jQuery('#id_group')"
            ".append(new Option(arguments[1], arguments[0], true, true))"
            ".trigger('change');",
            str(group.pk),
            str(group),
        )
        self.find_element(By.ID, "id_name", 10).send_keys("Test batch")
        self.find_element(By.ID, "id_prefix", 10).send_keys("test-prefix")
        self.find_element(By.CSS_SELECTOR, "input[type=submit]", 10).click()
        WebDriverWait(self.web_driver, 10).until(
            expected_conditions.presence_of_element_located(
                (By.CSS_SELECTOR, ".errorlist")
            )
        )
        WebDriverWait(self.web_driver, 10).until(
            lambda driver: driver.execute_script("return django.jQuery.active === 0")
        )
        WebDriverWait(self.web_driver, 10).until(
            lambda driver: (
                driver.find_element(By.ID, "id_group").get_attribute("value")
                == str(group.pk)
            )
        )
        self.assertEqual(self.get_browser_errors(), [])

    def test_view_only_change_page_shows_readonly_fields(self):
        org = self._get_org()
        check = self._create_radius_check(
            username="tester", attribute="NT-Password", value="Cam0_liX"
        )
        reply = self._create_radius_reply(
            username="tester", attribute="Reply-Message", value="hi"
        )
        # TransactionTestCase subclasses flush the database between
        # tests, deleting the "Operator" group created by data
        # migrations; _create_operator() would then assign no
        # permissions at all and the change pages would return
        # 403 Forbidden
        user = self._create_user(
            username="viewonly", email="viewonly@example.com", is_staff=True
        )
        user.user_permissions.add(
            *Permission.objects.filter(
                codename__in=("view_radiuscheck", "view_radiusreply")
            )
        )
        self._create_org_user(organization=org, user=user, is_admin=True)
        self.web_driver.delete_all_cookies()
        self.login(username=user.username, password="tester")
        for url, expected_value in (
            (
                reverse(
                    f"admin:{check._meta.app_label}_{check._meta.model_name}_change",
                    args=[check.pk],
                ),
                "Cam0_liX",
            ),
            (
                reverse(
                    f"admin:{reply._meta.app_label}_{reply._meta.model_name}_change",
                    args=[reply.pk],
                ),
                "hi",
            ),
        ):
            with self.subTest(url=url):
                self.open(url)
                value_row = self.wait_for_visibility(
                    By.CSS_SELECTOR, ".form-row.field-value", 10
                )
                self.assertIn(expected_value, value_row.text)
                self.assertFalse(
                    self.find_element(
                        By.CSS_SELECTOR, ".form-row.field-mode", 10, wait_for="presence"
                    ).is_displayed()
                )


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
@tag("selenium_tests")
@tag("no_parallel")
class TestRadiusBatchWebSockets(
    SeleniumTestMixin,
    CreateRadiusObjectsMixin,
    FileMixin,
    ChannelsLiveServerTestCase,
):
    def setUp(self):
        super().setUp()
        self.org = self._create_org()
        self.login()

    def test_batch_change_view_reloads_on_status_update(self):
        batch = self._create_radius_batch(
            name="websocket-test-batch",
            strategy="prefix",
            prefix="ws-test-",
            organization=self.org,
            status="processing",
        )
        change_url = reverse(
            "admin:openwisp_radius_radiusbatch_change", args=[batch.pk]
        )
        self.open(change_url)
        processing_message_element = self.wait_for_visibility(
            By.CSS_SELECTOR, ".messagelist .warning", 10
        )
        self.assertIn("Processing:", processing_message_element.text)
        tasks.process_radius_batch(batch.pk, number_of_users=0)
        WebDriverWait(self.web_driver, 10).until(
            expected_conditions.staleness_of(processing_message_element)
        )
        status_field = (By.CSS_SELECTOR, "div.field-status .readonly")
        WebDriverWait(self.web_driver, 10).until(
            expected_conditions.text_to_be_present_in_element(status_field, "Completed")
        )
        self.assertEqual(self.get_browser_errors(), [])
