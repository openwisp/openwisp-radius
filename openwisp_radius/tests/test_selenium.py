from django.contrib.auth import get_user_model
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select

from openwisp_users.tests.utils import TestOrganizationMixin
from openwisp_utils.tests.selenium import SeleniumTestMixin

from ..utils import load_model
from . import FileMixin

User = get_user_model()

OrganizationRadiusSettings = load_model("OrganizationRadiusSettings")


class BasicTest(
    SeleniumTestMixin, FileMixin, StaticLiveServerTestCase, TestOrganizationMixin
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
            "//li[contains(@class, 'select2-results__option') and "
            "text()='test org']",
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
            "//li[contains(@class, 'select2-results__option') and "
            "text()='test org']",
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
            "//li[contains(@class, 'select2-results__option') and "
            "text()='test org']",
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
            "//li[contains(@class, 'select2-results__option') and "
            "text()='test org']",
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
