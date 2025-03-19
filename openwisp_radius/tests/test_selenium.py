from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select

from openwisp_users.tests.utils import TestOrganizationMixin
from openwisp_utils.tests.selenium import SeleniumTestMixin

from . import FileMixin


class BasicTest(
    SeleniumTestMixin, FileMixin, StaticLiveServerTestCase, TestOrganizationMixin
):

    # Test case for batch user creation
    def test_batch_user_creation(self):
        """Test the batch user creation feature"""
        self.login()  # Log into the admin interface

        # Navigate to the organization creation page
        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, 'id_name', 10).send_keys(
            'Test Batch'
        )  # Create an organization named 'Test Batch'
        self.find_element(
            By.CSS_SELECTOR, 'input[type=submit]'
        ).click()  # Submit the form

        # Navigate to the radius batch creation page
        self.open(reverse('admin:openwisp_radius_radiusbatch_add'))

        # Set user strategy for batch creation to 'prefix'
        dropdown = self.wait_for_visibility(By.ID, 'id_strategy', 10)
        select = Select(dropdown)
        select.select_by_value('prefix')

        # Fill in the batch details
        self.find_element(By.ID, 'id_name', 10).send_keys('Test Batch')
        prefix_field = self.find_element(By.ID, 'id_prefix')
        prefix_field.clear()
        prefix_field.send_keys('test-user-')  # Set a prefix for users to be generated
        organization = self.find_element(By.ID, 'select2-id_organization-container', 10)
        organization.click()

        # Select the previously created organization
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
            10,
        )
        option.click()

        # Set the number of users to be generated
        self.find_element(By.ID, 'id_number_of_users').send_keys('5')

        # Submit the form to create the users
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, 'success', 10)
        self.assertIn('was added successfully', success_message.text)

        # Check if the generated users are listed
        self.open(reverse('admin:openwisp_users_user_changelist'))
        user_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'test-user-')]", 10
        )
        self.assertIsNotNone(user_link)  # Assert the user was created

    # Test case for importing users from a CSV file with all fields provided
    def test_standard_csv_import(self):
        """Test standard user import from CSV with all fields provided"""
        self.login()  # Log into the admin interface

        # Get the path of the CSV file for user import
        csv_file = self._get_path('static/users.csv')

        # Navigate to organization creation page
        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, 'id_name', 10).send_keys('Test Batch')
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Navigate to radius batch creation page
        self.open(reverse('admin:openwisp_radius_radiusbatch_add'))

        # Set strategy to CSV for importing users
        dropdown = self.find_element(By.ID, 'id_strategy', 10)
        select = Select(dropdown)
        select.select_by_value('csv')

        # Select the organization to associate with the users
        organization = self.find_element(By.ID, 'select2-id_organization-container', 10)
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
            10,
        )
        option.click()

        # Set batch name and upload CSV file for user import
        self.find_element(By.ID, 'id_name', 10).send_keys('Test Batch')
        csv_file_input = self.find_element(By.ID, 'id_csvfile', 10)
        csv_file_input.send_keys(csv_file)

        # Submit the form to start the import
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, 'success', 10)
        self.assertIn('was added successfully', success_message.text)

        # Verify that users from the CSV file were created
        self.find_element(By.CLASS_NAME, 'field-name').click()
        self.open(reverse('admin:openwisp_users_user_changelist'))
        user1_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'user1')]", 10
        )
        self.assertIsNotNone(user1_link)

        # Ensure another user from the CSV is also created
        user2_link = self.find_element(By.XPATH, "//a[contains(text(), 'user2')]")
        self.assertIsNotNone(user2_link)

    # Test case for importing users with hashed passwords from a CSV file
    def test_import_with_hashed_passwords(self):
        """Test user import with Django-formatted hashed passwords"""
        self.login()  # Log into the admin interface

        # Get the path of the CSV file with hashed passwords
        csv_file = self._get_path('static/user_with_hash.csv')

        # Navigate to organization creation page
        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, 'id_name', 10).send_keys('Test Batch')
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Navigate to radius batch creation page
        self.open(reverse('admin:openwisp_radius_radiusbatch_add'))

        # Set strategy to CSV for importing users
        dropdown = self.find_element(By.ID, 'id_strategy', 10)
        select = Select(dropdown)
        select.select_by_value('csv')

        # Set batch name and select the organization
        self.find_element(By.ID, 'id_name', 10).send_keys('Hashed Password Import Test')
        organization = self.find_element(By.ID, 'select2-id_organization-container', 10)
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
            10,
        )
        option.click()

        # Upload the CSV file with hashed passwords
        csv_file_input = self.find_element(By.ID, 'id_csvfile', 10)
        csv_file_input.send_keys(csv_file)

        # Submit the form to import users
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, 'success', 10)
        self.assertIn('was added successfully', success_message.text)

        # Verify that users with hashed passwords are created
        self.find_element(By.CLASS_NAME, 'field-name').click()
        self.open(reverse('admin:openwisp_users_user_changelist'))
        hash_user1_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'hash_user1')]", 10
        )
        self.assertIsNotNone(hash_user1_link)

        hash_user2_link = self.find_element(
            By.XPATH, "//a[contains(text(), 'hash_user2')]", 10
        )
        self.assertIsNotNone(hash_user2_link)

    # Test case for user generation with prefix strategy
    def test_prefix_user_generation(self):
        """Test user generation with prefix strategy"""
        self.login()  # Log into the admin interface

        # Create an organization for the prefix user generation
        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, 'id_name', 10).send_keys('Test Batch')
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Navigate to radius batch creation page
        self.open(reverse('admin:openwisp_radius_radiusbatch_add'))

        # Set user strategy to 'prefix'
        dropdown = self.find_element(By.ID, 'id_strategy', 10)
        select = Select(dropdown)
        select.select_by_value('prefix')

        # Select the organization and set the prefix for users
        organization = self.find_element(By.ID, 'select2-id_organization-container', 10)
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
            10,
        )
        option.click()

        # Set prefix and number of users to generate
        self.find_element(By.ID, 'id_name', 10).send_keys('Prefix Test')
        prefix_field = self.find_element(By.ID, 'id_prefix')
        prefix_field.clear()
        prefix_field.send_keys('prefix-user-')
        self.find_element(By.ID, 'id_number_of_users').send_keys('10')

        # Submit the form to create users with the prefix
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, 'success', 10)
        self.assertIn('was added successfully', success_message.text)

        # Verify that the batch is listed and contains the correct number of users
        batch_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'Prefix Test')]", 10
        )
        batch_link.click()
        readonly_elements = self.find_elements(By.CLASS_NAME, 'readonly', 10)

        # Check if any of the elements contain "10"
        contains_ten = any('10' in element.text for element in readonly_elements)

        # Assert if at least one element contains "10"
        assert contains_ten, "No element contains the number 10"

    # Test case for user generation using CSV file upload
    def test_csv_user_generation(self):
        """Test user generation with CSV upload"""
        self.login()  # Log into the admin interface

        # Get the path of the CSV file
        csv_file = self._get_path('static/csv_user_gen.csv')

        # Navigate to organization creation page
        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, 'id_name', 10).send_keys('Test Batch')
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Navigate to radius batch creation page
        self.open(reverse('admin:openwisp_radius_radiusbatch_add'))

        # Set strategy to 'csv' for user generation
        dropdown = self.find_element(By.ID, 'id_strategy', 10)
        select = Select(dropdown)
        select.select_by_value('csv')

        # Select the organization and upload the CSV
        organization = self.find_element(By.ID, 'select2-id_organization-container', 10)
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
            10,
        )
        option.click()

        self.find_element(By.ID, 'id_name', 10).send_keys('CSV Test')
        csv_file_input = self.find_element(By.ID, 'id_csvfile', 10)
        csv_file_input.send_keys(csv_file)

        # Submit the form to generate users via CSV upload
        self.find_element(By.CSS_SELECTOR, 'input[type=submit]', 10).click()

        # Verify success message
        success_message = self.wait_for_visibility(By.CLASS_NAME, 'success', 10)
        self.assertIn('was added successfully', success_message.text)

        # Verify that the users were created
        self.open(reverse('admin:openwisp_users_user_changelist'))
        user1_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'csv-user1')]", 10
        )
        self.assertIsNotNone(user1_link)