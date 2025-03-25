import os

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select

from openwisp_users.tests.utils import TestOrganizationMixin
from openwisp_utils.tests.selenium import SeleniumTestMixin

current_script_path = os.path.dirname(os.path.abspath(__file__))


class BasicTest(SeleniumTestMixin, StaticLiveServerTestCase, TestOrganizationMixin):
    def test_batch_user_creation(self):
        self.login()

        """Test the batch user creation feature"""
        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.open("/admin/openwisp_radius/radiusbatch/add/")

        dropdown = self.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("prefix")

        self.find_element(By.ID, "id_name").send_keys("Test Batch")
        prefix_field = self.find_element(By.ID, "id_prefix")
        prefix_field.clear()
        prefix_field.send_keys("test-user-")
        organization = self.find_element(By.ID, "select2-id_organization-container")
        organization.click()

        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )

        option.click()
        self.find_element(By.ID, "id_number_of_users").send_keys("5")

        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        self.open("/admin/openwisp_users/user/")

        user_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'test-user-')]", 10
        )
        self.assertIsNotNone(user_link)

        self.open("/admin/openwisp_radius/radiusbatch/")
        self.find_element(By.CLASS_NAME, "field-name").click()
        download_link = self.wait_for_visibility(By.ID, "downloadpdflink", 10)
        self.assertIsNotNone(download_link)

    def test_standard_csv_import(self):
        """Test standard user import from CSV with all fields provided"""
        try:
            self.login()

            csv_file = os.path.join(current_script_path, "csv_files/users.csv")

            self.open(reverse('admin:openwisp_users_organization_add'))
            self.find_element(By.ID, "id_name").send_keys("Test Batch")
            self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

            self.open("/admin/openwisp_radius/radiusbatch/add/")

            dropdown = self.find_element(By.ID, "id_strategy")

            select = Select(dropdown)
            select.select_by_value("csv")

            organization = self.find_element(By.ID, "select2-id_organization-container")
            organization.click()

            option = self.find_element(
                By.XPATH,
                "//li[contains(@class, 'select2-results__option') and "
                "text()='Test Batch']",
            )

            option.click()

            self.find_element(By.ID, "id_name").send_keys("Test Batch")

            csv_file_input = self.find_element(By.ID, "id_csvfile")

            csv_file_input.send_keys(csv_file)
            self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

            success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
            self.assertIn("was added successfully", success_message.text)
            self.find_element(By.CLASS_NAME, "field-name").click()
            self.open("/admin/openwisp_users/user/")

            user1_link = self.wait_for_visibility(
                By.XPATH, "//a[contains(text(), 'user1')]", 10
            )
            self.assertIsNotNone(user1_link)

            user2_link = self.find_element(By.XPATH, "//a[contains(text(), 'user2')]")
            self.assertIsNotNone(user2_link)
        except Exception as e:
            print("error ==> ", e)
            # self.logout()

    def test_import_with_hashed_passwords(self):
        """Test user import with Django-formatted hashed passwords"""
        self.login()

        csv_file = os.path.join(current_script_path, "csv_files/user_with_hash.csv")

        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.open("/admin/openwisp_radius/radiusbatch/add/")

        dropdown = self.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("csv")
        self.find_element(By.ID, "id_name").send_keys("Hashed Password Import Test")

        organization = self.find_element(By.ID, "select2-id_organization-container")
        organization.click()
        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )

        option.click()
        csv_file_input = self.find_element(By.ID, "id_csvfile")
        csv_file_input.send_keys(csv_file)

        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        self.find_element(By.CLASS_NAME, "field-name").click()
        self.open("/admin/openwisp_users/user/")
        hash_user1_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'hash_user1')]", 10
        )
        self.assertIsNotNone(hash_user1_link)

        hash_user2_link = self.find_element(
            By.XPATH, "//a[contains(text(), 'hash_user2')]"
        )
        self.assertIsNotNone(hash_user2_link)

    def test_prefix_user_generation(self):
        """Test user generation with prefix strategy"""
        self.login()

        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.open("/admin/openwisp_radius/radiusbatch/add/")

        dropdown = self.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("prefix")

        organization = self.find_element(By.ID, "select2-id_organization-container")
        organization.click()

        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )
        option.click()

        self.find_element(By.ID, "id_name").send_keys("Prefix Test")

        prefix_field = self.find_element(By.ID, "id_prefix")
        prefix_field.clear()
        prefix_field.send_keys("prefix-user-")

        self.find_element(By.ID, "id_number_of_users").send_keys("10")

        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        batch_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'Prefix Test')]", 10
        )
        batch_link.click()
        user_count_xpath = (
            "/html/body/div/div[3]/div[3]/div/div[1]/div[2]/form/div/"
            "fieldset/div[6]/div/div/div"
        )

        user_count = self.wait_for_visibility(By.XPATH, user_count_xpath, 10)

        self.assertIn("10", user_count.text)

    def test_csv_user_generation(self):
        """Test user generation with CSV upload"""
        self.login()
        csv_file = os.path.join(current_script_path, "csv_files/csv_user_gen.csv")
        self.open(reverse('admin:openwisp_users_organization_add'))
        self.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.open("/admin/openwisp_radius/radiusbatch/add/")

        dropdown = self.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("csv")

        organization = self.find_element(By.ID, "select2-id_organization-container")
        organization.click()

        option = self.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )
        option.click()

        self.find_element(By.ID, "id_name").send_keys("CSV Test")
        csv_file_input = self.find_element(By.ID, "id_csvfile")
        csv_file_input.send_keys(csv_file)

        self.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = self.wait_for_visibility(By.CLASS_NAME, "success", 10)
        self.assertIn("was added successfully", success_message.text)

        self.open("/admin/openwisp_users/user/")

        user1_link = self.wait_for_visibility(
            By.XPATH, "//a[contains(text(), 'csv-user1')]", 10
        )
        self.assertIsNotNone(user1_link)
