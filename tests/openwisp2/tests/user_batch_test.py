import os

from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.urls import reverse
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

from .test_selenium import SeleniumTestMixin

current_script_path = os.path.dirname(os.path.abspath(__file__))


class BasicTest(SeleniumTestMixin, StaticLiveServerTestCase):
    def setUp(self):
        self.admin = self._create_admin(
            username=self.admin_username, password=self.admin_password
        )

    def test_batch_user_creation(self):
        self.login()

        """Test the batch user creation feature"""
        self.web_driver.get(
            f"{self.live_server_url}{reverse('admin:openwisp_users_organization_add')}"
        )
        self.web_driver.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.web_driver.get(
            f"{self.live_server_url}/admin/openwisp_radius/radiusbatch/add/"
        )

        dropdown = self.web_driver.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("prefix")

        self.web_driver.find_element(By.ID, "id_name").send_keys("Test Batch")
        prefix_field = self.web_driver.find_element(By.ID, "id_prefix")
        prefix_field.clear()
        prefix_field.send_keys("test-user-")
        organization = self.web_driver.find_element(
            By.ID, "select2-id_organization-container"
        )
        organization.click()

        option = self.web_driver.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )

        option.click()
        self.web_driver.find_element(By.ID, "id_number_of_users").send_keys("5")

        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "success"))
        )
        self.assertIn("was added successfully", success_message.text)

        self.web_driver.get(f"{self.live_server_url}/admin/openwisp_users/user/")

        user_link = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located(
                (By.XPATH, "//a[contains(text(), 'test-user-')]")
            )
        )
        self.assertIsNotNone(user_link)

        self.web_driver.get(
            f"{self.live_server_url}/admin/openwisp_radius/radiusbatch/"
        )
        self.web_driver.find_element(By.CLASS_NAME, "field-name").click()
        download_link = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.ID, "downloadpdflink"))
        )
        self.assertIsNotNone(download_link)

    def test_standard_csv_import(self):
        """Test standard user import from CSV with all fields provided"""
        self.login()

        csv_file = os.path.join(current_script_path, "csv_files/users.csv")

        self.web_driver.get(
            f"{self.live_server_url}{reverse('admin:openwisp_users_organization_add')}"
        )
        self.web_driver.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.web_driver.get(
            f"{self.live_server_url}/admin/openwisp_radius/radiusbatch/add/"
        )

        dropdown = self.web_driver.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("csv")

        organization = self.web_driver.find_element(
            By.ID, "select2-id_organization-container"
        )
        organization.click()

        option = self.web_driver.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )

        option.click()

        self.web_driver.find_element(By.ID, "id_name").send_keys("Test Batch")

        csv_file_input = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.ID, "id_csvfile"))
        )

        csv_file_input.send_keys(csv_file)
        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "success"))
        )
        self.assertIn("was added successfully", success_message.text)
        self.web_driver.find_element(By.CLASS_NAME, "field-name").click()
        self.web_driver.get(f"{self.live_server_url}/admin/openwisp_users/user/")

        user1_link = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.XPATH, "//a[contains(text(), 'user1')]"))
        )
        self.assertIsNotNone(user1_link)

        user2_link = self.web_driver.find_element(
            By.XPATH, "//a[contains(text(), 'user2')]"
        )
        self.assertIsNotNone(user2_link)

    def test_import_with_hashed_passwords(self):
        """Test user import with Django-formatted hashed passwords"""
        self.login()

        csv_file = os.path.join(current_script_path, "csv_files/user_with_hash.csv")

        self.web_driver.get(
            f"{self.live_server_url}{reverse('admin:openwisp_users_organization_add')}"
        )
        self.web_driver.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.web_driver.get(
            f"{self.live_server_url}/admin/openwisp_radius/radiusbatch/add/"
        )

        dropdown = self.web_driver.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("csv")
        self.web_driver.find_element(By.ID, "id_name").send_keys(
            "Hashed Password Import Test"
        )

        organization = self.web_driver.find_element(
            By.ID, "select2-id_organization-container"
        )
        organization.click()
        option = self.web_driver.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )

        option.click()
        csv_file_input = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.ID, "id_csvfile"))
        )
        csv_file_input.send_keys(csv_file)

        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "success"))
        )
        self.assertIn("was added successfully", success_message.text)

        self.web_driver.find_element(By.CLASS_NAME, "field-name").click()
        self.web_driver.get(f"{self.live_server_url}/admin/openwisp_users/user/")
        hash_user1_link = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located(
                (By.XPATH, "//a[contains(text(), 'hash_user1')]")
            )
        )
        self.assertIsNotNone(hash_user1_link)

        hash_user2_link = self.web_driver.find_element(
            By.XPATH, "//a[contains(text(), 'hash_user2')]"
        )
        self.assertIsNotNone(hash_user2_link)

    def test_prefix_user_generation(self):
        """Test user generation with prefix strategy"""
        self.login()

        self.web_driver.get(
            f"{self.live_server_url}{reverse('admin:openwisp_users_organization_add')}"
        )
        self.web_driver.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.web_driver.get(
            f"{self.live_server_url}/admin/openwisp_radius/radiusbatch/add/"
        )

        dropdown = self.web_driver.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("prefix")

        organization = self.web_driver.find_element(
            By.ID, "select2-id_organization-container"
        )
        organization.click()

        option = self.web_driver.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )
        option.click()

        self.web_driver.find_element(By.ID, "id_name").send_keys("Prefix Test")

        prefix_field = self.web_driver.find_element(By.ID, "id_prefix")
        prefix_field.clear()
        prefix_field.send_keys("prefix-user-")

        self.web_driver.find_element(By.ID, "id_number_of_users").send_keys("10")

        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "success"))
        )
        self.assertIn("was added successfully", success_message.text)

        batch_link = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located(
                (By.XPATH, "//a[contains(text(), 'Prefix Test')]")
            )
        )
        batch_link.click()
        user_count_xpath = (
            "/html/body/div/div[3]/div[3]/div/div[1]/div[2]/form/div/"
            "fieldset/div[6]/div/div/div"
        )

        user_count = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.XPATH, user_count_xpath))
        )

        self.assertIn("10", user_count.text)

    def test_csv_user_generation(self):
        """Test user generation with CSV upload"""
        self.login()
        csv_file = os.path.join(current_script_path, "csv_files/csv_user_gen.csv")
        self.web_driver.get(
            f"{self.live_server_url}{reverse('admin:openwisp_users_organization_add')}"
        )
        self.web_driver.find_element(By.ID, "id_name").send_keys("Test Batch")
        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        self.web_driver.get(
            f"{self.live_server_url}/admin/openwisp_radius/radiusbatch/add/"
        )

        dropdown = self.web_driver.find_element(By.ID, "id_strategy")

        select = Select(dropdown)
        select.select_by_value("csv")

        organization = self.web_driver.find_element(
            By.ID, "select2-id_organization-container"
        )
        organization.click()

        option = self.web_driver.find_element(
            By.XPATH,
            "//li[contains(@class, 'select2-results__option') and "
            "text()='Test Batch']",
        )
        option.click()

        self.web_driver.find_element(By.ID, "id_name").send_keys("CSV Test")
        csv_file_input = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.ID, "id_csvfile"))
        )
        csv_file_input.send_keys(csv_file)

        self.web_driver.find_element(By.CSS_SELECTOR, "input[type=submit]").click()

        success_message = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located((By.CLASS_NAME, "success"))
        )
        self.assertIn("was added successfully", success_message.text)

        self.web_driver.get(f"{self.live_server_url}/admin/openwisp_users/user/")

        user1_link = WebDriverWait(self.web_driver, 10).until(
            EC.presence_of_element_located(
                (By.XPATH, "//a[contains(text(), 'csv-user1')]")
            )
        )
        self.assertIsNotNone(user1_link)
