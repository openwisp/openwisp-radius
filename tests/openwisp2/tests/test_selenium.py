import json
import os

from django.contrib.auth import get_user_model
from selenium.webdriver.common.by import By

from .selenium_test_mixins import SeleniumTestMixin as BaseSeleniumTestMixin

User = get_user_model()


class TestConfigMixin(object):
    """Loads test configuration from a config.json file."""

    config_file = os.path.join(os.path.dirname(__file__), "config.json")
    root_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
    with open(config_file) as json_file:
        config = json.load(json_file)


class SeleniumTestMixin(BaseSeleniumTestMixin, TestConfigMixin):
    admin_username = "admin"
    admin_password = "password"

    def setUp(self):
        self.admin = self._create_admin(
            username=self.admin_username, password=self.admin_password
        )

    def _create_user(self, **kwargs):
        opts = dict(
            username=self.config["tester_username"],
            password=self.config["tester_password"],
            first_name=self.config["tester_first_name"],
            last_name=self.config["tester_last_name"],
            email=self.config["tester_email"],
        )
        opts.update(kwargs)
        user = User(**opts)
        user.full_clean()
        return User.objects.create_user(**opts)

    def _create_admin(self, **kwargs):
        opts = dict(
            username=self.config["admin_username"],
            email=self.config["admin_email"],
            password=self.config["admin_password"],
            is_superuser=True,
            is_staff=True,
        )
        opts.update(kwargs)
        return self._create_user(**opts)

    def login(self, username=None, password=None, driver=None):
        """Log in to the admin dashboard.

        Input Arguments:

        - username: username to be used for login (default:
          cls.admin_username)
        - password: password to be used for login (default:
          cls.admin_password)
        - driver: selenium driver (default: cls.web_driver).
        """

        if not driver:
            driver = self.web_driver
        if not username:
            username = self.admin_username
        if not password:
            password = self.admin_password
        driver.get(f"{self.live_server_url}/admin/login/")
        if "admin/login" in driver.current_url:
            driver.find_element(by=By.NAME, value="username").send_keys(username)
            driver.find_element(by=By.NAME, value="password").send_keys(password)
            driver.find_element(by=By.XPATH, value='//input[@type="submit"]').click()
