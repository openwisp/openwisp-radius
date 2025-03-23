from django.contrib.auth import get_user_model

from openwisp_utils.tests.selenium import SeleniumTestMixin as BaseSeleniumTestMixin

User = get_user_model()


class SeleniumTestMixin(BaseSeleniumTestMixin):
    admin_username = "admin"
    admin_password = "password"
    admin_email = "admin@admin.com"

    def setUp(self):
        self.admin = self._create_admin(
            username=self.admin_username, password=self.admin_password
        )
        self.web_driver = self.get_chrome_webdriver()

    def _create_user(self, **kwargs):
        opts = dict(
            username="tester_username",
            password="tester_password",
            first_name="tester_first_name",
            last_name="tester_last_name",
            email="tester_email@email.com",
        )
        opts.update(kwargs)
        user = User(**opts)
        user.full_clean()
        return User.objects.create_user(**opts)

    def _create_admin(self, **kwargs):
        opts = dict(
            username=self.admin_username,
            email=self.admin_email,
            password=self.admin_password,
            is_superuser=True,
            is_staff=True,
        )
        opts.update(kwargs)
        return self._create_user(**opts)
