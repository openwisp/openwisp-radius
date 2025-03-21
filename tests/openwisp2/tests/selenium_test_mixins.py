import os

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class SeleniumTestMixin:
    """A base Mixin Class for Selenium Browser Tests.

    Provides common initialization logic and helper methods like login()
    and open().
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        options = Options()
        options.page_load_strategy = "eager"
        if os.environ.get("SELENIUM_HEADLESS", False):
            options.add_argument("--headless")
        GECKO_BIN = os.environ.get("GECKO_BIN", None)
        if GECKO_BIN:
            options.binary_location = GECKO_BIN
        options.set_preference("network.stricttransportsecurity.preloadlist", False)
        # Enable detailed GeckoDriver logging
        options.set_capability("moz:firefoxOptions", {"log": {"level": "trace"}})
        # Use software rendering instead of hardware acceleration
        options.set_preference("gfx.webrender.force-disabled", True)
        options.set_preference("layers.acceleration.disabled", True)
        # Increase timeouts
        options.set_preference("marionette.defaultPrefs.update.disabled", True)
        options.set_preference("dom.max_script_run_time", 30)
        kwargs = dict(options=options)
        # Optional: Store logs in a file
        # Pass GECKO_LOG=1 when running tests
        GECKO_LOG = os.environ.get("GECKO_LOG", None)
        if GECKO_LOG:
            kwargs["service"] = webdriver.FirefoxService(log_output="geckodriver.log")
        cls.web_driver = webdriver.Firefox(**kwargs)

    @classmethod
    def tearDownClass(cls):
        cls.web_driver.quit()
        super().tearDownClass()

    def open(self, url, driver=None, timeout=5):
        """Opens a URL.

        Input Arguments:

        - url: URL to open
        - driver: selenium driver (default: cls.base_driver).
        """
        if not driver:
            driver = self.web_driver
        driver.get(f"{self.live_server_url}{url}")
        WebDriverWait(driver, timeout).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        WebDriverWait(self.web_driver, timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "#main-content"))
        )

    def find_element(self, by, value, timeout=2, wait_for="visibility"):
        method = f"wait_for_{wait_for}"
        getattr(self, method)(by, value, timeout)
        return self.web_driver.find_element(by=by, value=value)

    def wait_for_visibility(self, by, value, timeout=2):
        return self.wait_for("visibility_of_element_located", by, value)

    def wait_for_invisibility(self, by, value, timeout=2):
        return self.wait_for("invisibility_of_element_located", by, value)

    def wait_for_presence(self, by, value, timeout=2):
        return self.wait_for("presence_of_element_located", by, value)

    def wait_for(self, method, by, value, timeout=2):
        try:
            return WebDriverWait(self.web_driver, timeout).until(
                getattr(EC, method)(((by, value)))
            )
        except TimeoutException as e:
            self.fail(f'{method} of "{value}" failed: {e}')
