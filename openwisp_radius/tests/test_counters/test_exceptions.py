from unittest.mock import MagicMock

from ...counters.exceptions import BaseException, MaxQuotaReached, SkipCheck
from ..mixins import BaseTestCase


class TestCounterExceptions(BaseTestCase):
    def test_base_exception_debug_level(self):
        logger = MagicMock()
        exception = BaseException("Debug message", "debug", logger)
        logger.debug.assert_called_with("Debug message")
        self.assertEqual(exception.message, "Debug message")
        self.assertEqual(exception.level, "debug")

    def test_base_exception_info_level(self):
        logger = MagicMock()
        exception = BaseException("Info message", "info", logger)
        logger.info.assert_called_with("Info message")
        self.assertEqual(exception.message, "Info message")
        self.assertEqual(exception.level, "info")

    def test_base_exception_warn_level(self):
        logger = MagicMock()
        exception = BaseException("Warn message", "warn", logger)
        logger.warn.assert_called_with("Warn message")
        self.assertEqual(exception.message, "Warn message")
        self.assertEqual(exception.level, "warn")

    def test_base_exception_error_level(self):
        logger = MagicMock()
        exception = BaseException("Error message", "error", logger)
        logger.error.assert_called_with("Error message")
        self.assertEqual(exception.message, "Error message")
        self.assertEqual(exception.level, "error")

    def test_base_exception_critical_level(self):
        logger = MagicMock()
        exception = BaseException("Critical message", "critical", logger)
        logger.critical.assert_called_with("Critical message")
        self.assertEqual(exception.message, "Critical message")
        self.assertEqual(exception.level, "critical")

    def test_base_exception_exception_level(self):
        logger = MagicMock()
        exception = BaseException("Exception message", "exception", logger)
        logger.exception.assert_called_with("Exception message")
        self.assertEqual(exception.message, "Exception message")
        self.assertEqual(exception.level, "exception")

    def test_base_exception_invalid_level(self):
        logger = MagicMock()
        with self.assertRaises(AssertionError):
            BaseException("Message", "invalid_level", logger)

    def test_skip_check_exception(self):
        logger = MagicMock()
        exception = SkipCheck("Skip check message", "info", logger)
        self.assertIsInstance(exception, BaseException)
        self.assertEqual(exception.message, "Skip check message")
        self.assertEqual(exception.level, "info")
        logger.info.assert_called_with("Skip check message")

    def test_max_quota_reached_exception(self):
        logger = MagicMock()
        reply_msg = "Your quota has been exceeded"
        exception = MaxQuotaReached(
            "Max quota reached message", "info", logger, reply_msg
        )
        self.assertIsInstance(exception, BaseException)
        self.assertEqual(exception.message, "Max quota reached message")
        self.assertEqual(exception.level, "info")
        self.assertEqual(exception.reply_message, reply_msg)
        logger.info.assert_called_with("Max quota reached message")

    def test_max_quota_reached_inherits_base_exception(self):
        logger = MagicMock()
        exception = MaxQuotaReached("Message", "error", logger, "Reply")
        logger.error.assert_called_with("Message")
        self.assertEqual(exception.message, "Message")
        self.assertEqual(exception.level, "error")

    def test_skip_check_raise(self):
        """Test that SkipCheck can be raised and caught properly"""
        logger = MagicMock()
        with self.assertRaises(SkipCheck) as ctx:
            raise SkipCheck("Skip this check", "debug", logger)
        self.assertEqual(ctx.exception.message, "Skip this check")
        self.assertEqual(ctx.exception.level, "debug")
        logger.debug.assert_called_with("Skip this check")

    def test_max_quota_reached_raise(self):
        """Test that MaxQuotaReached can be raised and caught properly"""
        logger = MagicMock()
        with self.assertRaises(MaxQuotaReached) as ctx:
            raise MaxQuotaReached("Quota exceeded", "warn", logger, "No more quota")
        self.assertEqual(ctx.exception.message, "Quota exceeded")
        self.assertEqual(ctx.exception.level, "warn")
        self.assertEqual(ctx.exception.reply_message, "No more quota")
        logger.warn.assert_called_with("Quota exceeded")
