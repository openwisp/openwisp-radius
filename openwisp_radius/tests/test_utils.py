from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from ..utils import find_available_username, validate_csvfile
from . import FileMixin
from .mixins import BaseTestCase


class TestUtils(FileMixin, BaseTestCase):
    def test_find_available_username(self):
        User = get_user_model()
        User.objects.create(username='rohith', password='password')
        self.assertEqual(find_available_username('rohith', []), 'rohith1')
        User.objects.create(username='rohith1', password='password')
        self.assertEqual(find_available_username('rohith', []), 'rohith2')

    def test_validate_file_format(self):
        invalid_format_path = self._get_path('static/test_batch_invalid_format.pdf')
        with self.assertRaises(ValidationError) as error:
            validate_csvfile(open(invalid_format_path, 'rb'))
        self.assertTrue(
            'Unrecognized file format, the supplied file does not look like a CSV file.'
            in error.exception.message
        )

    def test_validate_csvfile(self):
        invalid_csv_path = self._get_path('static/test_batch_invalid.csv')
        improper_csv_path = self._get_path('static/test_batch_improper.csv')
        with self.assertRaises(ValidationError) as error:
            validate_csvfile(open(invalid_csv_path, 'rt'))
        self.assertTrue('Enter a valid email address' in error.exception.message)
        with self.assertRaises(ValidationError) as error:
            validate_csvfile(open(improper_csv_path, 'rt'))
        self.assertTrue('Improper CSV format' in error.exception.message)
