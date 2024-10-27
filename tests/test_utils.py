from unittest.mock import patch

import responses
from django.test import TestCase
from feedback_form.utils import *


class ValidateRecaptchaTests(TestCase):

    @responses.activate
    def test_validate_recaptcha_success(self):
        """Checks that if the reCaptcha validation is successful then no error is added."""
        responses.add(
            responses.POST,
            'https://www.google.com/recaptcha/api/siteverify',
            json={'success': True},
            status=200
        )
        result = validate_recaptcha('fake-token', 'fake-secret-key')
        self.assertTrue(result['success'])
        self.assertIsNone(result['error'])

    @responses.activate
    def test_validate_recaptcha_failure(self):
        """Checks that if the reCaptcha validation is unsuccessful then error is added."""
        responses.add(
            responses.POST,
            'https://www.google.com/recaptcha/api/siteverify',
            json={'success': False, 'error-codes': ['invalid-input-response']},
            status=200
        )
        result = validate_recaptcha('fake-token', 'fake-secret-key')
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'The captcha task was failed or the token has expired. Please try again.')


class EmailSendingTests(TestCase):

    @patch('feedback_form.utils.EmailMultiAlternatives.send', side_effect=ImproperlyConfigured)
    def test_send_confirmation_email_improperly_configured(self, mock_send):
        """Checks ImproperlyConfigured error handling when sending an email."""
        result = send_confirmation_email(code='123456', recipient='test@example.com')

        self.assertFalse(result['success'])
        mock_send.assert_called_once()

    @patch('feedback_form.utils.EmailMultiAlternatives.send', side_effect=SMTPException)
    def test_send_confirmation_email_smtp_exception(self, mock_send):
        """Checks SMTPException handling when sending an email."""
        result = send_confirmation_email(code='123456', recipient='staff@example.com')

        self.assertFalse(result['success'])
        mock_send.assert_called_once()

    @patch('feedback_form.utils.EmailMultiAlternatives.send', side_effect=Exception('Unexpected error'))
    def test_send_confirmation_email_unexpected_exception(self, mock_send):
        """Checks the handling of an unexpected error when sending an email."""
        result = send_confirmation_email(code='123456', recipient='test@example.com')

        self.assertFalse(result['success'])
        mock_send.assert_called_once()

    @patch('feedback_form.utils.EmailMultiAlternatives.send')
    def test_send_confirmation_email_success(self, mock_send):
        """Checks that the confirmation email was sent successfully."""
        mock_send.return_value = 1

        result = send_confirmation_email(code='123456', recipient='test@example.com')

        self.assertTrue(result['success'])
        self.assertIsNone(result['error'])
        mock_send.assert_called_once()

    @patch('feedback_form.utils.EmailMultiAlternatives.send', side_effect=ImproperlyConfigured)
    def test_convey_submitted_email_improperly_configured(self, mock_send):
        """Checks ImproperlyConfigured error handling when sending an email."""
        result = convey_submitted_email(user_email='user@example.com', message='Hello!', recipient='staff@example.com')

        self.assertFalse(result['success'])
        mock_send.assert_called_once()

    @patch('feedback_form.utils.EmailMultiAlternatives.send', side_effect=SMTPException)
    def test_convey_submitted_email_smtp_exception(self, mock_send):
        """Checks SMTPException handling when sending an email."""
        result = convey_submitted_email(user_email='user@example.com', message='Hello!', recipient='staff@example.com')

        self.assertFalse(result['success'])
        mock_send.assert_called_once()

    @patch('feedback_form.utils.EmailMultiAlternatives.send', side_effect=Exception('Unexpected error'))
    def test_convey_submitted_email_unexpected_exception(self, mock_send):
        """Checks the handling of an unexpected error when sending an email."""
        result = convey_submitted_email(user_email='user@example.com', message='Hello!', recipient='staff@example.com')

        self.assertFalse(result['success'])
        mock_send.assert_called_once()

    @patch('feedback_form.utils.EmailMultiAlternatives.send')
    def test_convey_submitted_email_success(self, mock_send):
        """Checks that the submitted email was sent successfully."""
        mock_send.return_value = 1

        result = convey_submitted_email(user_email='user@example.com', message='Hello!', recipient='staff@example.com')

        self.assertTrue(result['success'])
        self.assertIsNone(result['error'])
        mock_send.assert_called_once()


class MiniUtilsTest(TestCase):

    def test_validate_email_incorrect(self):
        """Checks the validation of the incorrect email addresses."""
        invalid_addresses = ('bad@ss', 'bad.ass', 'bad@ss.s', '@bada.ss', 'lmao@kek.1337')

        for address in invalid_addresses:
            self.assertFalse(validate_email_address(address))

    def test_email_correct(self):
        """Checks the validation of the correct email addresses."""
        valid_addresses = ('super@cool.addres', 'super@cool.add.ress', 'SuPeRco0L@add.ress')

        for address in valid_addresses:
            self.assertTrue(validate_email_address(address))

    def test_hash_value_correctness(self):
        """Checks that hashing of the static string returns an expecting result."""
        expected_hash = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
        result = hash_value('hello')
        self.assertEqual(result, expected_hash)

    def test_hash_value_stability(self):
        """Checks that the hashing result does not change between attempts."""
        value = 'stable_test_string'
        result1 = hash_value(value)
        result2 = hash_value(value)
        self.assertEqual(result1, result2)

    def test_hash_value_empty_string(self):
        """Checks the hashing of an empty string."""
        expected_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()
        result = hash_value('')
        self.assertEqual(result, expected_hash)

    def test_hash_value_uniqueness(self):
        """Checks that the hashes of different strings are different."""
        hash1 = hash_value('string_one')
        hash2 = hash_value('string_two')
        self.assertNotEqual(hash1, hash2)

    def test_vigenere_decrypt(self):
        """Tests basic decryption with a known encrypted string."""
        ciphertext = 'KEYRIJVSUYVJN'
        vigenere_key_length = 3
        result = vigenere_decrypt(ciphertext, vigenere_key_length)
        self.assertEqual(result, 'HELLOWORLD')
