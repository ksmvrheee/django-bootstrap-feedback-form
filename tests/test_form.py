import logging
from datetime import datetime
from random import randint
from unittest import TestCase
from unittest.mock import patch

from feedback_form.forms import FeedbackForm
from feedback_form.models import FeedbackFormSession


class FeedbackFormUnitTests(TestCase):
    """Tests for the FeedbackForm object itself."""

    def setUp(self):
        logging.disable(logging.CRITICAL)  # disabling logging during the tests time

    def tearDown(self):
        logging.disable(logging.NOTSET)  # enabling logging back after the tests are done

    def test_initialization_without_session_identifier(self):
        """Checks that the form cannot be properly initialized without the 'session_identifier' argument."""
        form = FeedbackForm(data={'email': 'test@example.com', 'code': '123456', 'message': 'Test message'})
        self.assertTrue(hasattr(form, 'no_identifier'))
        self.assertTrue(hasattr(form, 'critical_error'))
        self.assertTrue(form.critical_error)
        self.assertIn('__all__', form.errors)
        self.assertEqual(form.errors['__all__'].as_data()[0].code, 'no_identifier')

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_no_session_record(self, mock_filter):
        """Checks that the form is not valid if the corresponding session record is not available."""
        mock_filter.return_value.first.return_value = None

        form = FeedbackForm(
            data={'email': 'test@example.com', 'code': 123456, 'message': 'Test message'},
            session_identifier='some-wrong-session-id'
        )
        form.is_valid()

        self.assertTrue(hasattr(form, 'critical_error'))
        self.assertTrue(form.critical_error)
        self.assertIn('__all__', form.errors)
        self.assertEqual(form.errors['__all__'].as_data()[0].code, 'no_record')

    @patch('feedback_form.models.FeedbackFormSession.delete')
    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_no_submission_attempts_left(self, mock_filter, mock_deletion):
        """Checks that the form is not valid if there is no submission attempts left for the record."""
        mock_filter.return_value.first.return_value = FeedbackFormSession(
            submission_attempts_left=0
        )
        mock_deletion.return_value = True

        form = FeedbackForm(
            data={'email': 'test@example.com', 'code': 123456, 'message': 'Test message'},
            session_identifier='some-session-id'
        )
        form.is_valid()

        self.assertTrue(hasattr(form, 'critical_error'))
        self.assertTrue(form.critical_error)
        self.assertIn('__all__', form.errors)
        self.assertEqual(form.errors['__all__'].as_data()[0].code, 'no_attempts_left')

    @patch('feedback_form.models.FeedbackFormSession.delete')
    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_time_exceeded(self, mock_filter, mock_deletion):
        """Checks that the form is not valid if the time for posting was exceeded."""
        mock_filter.return_value.first.return_value = FeedbackFormSession(
            confirmation_code_expiry=datetime(1999, 12, 12, 12, 12, 12)
        )
        mock_deletion.return_value = True

        form = FeedbackForm(
            data={'email': 'test@example.com', 'code': 123456, 'message': 'Test message'},
            session_identifier='some-session-id'
        )
        form.is_valid()

        self.assertTrue(form.critical_error)
        self.assertIn('__all__', form.errors)
        self.assertEqual(form.errors['__all__'].as_data()[0].code, 'time_expired')

    @patch('feedback_form.models.FeedbackFormSession.delete')
    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_email_mismatch(self, mock_filter, mock_deletion):
        """Checks that the form is not valid if the provided email does not match a stored one."""
        mock_filter.return_value.first.return_value = FeedbackFormSession(
            confirmation_code_expiry=datetime(2077, 12, 12, 12, 12, 12),
            email_hash='hashed-other@example.com'
        )
        mock_deletion.return_value = True

        with patch('feedback_form.forms.hash_value', side_effect=lambda x: f'hashed-{x}'):
            form = FeedbackForm(
                data={'email': 'test@example.com', 'code': '123456', 'message': 'Test message'},
                session_identifier='some-session-id'
            )
            form.is_valid()

        self.assertTrue(hasattr(form, 'critical_error'))
        self.assertTrue(form.critical_error)
        self.assertIn('email', form.errors)
        self.assertEqual(form.errors['email'].as_data()[0].code, 'wrong_email')

    @patch('feedback_form.models.FeedbackFormSession.delete')
    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_code_mismatch_critical(self, mock_filter, mock_deletion):
        """Checks that the form is not valid if the provided code does not match a stored one."""
        mock_filter.return_value.first.return_value = FeedbackFormSession(
            confirmation_code_expiry=datetime(2077, 12, 12, 12, 12, 12),
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-wrong-code',
            validation_attempts_left=0
        )
        mock_deletion.return_value = True

        with patch('feedback_form.forms.hash_value', side_effect=lambda x: f'hashed-{x}'):
            form = FeedbackForm(
                data={'email': 'test@example.com', 'code': '123456', 'message': 'Test message'},
                session_identifier='some-session-id'
            )
            form.is_valid()

        self.assertTrue(hasattr(form, 'critical_error'))
        self.assertTrue(form.critical_error)
        self.assertIn('__all__', form.errors)
        self.assertEqual(form.errors['__all__'].as_data()[0].code, 'wrong_code_and_no_validation_attempts')

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_code_mismatch_attempts_left(self, mock_filter):
        """
        Checks that the form is not valid if the provided code does not match a stored
        one, but if there is at least one extra validation attempt left, the form
        can be validated again, hence the validation attempts value decreases.
        """
        session_record_submission_attempts_left = randint(1, 3)
        session_record_validation_attempts_left = randint(1, 3)

        mock_filter.return_value.first.return_value = FeedbackFormSession(
            confirmation_code_expiry=datetime(2077, 12, 12, 12, 12, 12),
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-wrong-code',
            submission_attempts_left=session_record_submission_attempts_left,
            validation_attempts_left=session_record_validation_attempts_left
        )

        with patch('feedback_form.forms.hash_value', side_effect=lambda x: f'hashed-{x}'):
            form = FeedbackForm(
                data={'email': 'test@example.com', 'code': '123456', 'message': 'Test message'},
                session_identifier='some-session-id'
            )
            form.is_valid()

        self.assertFalse(hasattr(form, 'critical_error'))
        self.assertIn('code', form.errors)
        self.assertEqual(form.errors['code'].as_data()[0].code, 'wrong_code')
        self.assertEqual(form.session_record.submission_attempts_left, session_record_submission_attempts_left-1)
        self.assertEqual(form.session_record.validation_attempts_left, session_record_validation_attempts_left-1)

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_success(self, mock_filter):
        """Checks the expected behavior."""
        mock_filter.return_value.first.return_value = FeedbackFormSession(
            email_hash='hashed-test@example.com',
            confirmation_code_hash = 'hashed-123456',
            confirmation_code_expiry=datetime(2077, 12, 12, 12, 12, 12),
            submission_attempts_left=3
        )

        with patch('feedback_form.forms.hash_value', side_effect=lambda x: f'hashed-{x}'):
            form = FeedbackForm(
                data={'email': 'test@example.com', 'code': '123456', 'message': 'Test message'},
                session_identifier='some-session-id'
            )
            form.is_valid()

        self.assertEqual(len(form.errors), 0)