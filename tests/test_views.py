import json
import logging
from datetime import timedelta, datetime
from random import randint
from unittest.mock import patch, Mock

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from feedback_form.models import FeedbackFormSession


class FeedbackFormViewsTests(APITestCase):
    """Tests for the view functions of the app."""

    def setUp(self):
        logging.disable(logging.CRITICAL) # disabling logging during the tests time

        # obtaining the endpoints urls
        self.feedback_url = reverse('ajax_feedback_form_validation')
        self.form_success_url = reverse('form_success')
        self.confirm_email_initial_url = reverse('ajax_email_confirmation')
        self.confirm_email_secondary_url = reverse('ajax_email_reconfirmation')
        self.validate_code_url = reverse('ajax_code_validation')

        # default values for the request variables
        self.session_id = 'encrypted-session-id'
        self.email = 'test@example.com'
        self.code = '123456'
        self.message = 'This is a test.'
        self.recaptcha_token = 'this-is-very-real-recaptcha-token'

    def tearDown(self):
        logging.disable(logging.NOTSET)  # enabling logging back after the tests are done

    def test_feedback_form_view_access_denied(self):
        """Checks that access to the endpoint is denied without the 'XMLHttpRequest' header for AJAX."""
        response = self.client.post(
            self.feedback_url,
            data={'email': self.email, 'code': self.code, 'message': self.message},
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_feedback_form_view_no_session_id(self):
        """Checks that access to the endpoint is denied without the 'X-Form-Session-Id' header."""
        response = self.client.post(
            self.feedback_url,
            data={'email': self.email, 'code': self.code, 'message': self.message},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_feedback_form_view_missing_fields(self):
        """Checks that the endpoint functionality cannot be used without providing all necessary fields."""
        response = self.client.post(
            self.feedback_url,
            data={},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_feedback_form_view_invalid_email(self):
        """Checks that the endpoint functionality cannot be used without providing a valid looking email."""
        with patch('feedback_form.views.vigenere_decrypt', return_value='decrypted-session-id'):
            response = self.client.post(
                self.feedback_url,
                data={'email': 'not-an-email', 'code': self.code, 'message': self.message},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['success'], False)

    @patch('feedback_form.forms.FeedbackFormSession.delete')
    def test_feedback_form_view_form_validation_failed(self, mock_deletion):
        """Checks that if the form validation fails the endpoint functionality could not be accessed."""
        mock_session = FeedbackFormSession(
            session_identifier='hashed-some-session-id',
            email_hash='hashed-another-email@example.com',
            confirmation_code_hash='hashed-123456',
            confirmation_code_expiry=datetime(2077, 12, 12, 12, 12, 12)
        )
        mock_deletion.return_value = True

        with patch('feedback_form.forms.FeedbackFormSession.objects.filter') as mock_filter:
            mock_filter.return_value.first.return_value = mock_session

            response = self.client.post(
                self.feedback_url,
                data={'email': self.email, 'code': self.code, 'message': self.message},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['success'], False)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['isErrorCritical'], True)

    @patch('feedback_form.views.convey_submitted_email', return_value={'success': False, 'error': 'SMTP error'})
    def test_feedback_form_view_email_sending_failure(self, mock_send_email):
        """Checks that if email sending fails there is an error explicitly returned."""
        mock_form = Mock()
        mock_form.is_valid.return_value = True
        mock_form.cleaned_data = {'email': self.email, 'message': self.message}

        with patch('feedback_form.views.FeedbackForm', return_value=mock_form):
            response = self.client.post(
                self.feedback_url,
                data={'email': self.email, 'code': self.code, 'message': self.message},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )
        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.data['success'], False)
        self.assertIn('errors', response.data)
        self.assertEqual(response.data['isErrorCritical'], False)

    def test_feedback_form_view_success(self):
        """Checks the expected behavior."""
        mock_form = Mock()
        mock_form.is_valid.return_value = True
        mock_form.cleaned_data = {'email': 'test@example.com', 'message': 'This is a test.'}

        with patch('feedback_form.views.FeedbackForm', return_value=mock_form):
            response = self.client.post(
                self.feedback_url,
                data={'email': self.email, 'code': self.code, 'message': 'This is a test.'},
                # json.dumps({'email': self.email, 'code': self.code, 'message': 'This is a test.'}),
                # content_type="application/json",
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data['success'], True)

    def test_form_success_view_access_denied(self):
        """Checks that access to the endpoint is denied without the 'form_submitted' cookie."""
        response = self.client.get(self.form_success_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_confirm_email_view_initial_access_denied(self):
        """Checks that access to the endpoint is denied without the 'XMLHttpRequest' header for AJAX."""
        response = self.client.post(
            self.confirm_email_initial_url,
            data={'recaptcha-token': self.recaptcha_token, 'email': self.email},
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_confirm_email_view_initial_no_session_id(self):
        """Checks that access to the endpoint is denied without the 'X-Form-Session-Id' header."""
        response = self.client.post(
            self.confirm_email_initial_url,
            data={'recaptcha-token': self.recaptcha_token, 'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @patch('feedback_form.utils.vigenere_decrypt', return_value='decrypted-session-id')
    def test_confirm_email_view_initial_missing_fields(self, mock_decrypt):
        """Checks that the endpoint functionality cannot be used without providing all necessary fields."""
        response = self.client.post(
            self.confirm_email_initial_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_confirm_email_view_initial_invalid_email(self):
        """Checks that the endpoint functionality cannot be used without providing a valid looking email."""
        with patch('feedback_form.views.vigenere_decrypt', return_value='decrypted-session-id'):
            response = self.client.post(
                self.confirm_email_initial_url,
                data={'recaptcha-token': self.recaptcha_token, 'email': 'not-an-email'},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['success'], False)

    def test_confirm_email_view_initial_captcha_validation_failure(self):
        """Checks that if the captcha validation fails the endpoint functionality could not be accessed."""
        with patch('feedback_form.views.validate_recaptcha',
                   return_value={'success': False, 'error': 'Invalid captcha.'}):
            response = self.client.post(
                self.confirm_email_initial_url,
                data={'recaptcha-token': 'invalid-token', 'email': self.email},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )

            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertEqual(response.data['success'], False)
            self.assertIn('error', response.data)
            self.assertEqual(response.data['error'], 'Invalid captcha.')

    @patch('feedback_form.views.send_confirmation_email', return_value={'success': False, 'error': 'SMTP error'})
    def test_confirm_email_view_initial_email_sending_failure(self, mock_send_email):
        """Checks that if email sending fails there is an error explicitly returned."""
        with patch('feedback_form.views.validate_recaptcha', return_value={'success': True, 'error': None}):
            response = self.client.post(
                self.confirm_email_initial_url,
                data={'email': self.email, 'recaptcha-token': 'valid-token'},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )
        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.data['success'], False)
        self.assertIn('error', response.data)

    @patch('feedback_form.views.vigenere_decrypt', return_value='decrypted-session-id')
    @patch('feedback_form.views.validate_recaptcha', return_value={'success': True})
    @patch('feedback_form.views.send_confirmation_email', return_value={'success': True})
    @patch('feedback_form.views.generate_confirmation_code', return_value='123456')
    @patch('feedback_form.views.hash_value', side_effect=lambda x: f'hashed-{x}')
    def test_confirm_email_view_initial_session_record_created(self, mock_hash_value, mock_generate_code,
                                                               mock_send_email, mock_validate_recaptcha,
                                                               mock_vigenere_decrypt):
        """Checks that a session record object is created as expected."""
        self.assertEqual(FeedbackFormSession.objects.count(), 0)

        response = self.client.post(
            self.confirm_email_initial_url,
            data={'email': self.email, 'recaptcha-token': self.recaptcha_token},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], True)

        self.assertEqual(FeedbackFormSession.objects.count(), 1)

        session_record = FeedbackFormSession.objects.first()
        self.assertEqual(session_record.email_hash, 'hashed-test@example.com')
        self.assertEqual(session_record.confirmation_code_hash, 'hashed-123456')
        self.assertEqual(session_record.session_identifier, 'hashed-decrypted-session-id')

    @patch('feedback_form.views.vigenere_decrypt', return_value='decrypted-session-id')
    @patch('feedback_form.views.validate_recaptcha', return_value={'success': True})
    @patch('feedback_form.views.send_confirmation_email', return_value={'success': True})
    @patch('feedback_form.views.generate_confirmation_code', return_value='123456')
    @patch('feedback_form.views.hash_value', side_effect=lambda x: f'hashed-{x}')
    def test_confirm_email_view_initial_session_record_updated(self, mock_hash_value, mock_generate_code,
                                                               mock_send_email, mock_validate_recaptcha,
                                                               mock_vigenere_decrypt):
        """Checks that a session record object is being updated."""
        session_record = FeedbackFormSession.objects.create(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-old-email@example.com',
            confirmation_code_hash='hashed-old-code',
            resending_attempts_left=1,
            validation_attempts_left=5,
            submission_attempts_left=3,
            cooldown_expiry=timezone.now(),
            confirmation_code_expiry=timezone.now()
        )

        response = self.client.post(
            self.confirm_email_initial_url,
            data={'email': self.email, 'recaptcha-token': 'valid-token'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], True)

        self.assertEqual(FeedbackFormSession.objects.count(), 1)

        session_record.refresh_from_db()
        self.assertEqual(session_record.email_hash, 'hashed-test@example.com')
        self.assertEqual(session_record.confirmation_code_hash, 'hashed-123456')
        self.assertEqual(session_record.session_identifier, 'hashed-decrypted-session-id')
        self.assertEqual(session_record.resending_attempts_left, 2)
        self.assertEqual(session_record.validation_attempts_left, 10)

    @patch('feedback_form.views.vigenere_decrypt', return_value='decrypted-session-id')
    @patch('feedback_form.views.validate_recaptcha', return_value={'success': True})
    @patch('feedback_form.views.send_confirmation_email', return_value={'success': True})
    @patch('feedback_form.views.generate_confirmation_code', return_value='123456')
    @patch('feedback_form.views.hash_value', side_effect=lambda x: f'hashed-{x}')
    def test_confirm_email_view_initial_success(self, mock_hash, mock_generate_code, mock_send_email,
                                                mock_validate_recaptcha, mock_vigenere_decrypt):
        """Checks the expected behavior."""
        response = self.client.post(
            self.confirm_email_initial_url,
            data={'email': self.email, 'recaptcha-token': 'valid-token'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], True)


    def test_confirm_email_view_secondary_access_denied(self):
        """Tests that access to the endpoint is denied without the 'XMLHttpRequest' header for AJAX."""
        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_confirm_email_view_secondary_no_session_id(self):
        """Checks that access to the endpoint is denied without the 'X-Form-Session-Id' header."""
        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_confirm_email_view_secondary_missing_fields(self):
        """Checks that the endpoint functionality cannot be used without providing all necessary fields."""
        response = self.client.post(
            self.confirm_email_secondary_url,
            data={},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_confirm_email_view_secondary_invalid_email(self):
        """Checks that the endpoint functionality cannot be used without providing a valid looking email."""
        with patch('feedback_form.views.vigenere_decrypt', return_value='decrypted-session-id'):
            response = self.client.post(
                self.confirm_email_secondary_url,
                data={'email': 'not-an-email'},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        self.assertEqual(response.data['success'], False)

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_confirm_email_view_secondary_no_session_record(self, mock_filter):
        """Checks that if session record cannot be retrieved there is an error explicitly returned."""
        mock_filter.return_value.first.return_value = None
        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_confirm_email_view_secondary_no_resending_attempts_left(self, mock_filter):
        """Checks that if there is no resending attempts left there is an error explicitly returned."""
        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-123456',
            resending_attempts_left=0
        )
        mock_filter.return_value.first.return_value = session_record

        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('The number of repeated code requests has been exceeded.', response.data['error'])

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_confirm_email_view_secondary_cooldown(self, mock_filter):
        """Checks that if cooldown is not yet passed the endpoint functionality cannot be accessed."""
        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-123456',
            resending_attempts_left=1,
            cooldown_expiry=timezone.now() + timedelta(seconds=30)
        )
        mock_filter.return_value.first.return_value = session_record

        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Request frequency exceeded.', response.data['error'])

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    @patch('feedback_form.views.send_confirmation_email', return_value={'success': False, 'error': 'SMTP error'})
    def test_confirm_email_view_secondary_email_sending_failure(self, mock_send_email, mock_filter):
        """Checks that if email sending fails there is an error explicitly returned."""
        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-123456',
            resending_attempts_left=1,
            cooldown_expiry=datetime(1999, 12, 12, 12,12, 12)
        )
        mock_filter.return_value.first.return_value = session_record

        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(response.data['success'], False)
        self.assertIn('error', response.data)

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    @patch('feedback_form.views.send_confirmation_email', return_value={'success': True})
    @patch('feedback_form.views.generate_confirmation_code', return_value='123456')
    @patch('feedback_form.views.hash_value', side_effect=lambda x: f'hashed-{x}')
    def test_confirm_email_view_secondary_session_record_updated(self, mock_hash_value, mock_generate_code,
                                                                 mock_send_email, mock_filter):
        """Checks that a session record object is being updated."""
        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-old-code',
            resending_attempts_left=1,
            validation_attempts_left=5,
            submission_attempts_left=3,
            cooldown_expiry=timezone.now() - timedelta(minutes=5),
            confirmation_code_expiry=timezone.now() + timedelta(hours=1)
        )
        mock_filter.return_value.first.return_value = session_record

        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], True)

        self.assertEqual(FeedbackFormSession.objects.count(), 1)

        updated_session = mock_filter.return_value.first.return_value
        self.assertEqual(updated_session.confirmation_code_hash, 'hashed-123456')  # Новый код подтверждения
        self.assertEqual(updated_session.resending_attempts_left, 0)  # Число попыток должно уменьшиться
        self.assertGreater(updated_session.cooldown_expiry, timezone.now())

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    @patch('feedback_form.views.send_confirmation_email', return_value={'success': True})
    @patch('feedback_form.views.generate_confirmation_code', return_value='123456')
    def test_confirm_email_view_secondary_success(self, mock_generate_code, mock_send_email, mock_filter):
        """Checks the expected behavior."""
        mock_filter.return_value.first.return_value = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-123456',
            resending_attempts_left=1,
            validation_attempts_left=10,
            cooldown_expiry=timezone.now(),
            confirmation_code_expiry=timezone.now()
        )
        response = self.client.post(
            self.confirm_email_secondary_url,
            data={'email': self.email},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], True)

    def test_validate_code_view_secondary_access_denied(self):
        """Checks that access to the endpoint is denied without the 'XMLHttpRequest' header for AJAX."""
        response = self.client.post(
            self.validate_code_url,
            data={'email': self.email, 'code': self.code},
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_validate_code_view_secondary_no_session_id(self):
        """Checks that access to the endpoint is denied without the 'X-Form-Session-Id' header."""
        response = self.client.post(
            self.validate_code_url,
            data={'email': self.email, 'code': self.code},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_validate_code_view_secondary_missing_fields(self):
        """Checks that the endpoint functionality cannot be used without providing all necessary fields."""
        response = self.client.post(
            self.validate_code_url,
            data={},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertIn('error', response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_validate_code_view_secondary_no_session_record(self, mock_filter):
        """Checks that if session record cannot be retrieved there is an error explicitly returned."""
        mock_filter.return_value.first.return_value = None
        response = self.client.post(
            self.validate_code_url,
            data={'email': self.email, 'code': self.code},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_validate_code_view_max_attempts_exceeded(self, mock_filter):
        """Checks that if there is no validation attempts left there is an error explicitly returned."""
        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-123456',
            validation_attempts_left=0
        )
        mock_filter.return_value.first.return_value = session_record

        response = self.client.post(
            self.validate_code_url,
            data={'email': self.email, 'code': 'wrong-code'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('The number of available code validation attempts has been exceeded.', response.data['error'])

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_validate_code_view_email_mismatch(self, mock_filter):
        """Checks that if email does not match there is an error explicitly returned."""
        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-another@example.com',
            confirmation_code_hash='hashed-123456',
        )
        mock_filter.return_value.first.return_value = session_record

        response = self.client.post(
            self.validate_code_url,
            data={'email': self.email, 'code': self.code},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('The email address you entered does not match', response.data['error'])

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_validate_code_view_code_mismatch(self, mock_filter):
        """Checks that if code does not match there is an error explicitly returned."""
        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-another-code',
        )
        mock_filter.return_value.first.return_value = session_record

        mock_hashing = Mock(side_effect={
            'hashed-decrypted-session-id': self.session_id,
            'hashed-test@example.com': self.email,
            'hashed-wrong-code': 'wrong-code'
        })

        with patch('feedback_form.views.hash_value', mock_hashing):
            response = self.client.post(
                self.validate_code_url,
                data={'email': self.email, 'code': 'wrong-code'},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('Wrong code. Please try again.', response.data['error'])

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    @patch('feedback_form.views.hash_value', side_effect=lambda x: f'hashed-{x}')
    def test_validate_code_view_session_record_updated(self, mock_hash_value, mock_filter):
        """Checks that a session record object is being updated."""
        session_record_validation_attempts_left = randint(2, 10)

        session_record = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-123456',
            validation_attempts_left=session_record_validation_attempts_left,
            confirmation_code_expiry=datetime(2077, 12, 12, 12, 12, 12)
        )
        mock_filter.return_value.first.return_value = session_record

        response = self.client.post(
            self.validate_code_url,
            data={'email': self.email, 'code': 'wrong-code'},
            HTTP_X_REQUESTED_WITH='XMLHttpRequest',
            HTTP_X_FORM_SESSION_ID=self.session_id
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['success'], False)
        self.assertEqual(response.data['error'], 'Wrong code. Please try again.')

        updated_validation_attempts_left = response.data['validationAttemptsLeft']
        self.assertEqual(updated_validation_attempts_left, session_record_validation_attempts_left-1)

    @patch('feedback_form.models.FeedbackFormSession.objects.filter')
    def test_validate_code_view_success(self, mock_filter):
        """Checks the expected behavior."""
        mock_hashing = Mock(side_effect={
            'hashed-decrypted-session-id': self.session_id,
            'hashed-test@example.com': self.email,
            'hashed-123456': self.code
        })
        mock_filter.return_value.first.return_value = FeedbackFormSession(
            session_identifier='hashed-decrypted-session-id',
            email_hash='hashed-test@example.com',
            confirmation_code_hash='hashed-123456',
            validation_attempts_left=5
        )
        with patch('feedback_form.views.hash_value', mock_hashing):
            response = self.client.post(
                self.validate_code_url,
                data={'email': self.email, 'code': '123456'},
                HTTP_X_REQUESTED_WITH='XMLHttpRequest',
                HTTP_X_FORM_SESSION_ID=self.session_id
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], True)
