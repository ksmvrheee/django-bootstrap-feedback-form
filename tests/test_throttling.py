import logging

from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase


class FeedbackFormThrottleTests(APITestCase):
    """Tests for the throttling class for the app."""

    def setUp(self):
        logging.disable(logging.CRITICAL) # disabling logging during the tests time

    def tearDown(self):
        logging.disable(logging.NOTSET)  # enabling logging back after the tests are done

    @override_settings(FEEDBACK_FORM_THROTTLE_RATE='5/day')
    def test_throttling(self):
        """Checks if the throttling class FeedbackFormThrottle (applied for all endpoints) works as intended."""
        url = reverse('ajax_feedback_form_validation')

        for _ in range(5):
            response = self.client.post(url)
            self.assertNotEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

        response = self.client.post(url, data={'email': 'test@example.com'})
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)