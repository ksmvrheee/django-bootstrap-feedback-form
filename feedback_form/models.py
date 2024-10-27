from datetime import timedelta

from django.db import models
from django.utils import timezone


class FeedbackFormSession(models.Model):
    """
    A model to store an information about the session of the filling of the
    feedback form by user. User is identified by the session_identifier - the value
    stored in the cookies that is defined by the js function on the frontend. Works
    with FeedbackForm and the ajax-based views.
    """
    session_identifier = models.CharField(max_length=255)
    email_hash = models.CharField(max_length=128)
    confirmation_code_hash = models.CharField(max_length=128)
    resending_attempts_left = models.IntegerField(default=2)
    validation_attempts_left = models.IntegerField(default=10)
    submission_attempts_left = models.IntegerField(default=3)
    cooldown_expiry = models.DateTimeField()
    confirmation_code_expiry = models.DateTimeField()

    def save(self, *args, **kwargs):
        # defining the initial expiry values based on the current time after the creating of an object
        if not self.pk:
            self.cooldown_expiry = timezone.now() + timedelta(seconds=25)
            self.confirmation_code_expiry = timezone.now() + timedelta(minutes=60)

        super().save(*args, **kwargs)
