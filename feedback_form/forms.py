import logging

from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone

from .models import FeedbackFormSession
from .utils import hash_value

logger = logging.getLogger('feedback_form_app_logger')  # getting the logger to log stuff


class FeedbackForm(forms.Form):
    """
    A feedback form that allows a user to send an email message to a staff member.
    User must enter the email and confirm it (this logic is implemented in the views
    and on the frontend). The form works with the FeedbackFormSession model that saves
    the state of the user's session with the form. FeedbackForm performs a validation
    based on the model object retrieved from the db using the 'session_identifier'
    argument provided within the initializer method.
    """
    email = forms.EmailField()
    code = forms.DecimalField()
    message = forms.CharField()

    def __init__(self, *args, **kwargs):
        # fetching the 'session_identifier' argument and preventing it from
        # going further into the super class. 'session_identifier' is an identifier
        # used to retrieve the model instance needed to perform a validation with the db
        session_identifier = kwargs.pop('session_identifier', None)

        super().__init__(*args, **kwargs)

        if session_identifier is None:
            # the form was initialized without providing the 'session_identifier' argument
            # which probably means that it was initialized the wrong way or somehow accidentally
            logger.error('The FeedbackForm object was initialized without providing the "session_identifier" argument!')
            
            self.no_identifier = True
            self.critical_error = True

        else:
            session_identifier = hash_value(session_identifier)
            session_record = FeedbackFormSession.objects.filter(session_identifier=session_identifier).first()
            self.session_record = session_record

    def clean(self):
        if hasattr(self, 'no_identifier'):
            # the form object has no session identifier
            self.add_error(None, ValidationError(
                message='Critical error occurred while trying to process the form.',
                code='no_identifier'
            ))
            return None

        cleaned_data = super().clean()

        if self.session_record is None:
            # session record object does not exist
            # this shouldn't be reachable to the user, so most likely some error or abuse
            self.add_error(None, ValidationError(
                message='Critical error occurred while trying to process the form.',
                code='no_record'
            ))
            logger.warning('Session record with the session_identifier provided to the form object does not exist! '
                           'Seems like an abuse or an error.')
            self.critical_error = True

        if self.errors:
            if self.errors.get('email', False):
                # it is what it is...
                self.critical_error = True
            return cleaned_data

        if not self.session_record.submission_attempts_left:
            # user has no submission attempts left
            # this is used to prevent a spam with submissions
            self.add_error(None, ValidationError(
                message='The number of available attempts to send a message has been exhausted. '
                        'Please try requesting the code again.', code='no_attempts_left'
            ))
            self.session_record.delete()
            self.critical_error = True

            return cleaned_data

        # decreasing the submission attempts counter
        self.session_record.submission_attempts_left -= 1

        if timezone.now() > self.session_record.confirmation_code_expiry:
            # the session is expired
            self.add_error(None, ValidationError(
                message='We apologize, but the time for posting has expired.',
                code='time_expired'
            ))
            self.session_record.delete()
            self.critical_error = True

            return cleaned_data

        # hashing the values to compare them with those stored in the db
        email = hash_value(cleaned_data.get('email', ''))
        code = hash_value(str(cleaned_data.get('code', '')))

        if self.session_record.email_hash != email:
            # the email entered does not match
            self.add_error('email', ValidationError(
                message='The entered email address does not match the address to which the code was sent. '
                        'Please check your email and request the code again.', code='wrong_email'
            ))
            self.session_record.delete()
            self.critical_error = True

            return cleaned_data

        if self.session_record.confirmation_code_hash != code:
            # the confirmation code entered does not match
            if not self.session_record.validation_attempts_left:
                # user has no code validation attempts left
                self.add_error(None, ValidationError(
                    message='Incorrect code was entered and the number of available attempts '
                            'to validate it has been exhausted. Please try requesting the code again.',
                    code='wrong_code_and_no_validation_attempts'
                ))
                self.session_record.delete()
                self.critical_error = True

                return cleaned_data

            else:
                # user has at least one code validation attempt left
                self.add_error('code', ValidationError(
                    message='Incorrect code entered. Please, request the code again.',
                    code='wrong_code'
                ))

                # decreasing the number of validation attempts available
                # because an unintended validation of the code has just occurred
                self.session_record.validation_attempts_left -= 1
                self.session_record.save()
                return cleaned_data

        return cleaned_data
