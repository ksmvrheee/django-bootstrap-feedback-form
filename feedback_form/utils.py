import hashlib
import logging
import random
import re
from smtplib import SMTPException

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from requests import post, HTTPError, Timeout, RequestException, ConnectionError

logger = logging.getLogger('feedback_form_app_logger')  # getting the logger to log stuff


def validate_recaptcha(response_token: str,
                       secret_key: str = settings.RECAPTCHA_SECRET_KEY) -> dict:
    """
    Validates the reCaptcha token provided from the frontend
    after the user passes the reCaptcha task.

    :param response_token: the token that could be got from the frontend
        after the user passes the reCaptcha task.
    :param secret_key: the secret key that is given to a reCaptcha operator
        after the registration of a widget.
    :return: a dict with the info about the validation:
        'success': bool - True if the validation was
        successful, False if it was not.
        'error': str | None - a description of an
        occurred error or None if there is no error.
    """
    try:
        # making the  POST-request to the validation endpoint
        validation_request = post(
            url='https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': secret_key,
                'response': response_token
            }
        )
        # raising HTTPError if request was not successful
        validation_request.raise_for_status()
        result = validation_request.json()

        if 'success' in result:  # expected server behavior
            if result['success']:
                # the verification went fine
                return {
                    'success': True,
                    'error': None
                }
            else:
                # the verification went wrong
                return {
                    'success': False,
                    'error': 'The captcha task was failed or the token has expired. '
                             'Please try again.'
                }
        else:  # unexpected server behavior
            logger.error('An unusual response was received from the reCaptcha server while trying to '
                         f'validate the token: {result}')

            return {
                'success': False,
                'error': 'Invalid response from reCaptcha server. Please try again.'
            }

    except HTTPError as e:
        # HTTPError occurred
        logger.warning(f'HTTPError occurred during reCaptcha validation: {str(e)}', exc_info=True)

        return {
            'success': False,
            'error': 'HTTP error occurred while processing a request to the server. Please try again.'
        }

    except ConnectionError:
        # ConnectionError occurred
        return {
            'success': False,
            'error': 'An error occurred while connecting to the server. Please try again or refresh the page.'
        }

    except Timeout:
        # request timed out
        return {
            'success': False,
            'error': 'Server response timeout exceeded. Please try again.'
        }

    except RequestException:
        # other RequestException occurred
        return {
            'success': False,
            'error': 'There was an unexpected error. Please try again.'
        }


def validate_email_address(email_address: str) -> bool:
    """
    Validates email address using regular expression.
    Important: regular expression based test may perform wrong on
    a small amount of input data.

    :param email_address: the string representing the email address to validate.
    :return: True if email address is considered valid, False if it is not.
    """
    return bool(re.search(r'^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]'
                          r'+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]'
                          r'{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$', email_address))


def generate_confirmation_code() -> str:
    """
    Generates a random six-digit code as a string.

    :return: a string containing the generated code.
    """
    return str(random.randint(100000, 999999))


def vigenere_decrypt(ciphertext: str, vigenere_key_length: int = 10) -> str:
    """
    Decrypts the provided string using the Vigenere algorithm. The string itself
    must include the key it was encrypted with in the beginning.

    :param ciphertext: a string to decrypt combined with a key in the beginning.
    :param vigenere_key_length: the length of the used code.
    :return: a decrypted string (without the code).
    """
    key = ciphertext[:vigenere_key_length]
    cipher = ciphertext[vigenere_key_length:]

    plaintext = ''
    key_length = len(key)
    for i in range(len(cipher)):
        char = cipher[i]
        if char.isalpha():
            key_char = key[i % key_length]
            shift = ord(key_char.upper()) - 65
            char_code = ord(char)
            if char.islower():
                decrypted_char_code = (char_code - 97 - shift + 26) % 26 + 97
            else:
                decrypted_char_code = (char_code - 65 - shift + 26) % 26 + 65
            plaintext += chr(decrypted_char_code)
        else:
            plaintext += char
    return plaintext


def hash_value(value: str) -> str:
    """
    Hashes given value by sha256 from the standard hashlib module.

    :param value: any string to hash.
    :return: the hash of the given string.
    """

    hasher = hashlib.sha256()

    hasher.update(value.encode('utf-8'))
    hashed_value = hasher.hexdigest()

    return hashed_value


def send_confirmation_email(code: int | str, recipient: str) -> dict:
    """
    Sends a confirmation email to a recipient using the template 'confirmation_email.html'
    located in a 'templates' folder of the 'feedback_form' app:
    'feedback_form/templates/feedback_form/confirmation_email.html' (available for overriding).
    The template must have the '{{ code }}' variable inside for displaying the code.

    :param code: the code that will be sent
        by email to the recipient inside the template.
    :param recipient: the recipient of the letter.
        Must be a valid email address.
    :return: a dict with the info about the operation:
        'success': bool - True if the email sending was
        successful, False if it was not.
        'error': str | None - a description of an
        occurred error or None if there is no error.
    """

    template_name = 'feedback_form/confirmation_email.html'
    context = {'code': code}

    try:
        html_content = render_to_string(template_name, context)
        text_content = strip_tags(html_content)  # remove html tags from the content

        # creating the object for the letter, adding the text version first
        msg = EmailMultiAlternatives('Email Confirmation', text_content, to=[recipient])

        # adding the html version
        msg.attach_alternative(html_content, 'text/html')

        msg.send()

        # if everything went fine
        return {
            'success': True,
            'error': None
        }

    except ImproperlyConfigured as e:
        # Django mailing configs are improperly configured
        logger.error(f'\nDjango mailing configs are improperly configured! Details:{str(e)}.',
                     exc_info=True)
        return {
            'success': False,
            'error': 'We apologize, there was an error on our end. Please try again later.'
        }

    except SMTPException as e:
        # SMTP error occurred or connection is timed out
        logger.error(f'\nSMTP error has occurred while attempting to send an email. '
                     f'Details: {str(e)}', exc_info=True)

        return {
            'success': False,
            'error': 'We apologize, there was an error on our end. Please try again later.'
        }

    except Exception as e:
        # different error occurred
        logger.error(f'\nSome error has occurred while attempting to send an email. '
                     f'Details: {str(e)}', exc_info=True)

        return {
            'success': False,
            'error': 'We apologize, there was an error on our end. Please try again later.'
        }


def convey_submitted_email(user_email: str, message: str, recipient: str) -> dict:
    """
    Sends an email from the valid clear feedback form to the stuff member using the template
    'submitted_email_report.html' located in a 'templates' folder of the 'feedback_form' app:
    'feedback_form/templates/feedback_form/submitted_email_report.html' (available for overriding).
    The template must have the '{{ user_message }}' variable inside for displaying the text
    from the user and the '{{ user_email }}' inside for displaying  the user's email.

    :param message: a text of the message to convey.
    :param user_email: email of the user provided from the feedback form.
    :param recipient: the recipient of the letter (a staff member).
        Must be a valid email address.
    :return: a dict with the info about the operation:
        'success': bool - True if the email sending was
        successful, False if it was not.
        'error': str | None - a description of an
        occurred error or None if there is no error.
    """

    template_name = 'feedback_form/submitted_email_report.html'
    context = {'user_email': user_email, 'user_message': message}

    try:
        html_content = render_to_string(template_name, context)
        text_content = strip_tags(html_content)  # remove html tags from the content

        # creating the object for the letter, adding the text version first
        msg = EmailMultiAlternatives('New Message from the Feedback Form', text_content, to=[recipient])

        # adding the html version
        msg.attach_alternative(html_content, 'text/html')

        msg.send()

        # if everything went fine
        return {
            'success': True,
            'error': None
        }

    except ImproperlyConfigured as e:
        # Django mailing configs are improperly configured
        logger.error(f'\nDjango mailing configs are improperly configured! Details:{str(e)}.',
                     exc_info=True)
        return {
            'success': False,
            'error': 'We apologize, there was a critical error on our end. Please save your data and '
                     'try to send us a message later, or use other means of communication to contact us.'
        }

    except SMTPException as e:
        # SMTP error occurred or connection is timed out
        logger.error(f'\nSMTP error has occurred while attempting to send an email. '
                     f'Details: {str(e)}', exc_info=True)

        return {
            'success': False,
            'error': 'We apologize, there was an error on our end.'
        }

    except Exception as e:
        # different error occurred
        logger.error(f'\nSome error has occurred while attempting to send an email. '
                     f'Details: {str(e)}', exc_info=True)

        return {
            'success': False,
            'error': 'We apologize, there was an error on our end.'
        }
