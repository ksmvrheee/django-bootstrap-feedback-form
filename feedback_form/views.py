from datetime import timedelta

from django.core.exceptions import DisallowedHost
from django.http import Http404
from django.shortcuts import render
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.response import Response

from .forms import FeedbackForm
from .models import FeedbackFormSession
from .throttling import FeedbackFormThrottle
from .utils import *

logger = logging.getLogger('feedback_form_app_logger')  # getting the logger to log stuff


@sensitive_variables('request', 'data', 'email')
@api_view(['POST'])
@throttle_classes([FeedbackFormThrottle])
def feedback_form_view(request):
    """
    An endpoint for the AJAX-driven final validation of the feedback form. Includes a
    validation of the FeedbackForm itself, including some work with FeedbackFormSession model.
    If the validation performs successfully, sends a letter with the user's message to the email
    configured by the FEEDBACK_EMAIL_INBOX variable in the settings file. Returns the success
    status and the information about the errors occurred for the frontend if needed.
    """
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return Response({'error': 'Access denied.'}, status=403)

    if 'X-Form-Session-Id' in request.headers:
        session_identifier = vigenere_decrypt(request.headers.get('X-Form-Session-Id'))
    else:
        logger.warning('The AJAX request was performed to a form validation endpoint without specifying '
                       'an identifying header. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Identifying header is missing.'}, status=403)

    data = request.data

    email = data.get('email')
    code = data.get('code')
    message = data.get('message')

    if None in (session_identifier, email, code, message):
        logger.warning('The AJAX request was performed to a form validation endpoint without providing '
                       'all required fields. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Required fields are missing.'}, status=400)

    if not validate_email_address(email):
        # the email address is not valid
        return Response({
            'success': False,
            'error': 'Email looks incorrect, please try again.',
            'isErrorCritical': True
        }, status=400)

    form = FeedbackForm(data=data, session_identifier=session_identifier)

    if not form.is_valid():
        # form validation failed
        return Response({
            'success': False,
            'errors': form.errors,
            'isErrorCritical': hasattr(form, 'critical_error')
        }, status=400)

    else:
        # trying to send the letter to a staff member
        email_sending_result = convey_submitted_email(user_email=form.cleaned_data.get('email'),
                                                      message=form.cleaned_data.get('message'),
                                                      recipient=settings.FEEDBACK_EMAIL_INBOX)
        if not email_sending_result['success']:
            # some error while sending the letter
            form.session_record.save()

            return Response({
                'success': False,
                'errors': {'__all__': [email_sending_result['error'],]},
                'isErrorCritical': False
            }, status=503)

        else:
            # success
            form.session_record.delete()

            return Response({'success': True}, status=200)


def form_success_view(request):
    """
    A view to display the success message after the successful form submission.
    Should not be available to a user that didn't submit the form so raises error 404.
    Inside the view's js code there is a redirect which redirects user after showing them
    an info message and waiting for the timer to count. The redirection location depends
    on whether anywhere in the project the view with the named url 'form_redirect_address'
    is defined. If there is no view with such url name, a redirection address will be
    defined as an initial feedback form url that had to be set by js earlier.
    If it somehow was not set then js will redirect to the root of the site.
    """
    if not request.COOKIES.get('form_submitted', ''):
        raise Http404
    else:
        context = {}
        try:
            context['form_redirect_address'] = reverse('form_redirect_address')

        except NoReverseMatch:
            # no fallback view was defined

            # trying to obtain the cookie which contains an initial feedback form url
            # (that had to be set by js)
            referrer = request.COOKIES.get('referrer', False)
            # if it somehow was not set then js will redirect to the root of the site
            # if you wouldn't want it, you'd set a fallback view.
            context['form_redirect_address'] = referrer if referrer else None

        response = render(request, template_name='feedback_form/form_success.html', context=context)
        response.delete_cookie('form_submitted')

    return response


@sensitive_variables('request', 'data', 'email')
@api_view(['POST'])
@throttle_classes([FeedbackFormThrottle])
def confirm_email_view_initial(request):
    """
    An endpoint for the AJAX-driven confirmation of the email address.
    Requires the ReCaptcha token. Works with the FeedbackFormSession model.
    Returns the success status, a message and the actions for the frontend.
    """
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return Response({'error': 'Access denied.'}, status=403)

    if 'X-Form-Session-Id' in request.headers:
        session_identifier = vigenere_decrypt(request.headers.get('X-Form-Session-Id'))
    else:
        logger.warning('The AJAX request was performed to an email confirmation endpoint without specifying '
                       'an identifying header. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Identifying header is missing.'}, status=403)

    data = request.data

    recaptcha_token = data.get('recaptcha-token')
    email = data.get('email')

    if None in (session_identifier, recaptcha_token, email):
        logger.warning('The AJAX request was performed to an email confirmation endpoint without providing '
                       'all required fields. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Required fields are missing.'}, status=400)

    if not validate_email_address(email):
        # the email address is not valid
        return Response({
            'success': False,
            'error': 'Email looks incorrect, please try again.',
            'errorScope': 'general',
            'actions': [
                ['show', '#generalErrorMessage'],
                ['resetCaptcha']
            ]
        }, status=400)

    # reCaptcha validation
    captcha_validation_result = validate_recaptcha(recaptcha_token)

    # checking if the reCaptcha validation went successful
    if not captcha_validation_result['success']:
        # reCaptcha validation went unsuccessful
        return Response({
            'success': False,
            'error': captcha_validation_result['error'],
            'errorScope': 'general',
            'actions': [
                ['show', '#generalErrorMessage'],
                ['resetCaptcha']
            ]
        }, status=403)

    # generating the confirmation code
    confirmation_code = generate_confirmation_code()

    # sending the confirmation email message
    email_sending_result = send_confirmation_email(confirmation_code, email)

    # checking if sending of the confirmation message went successful
    if not email_sending_result['success']:
        # sending of the confirmation message went unsuccessful
        return Response({
            'success': False,
            'error': email_sending_result['error'],
            'errorScope': 'general',
            'actions': [
                ['show', '#generalErrorMessage'],
                ['resetCaptcha']
            ]
        }, status=503)

    # hashing the values for storage purposes
    hashed_identifier = hash_value(session_identifier)
    hashed_email = hash_value(email)
    hashed_code = hash_value(confirmation_code)

    # trying to obtain the session record object
    session_record = FeedbackFormSession.objects.filter(session_identifier=hashed_identifier).first()

    if session_record is None:
        # creating new session record object if it isn't there
        session_record = FeedbackFormSession(session_identifier=hashed_identifier,
                                             email_hash=hashed_email,
                                             confirmation_code_hash=hashed_code)
        session_record.save()

    else:
        # modifying the existing session record object
        session_record.email_hash = hashed_email
        session_record.confirmation_code_hash = hashed_code

        # resetting the values (because the user has been confirmed with a captcha)
        session_record.resending_attempts_left = 2
        session_record.validation_attempts_left = 10
        session_record.submission_attempts_left = 3
        session_record.cooldown_expiry = timezone.now() + timedelta(seconds=25)
        session_record.confirmation_code_expiry = timezone.now() + timedelta(minutes=60)

        session_record.save()

    return Response({
        'success': True,
        'message': 'An email with a confirmation code has been sent to the email address you provided. '
                   'Enter the received code in the field below.',
        'actions': [
            ['hide', '#emailConfirmationGroup'],
            ['show', '#generalInfoMessage'],
            ['startTimer'],
            ['enable', '#id_code'],
            ['show', '#codeFieldGroup']
        ]
    }, status=200)


@sensitive_variables('request', 'data', 'email')
@api_view(['POST'])
@throttle_classes([FeedbackFormThrottle])
def confirm_email_view_secondary(request):
    """
    An endpoint for the AJAX-driven reconfirmation of the email address.
    Does not require the ReCaptcha token, but decreases the number of the available
    attempts with every attempt by working with the FeedbackFormSession model.
    Returns the success status, a message and the actions for the frontend.
    """
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return Response({'error': 'Access denied.'}, status=403)

    if 'X-Form-Session-Id' in request.headers:
        session_identifier = vigenere_decrypt(request.headers.get('X-Form-Session-Id'))
    else:
        logger.warning('The AJAX request was performed to an email reconfirmation endpoint without specifying '
                       'an identifying header. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Identifying header is missing.'}, status=403)

    data = request.data

    email = data.get('email')

    if None in (session_identifier, email):
        logger.warning('The AJAX request was performed to an email reconfirmation endpoint without providing '
                       'all required fields. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Required fields are missing.'}, status=400)

    if not validate_email_address(email):
        # the email address is not valid
        return Response({
            'success': False,
            'error': 'Email looks incorrect, please try again.',
            'errorScope': 'general',
            'actions': [
                ['show', '#generalErrorMessage'],
                ['startTimer']
            ]
        }, status=400)

    # hashing the identifier
    hashed_identifier = hash_value(session_identifier)

    # trying to obtain the session record object
    session_record = FeedbackFormSession.objects.filter(session_identifier=hashed_identifier).first()

    if session_record is None:
        # session record does not exist
        # this shouldn't be reachable to the user, so most likely some error or abuse
        logger.warning('The AJAX request to an email reconfirmation endpoint contained a session identifier: '
                       f'{hashed_identifier}, that corresponds to an non-existing session record object.')

        return Response({
            'success': False,
            'error': 'There has been an error. Please save your data and try refreshing the page.',
            'errorScope': 'general',
            'actions': [
                ['hide', '#generalInfoMessage'],
                ['show', '#generalErrorMessage'],
                ['hide', '#codeFieldGroup'],
                ['clearTimer'],
                ['resetCaptcha']
            ]
        }, status=403)

    if not session_record.resending_attempts_left:
        # user has no resending attempts left, so the captcha must be reentered

        return Response({
            'success': False,
            'error': 'The number of repeated code requests has been exceeded. '
                     'Please check your email address carefully, perform the captcha '
                     'task again (check the box above) and click on the "confirm email" button.',
            'errorScope': 'general',
            'actions': [
                ['hide', '#generalInfoMessage'],
                ['show', '#generalErrorMessage'],
                ['hide', '#codeFieldGroup'],
                ['clearTimer'],
                ['resetCaptcha'],
                ['show', '#emailConfirmationGroup']
            ]
        }, status=403)

    # user still has some resending attempts left so decreasing them
    session_record.resending_attempts_left -= 1

    if timezone.now() < session_record.cooldown_expiry:
        # cooldown has not yet passed
        # user shouldn't be able to send a request during a cooldown, so most likely some error or abuse

        # updating the cooldown expiry value
        session_record.cooldown_expiry = timezone.now() + timedelta(seconds=25)
        session_record.save()

        return Response({
            'success': False,
            'error': 'Request frequency exceeded.',
            'errorScope': 'general',
            'actions': [
                ['show', '#generalErrorMessage'],
                ['startTimer']
            ]
        }, status=403)

    # generating the confirmation code
    confirmation_code = generate_confirmation_code()

    # sending the confirmation email message
    email_sending_result = send_confirmation_email(confirmation_code, email)

    # checking if the sending of the confirmation message went successful
    if not email_sending_result['success']:
        # sending of the confirmation message went unsuccessful
        session_record.cooldown_expiry = timezone.now() + timedelta(seconds=25)

        session_record.save()

        return Response({
            'success': False,
            'error': email_sending_result['error'],
            'errorScope': 'general',
            'actions': [
                ['hide', '#generalInfoMessage'],
                ['show', '#generalErrorMessage'],
                ['startTimerAfterError'],
            ]
        }, status=503)

    # hashing email and code for storage purposes
    hashed_email = hash_value(email)
    hashed_code = hash_value(confirmation_code)

    # updating the values
    session_record.email_hash = hashed_email
    session_record.confirmation_code_hash = hashed_code
    session_record.cooldown_expiry = timezone.now() + timedelta(seconds=25)
    session_record.confirmation_code_expiry = timezone.now() + timedelta(minutes=60)
    session_record.validation_attempts_left = 10

    session_record.save()

    return Response({
        'success': True,
        'message': 'The letter has been resent. Please check your email.',
        'actions': [
            ['show', '#generalInfoMessage'],
            ['startTimer']
        ]
    }, status=200)


@sensitive_variables('request', 'data', 'email')
@api_view(['POST'])
@throttle_classes([FeedbackFormThrottle])
def validate_code_view(request):
    """
    An endpoint for the AJAX-driven validation of the code entered as a part of email confirmation.
    Works with the FeedbackFormSession model and validates a compliance of an entered data with a record.
    Returns the success status, a message and the actions for the frontend.
    """
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        return Response({'error': 'Access denied.'}, status=403)

    if 'X-Form-Session-Id' in request.headers:
        session_identifier = vigenere_decrypt(request.headers.get('X-Form-Session-Id'))
    else:
        logger.warning('The AJAX request was performed to a code validation endpoint without '
                       'specifying an identifying header. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Identifying header is missing.'}, status=403)

    data = request.data

    email = data.get('email')
    confirmation_code = data.get('code')

    if None in (session_identifier, email, confirmation_code):
        logger.warning('The AJAX request was performed to a code validation endpoint without providing '
                       'all required fields. Might be the frontend malfunction or an act of abuse.')

        return Response({'error': 'Required fields are missing.'}, status=400)

    # hashing the identifier
    hashed_identifier = hash_value(session_identifier)

    # trying to obtain the session record object
    session_record = FeedbackFormSession.objects.filter(session_identifier=hashed_identifier).first()

    if session_record is None:
        # session record does not exist
        # this shouldn't be reachable to the user, so most likely some error or abuse
        logger.warning('The AJAX request to an code validation endpoint contained a session identifier: '
                       f'{hashed_identifier}, that corresponds to an non-existing session record object.')

        return Response({
            'success': False,
            'error': 'A critical error occurred while trying to validate the code.  '
                     'Please save the data and try to refresh the page.',
            'errorScope': 'codeField',
            'actions': [
                ['hide', '#generalInfoMessage'],
                ['hide', '#generalErrorMessage'],
                ['show', '#codeFieldGroupErrorMessage'],
                ['clearTimer'],
                ['disableInputFields'],
                ['disableButtons']
            ]
        }, status=403)

    if not session_record.validation_attempts_left:
        # user has no validation attempts left
        return Response({
            'success': False,
            'error': 'The number of available code validation attempts has been exceeded. '
                     'Please carefully check the entered email address and click on the '
                     'button to send the email with the code again.',
            'errorScope': 'codeField',
            'actions': [
                ['show', '#codeFieldGroupErrorMessage']
            ],
            'validationAttemptsLeft': 0
        }, status=403)

    # decreasing validation attempts
    session_record.validation_attempts_left -= 1
    session_record.save()

    # hashing email and code for comparison purposes
    hashed_email = hash_value(email)
    hashed_code = hash_value(confirmation_code)

    if session_record.email_hash != hashed_email:
        # entered email does not match
        return Response({
            'success': False,
            'error': 'The email address you entered does not match the one to which the code was sent. '
                     'Please carefully check the entered email address and request the letter again.',
            'errorScope': 'codeField',
            'actions': [
                ['show', '#codeFieldGroupErrorMessage']
            ],
            'validationAttemptsLeft': session_record.validation_attempts_left
        }, status=400)

    if session_record.confirmation_code_hash != hashed_code:
        # entered code does not match
        if not session_record.validation_attempts_left:
            # user got the confirmation code wrong on the last try
            return Response({
                'success': False,
                'error': 'The number of available code verification attempts has been exceeded. '
                         'Please carefully check the entered email address and request the letter again.',
                'errorScope': 'codeField',
                'actions': [
                    ['show', '#codeFieldGroupErrorMessage']
                ],
                'validationAttemptsLeft': 0
            }, status=403)
        else:
            # there is at least one more try
            return Response({
                'success': False,
                'error': 'Wrong code. Please try again.',
                'errorScope': 'codeField',
                'actions': [
                    ['show', '#codeFieldGroupErrorMessage']
                ],
                'validationAttemptsLeft': session_record.validation_attempts_left
            }, status=403)

    return Response({
        'success': True,
        'actions': [
            ['disable', '#id_email'],
            ['disable', '#id_code'],
            ['hide', '#emailConfirmationGroup'],
            ['hide', '#generalErrorMessage'],
            ['hide', '#generalInfoMessage'],
            ['hide', '#codeFieldGroup']
        ]
    }, status=200)
