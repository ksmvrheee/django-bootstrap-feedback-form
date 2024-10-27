django-bootstrap-feedback-form
______________________________

This app offers a way to create a responsive bootstrap-styled email-driven feedback form with a captcha and an email confirmation feature to your Django web-app hassle-free! The form itself is rendered on the page with the template tag while the form usage sessions are stored in the database. The initial validation and the UI manipulations are powered by JavaScript code which communicates with the server side via AJAX.

See the detailed documentation `here <https://github.com/ksmvrheee/django-bootstrap-feedback-form/blob/main/docs/index.rst>`_.

Quick Start
-----------
1. Install the package using pip::

    pip install django-bootstrap-feedback-form

2. Add 'feedback_form' to the INSTALLED_APPS setting of your Django project like this::

    INSTALLED_APPS = [
        ...,
        'feedback_form',
    ]

3. Include the URLconf of the app in your project urls.py something like this::

    path('feedback_form_urls/', include('feedback_form.urls')),

4. Obtain and add to your project ``settings.py`` the `reCaptcha v2 keys <https://cloud.google.com/recaptcha/docs/create-key-website>`_: the public one and the private one. Here and below shown a way to add such variables using `python-dotenv <https://github.com/theskumar/python-dotenv>`_ (while you can technically define them just as is in your code, it is highly discouraged)::

    RECAPTCHA_PUBLIC_KEY = getenv('RECAPTCHA_PUBLIC_KEY')
    RECAPTCHA_SECRET_KEY = getenv('RECAPTCHA_SECRET_KEY')

5. Define the Django email backend in your project ``settings.py`` (as shown in the `Django docs <https://docs.djangoproject.com/en/dev/topics/email/>`_). Don't forget to define ``EMAIL_TIMEOUT``::

    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_USE_SSL = True
    EMAIL_TIMEOUT = 20
    EMAIL_HOST = getenv('EMAIL_HOST')
    EMAIL_PORT = getenv('EMAIL_PORT')
    EMAIL_HOST_USER = getenv('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = getenv('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = getenv('FROM_EMAIL')
    SERVER_EMAIL = getenv('SERVER_EMAIL')

6. Define the ``FEEDBACK_EMAIL_INBOX`` variable with your desired email inbox to get messages::

    FEEDBACK_EMAIL_INBOX = getenv('FEEDBACK_EMAIL_INBOX')

7. Define in one of your project apps a view with the **named url** (the url *name* parameter) being 'form_redirect_address' that will be visited by a user after the successful submission of the form. It is not necessary but strongly advised in order to avoid some troubles with the url resolving::

    path('some_url_idk/', some_view_idk, name='form_redirect_address'),

8. Run ``python manage.py migrate feedback_form`` to create the app main model in the DB.

9. Load and call the ``render_feedback_form`` template tag from the ``feedback_form`` tags module in a desired place of your Django template::

    {% load feedback_form %}
    {% render_feedback_form %}

10. Launch the server and check that everything works fine.

Potential Problems and Liabilities
----------------------------------
There are few problems and legal liabilities associated with using this application.

1. It **uses cookies**. If you must make some notification to the user according to the laws in your jurisdiction, you should probably do it. Although these cookies pretty much should be considered strictly necessary and technical ones: they are used to identify a user and to prevent malfunction (and not in any form to spy or to collect some sensitive data), in some countries they still need to be stated.

2. It **sends a user data** (especially an email address) **over the SMTP protocol (or any other mean that you configure)**. This also may need some notice or something like that. Anyway, use only trusted SMTP providers.

3. If you use the ``mail_admins`` built-in Django logging handler (or something with a similar functionality), you may accidentally send a sensitive data (like an email or ip address) through the email. The ``@sensitive_variables`` decorator is used for every form-related view here to sanitize the data, but there's no warranty. This is applicable to all Django apps unfortunately.

4. Therefore, if applicable, you may need to establish some *Privacy Policy / Terms of Service* or something like that on your site or app.

5. Also some SMTP services tend to not return an errors even if sending the letter goes wrong. That means that it's impossible to catch the issues of that kind on the backend (or at least it is not optimal to do so). But it mainly affects some none-existing email address or host, so it should not affect the full cycle of the form submission (because of the email address confirmation feature), so it's probably fine. Probably.

For the detailed usage and customization suggestions consult the `docs <https://github.com/ksmvrheee/django-bootstrap-feedback-form/blob/main/docs/index.rst>`_.
