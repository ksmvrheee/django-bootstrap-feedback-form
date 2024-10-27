Prerequisites
-------------
In order to use this app some preliminary conditions must be met.

First, you'll need to configure the email backend of the Django framework for sending the emails. This is shown in the `Django docs <https://docs.djangoproject.com/en/dev/topics/email/>`_. It is done by defining the required config variables in the ``settings.py`` of the project. Don't forget to define ``EMAIL_TIMEOUT``::

    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_USE_SSL = True
    EMAIL_TIMEOUT = 20
    EMAIL_HOST = getenv('EMAIL_HOST')
    EMAIL_PORT = getenv('EMAIL_PORT')
    EMAIL_HOST_USER = getenv('EMAIL_HOST_USER')
    EMAIL_HOST_PASSWORD = getenv('EMAIL_HOST_PASSWORD')
    DEFAULT_FROM_EMAIL = getenv('FROM_EMAIL')
    SERVER_EMAIL = getenv('SERVER_EMAIL')

Second, you'll need to define in the ``settings.py`` the variables that are used by the app itself for rendering the reCaptcha widget, validating it's value and sending an email directly to the desired address.

``RECAPTCHA_PUBLIC_KEY`` and ``RECAPTCHA_SECRET_KEY`` store the public and the secret key of the reCaptcha v2 instance respectfully. If you never used reCaptcha, you can see the info about using it `here <https://cloud.google.com/recaptcha/docs/create-key-website>`_. ``FEEDBACK_EMAIL_INBOX`` stores the desired address for the submitted message to be sent::

    RECAPTCHA_PUBLIC_KEY = getenv('RECAPTCHA_PUBLIC_KEY')
    RECAPTCHA_SECRET_KEY = getenv('RECAPTCHA_SECRET_KEY')

    FEEDBACK_EMAIL_INBOX = getenv('FEEDBACK_EMAIL_INBOX')

Next it is strongly advised to define a redirect view to which a user will be redirected after the successful form submission. In one of your project apps create a view with the **named url** (the url *name* parameter) being 'form_redirect_address'. It is not necessary but strongly advised in order to avoid some troubles with the url resolving::

    path('some_url_idk/', some_view_idk, name='form_redirect_address'),

If everything was successfully installed and configured on the backend, you can proceed to finally add the form to one of your pages.

The form requires the ``Bootstrap css`` and minimal ``js`` files linked to the page. While you can technically override the ``Bootstrap`` css classes, the js component is used for displaying the modal. At the time of writing the app is adjusted to use ``Bootstrap 5.3.1`` version. Compatibility with ``Bootstrap 5.x.x`` is reasonably expected. You must include these files to the page manually. The ``Bootstrap js`` can be defined on the page after the form, but **it shall not be defined with a 'defer' attribute**!

Example::

    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <!-- Bootstrap CSS -->
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-4bw+/aepP/YC94hEpVNVgiZdgIC5+VKNBQNGCHeKRQN+PtmoHDEXuppvnDJzQIu9" crossorigin="anonymous">
    </head>
    <body>

        <!-- the feedback form is rendered here -->

        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js" integrity="sha384-HwwvtgBNo3bZJJLYd8oVXjrBZt8cqVSpeBNS5n7C8IVInixGAoxmnlMuBnhbgrkm" crossorigin="anonymous"></script>
    </body>

After satisfying all the prerequisites you can proceed to `Usage <usage.rst>`_.