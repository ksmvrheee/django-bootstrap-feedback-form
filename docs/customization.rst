Customization
-------------
If you want you can customize some aspects of the app behaviour.

First, you can override two email html templates: the first is for the letter that will be sent to user to confirm his email address and the other is for the letter that will be sent to the inbox containing the return email address and the message from the user.

The templates are written using a standard Django template language. If you want to override them you will need to place them in the main ``templates`` folder of your project (which is `specified <https://docs.djangoproject.com/en/dev/howto/overriding-templates/>`_ in your ``settings.py``) inside another folder which is named the same as the app.

So it goes::

    <your_project>/<your_templates_folder>/feedback_form/confirmation_email.html

or::

    <your_project>/<your_templates_folder>/feedback_form/submitted_email_report.html

for confirmation email template or submitted email report template respectfully.

Second, as for the layout of the form itself, you can of course place the form container (that template tag) into some another html container to manipulate it's position on the page. But it is really discouraged cause of the reCaptcha widget which is really poorly contained inside it's container and tends to escape it (especially on small devices). Additionally the implemented form container has the id ``#feedbackFormSection`` which can be used for some direct css applying.

So, if you really need to change the layout you can do something like this::

    <div class="py-0">
      {% render_feedback_form %}
    </div>

or::

    #feedbackFormSection {
      padding-top: 0;
      padding-bottom: 0;
    }

Of course, you can look up some css classes that the form uses and manually override some of their properties::

    .feedback-form-control:focus {
      border-color: #ffaacc;
    }

Let's look at some pythonic aspects to customize. For example, this app includes a logger wihch logs some errors and warnings. If you wish, you may intercept it and replace with you own logger that logs stuff the way you like it. The name of the logger is ``feedback_form_app_logger``. You can override it in your ``settings.py`` by updating the dictionary accessible by the 'logging' key of the `LOGGING settings collection <https://docs.djangoproject.com/en/dev/ref/logging/#default-logging-definition>`_. For example::

    LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        ...
    },
    'handlers': {
        ...
    },
    'loggers': {
        'feedback_form_app_logger': {
            ...  # define custom logging logic here
        },
      },
    }

Also there is a custom DRF throttling class applied to every AJAX-endpoint of the app. It is used to prevent a spam and to somehow attempt to counter the DDOS attacks. You can customize the number of requests to these endpoints per time unit `DRF style <https://www.django-rest-framework.org/api-guide/throttling/#setting-the-throttling-policy>`_. To do so you need to add ``FEEDBACK_FORM_THROTTLE_RATE`` variable to your ``settings.py`` with the DRF-formatted frequency value::

    FEEDBACK_FORM_THROTTLE_RATE = '10/hour'

The default value is '100/day'. You can limit it but keep in mind that the perfect use-case of interacting with the form consists of a minimum 3 requests.

Also it is really advised to set the `DRF setting <https://www.django-rest-framework.org/api-guide/metadata/#setting-the-metadata-scheme>`_ ``DEFAULT_METADATA_CLASS`` to None to avoid exposing the docstrings to a potential attacker. Example::

    REST_FRAMEWORK = {
      ...,
      'DEFAULT_METADATA_CLASS': None
    }

You are now familiar with some customization you can do here.

Before actually implementing the form you might want to look at `Potential Problems and Liabilities <potential_problems_and_liabilities.rst>`_.