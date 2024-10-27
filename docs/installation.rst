Installation
------------
1. Install the package using pip::

    pip install django-bootstrap-feedback-form

2. Add 'feedback_form' to the INSTALLED_APPS setting of your Django project like this::

    INSTALLED_APPS = [
        ...,
        'feedback_form',
    ]

3. Include the URLconf of the app in your project urls.py something like this::

    path('feedback_form_urls/', include('feedback_form.urls')),

4. Run ``python manage.py migrate feedback_form`` to create the app main model in the DB.

If nothing went wrong so far you can move to the next part of setting up this app: `Prerequisites <prerequisites.rst>`_.