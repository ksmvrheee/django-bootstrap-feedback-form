Usage
-----
To add the form on your web page load and call the ``render_feedback_form`` template tag from the ``feedback_form`` tags module in a desired place of your Django template::

    {% load feedback_form %}
    {% render_feedback_form %}

If everything went as planned the form will be rendered at that part of a page.

The app offers some ways to customize it's behaviour. To read about them see `Customization <customization.rst>`_.