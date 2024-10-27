from django import template
from django.conf import settings


register = template.Library()


@register.inclusion_tag(filename='feedback_form/feedback_form.html')
def render_feedback_form():
    feedback_form_context = {'recaptcha_public_key': settings.RECAPTCHA_PUBLIC_KEY}

    return feedback_form_context
