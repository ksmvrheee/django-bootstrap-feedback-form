from django.urls import path

from .views import *


urlpatterns = [
    path('ajax/validate-feedback-form/', feedback_form_view, name='ajax_feedback_form_validation'),
    path('ajax/confirm-email/', confirm_email_view_initial, name='ajax_email_confirmation'),
    path('ajax/reconfirm-email/', confirm_email_view_secondary, name='ajax_email_reconfirmation'),
    path('ajax/validate-confirmation-code/', validate_code_view, name='ajax_code_validation'),
    path('form_success/', form_success_view, name='form_success')
]