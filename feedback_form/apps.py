from django.apps import AppConfig
from django.conf import settings


class FeedbackFormConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'feedback_form'

    def ready(self):
        # setting up a logger for the app
        import logging
        logger = logging.getLogger('feedback_form_app_logger')

        if not logger.hasHandlers():
            log_file = settings.BASE_DIR / 'feedback_form_errors_and_warnings.log'
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.WARNING)
            formatter = logging.Formatter('\n%(asctime)s - %(filename)s\n%(message)s')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logger.setLevel(logging.WARNING)
