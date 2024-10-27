from django.conf import settings
from rest_framework.throttling import SimpleRateThrottle


class FeedbackFormThrottle(SimpleRateThrottle):
    scope = 'feedback_form'

    def get_rate(self):
        return getattr(settings, 'FEEDBACK_FORM_THROTTLE_RATE', '100/day')

    def get_cache_key(self, request, view):
        return self.cache_format % {
            'scope': self.scope,
            'ident': self.get_ident(request)
        }
