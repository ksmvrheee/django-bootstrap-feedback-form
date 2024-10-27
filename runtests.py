import os
import sys

import django
from django.core.management import call_command


def run_tests():
    os.environ['DJANGO_SETTINGS_MODULE'] = 'test_settings'
    django.setup()

    failures = call_command('test', 'tests')
    sys.exit(bool(failures))


if __name__ == '__main__':
    run_tests()
