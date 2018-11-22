#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

sys.path.insert(0, "tests")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

if __name__ == "__main__":
    from django.core.management import execute_from_command_line
    args = sys.argv
    args.insert(1, "test")
    if 'settings_subscriptions' in sys.argv:
        args.insert(2, "openwisp_radius.subscriptions")
    else:
        args.insert(2, "openwisp_radius.tests")
    execute_from_command_line(args)
