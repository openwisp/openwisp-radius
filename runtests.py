#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

sys.path.insert(0, 'tests')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'openwisp2.settings')

if __name__ == '__main__':
    from django.core.management import execute_from_command_line

    args = sys.argv
    args.insert(1, 'test')
    if not os.environ.get('SAMPLE_APP', False):
        args.insert(2, 'openwisp_radius')
    else:
        args.insert(2, 'openwisp2')
    # args.insert(3, '-v 3')
    execute_from_command_line(args)
