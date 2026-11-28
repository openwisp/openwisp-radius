#!/usr/bin/env python

"""Run RADIUS tests and validate focused test labels."""

import os
import sys

from openwisp_utils.test.runner import (
    InvalidTestArgument,
    compile_test_label_pattern,
    parse_test_arguments,
    validate_test_labels,
)

sys.path.insert(0, "tests")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "openwisp2.settings")


def run_focused_tests(arguments):
    import django

    sample_modules = ("openwisp2.sample_radius.tests", "openwisp2.sample_users.tests")
    pattern = compile_test_label_pattern(
        module_roots=(
            "openwisp_radius.tests",
            "openwisp_radius.tests.test_api",
            "openwisp_radius.tests.test_counters",
            "openwisp_radius.tests.test_saml",
            "openwisp_radius.integrations.monitoring.tests",
        ),
        exact_modules=(
            *sample_modules,
            "openwisp2.integrations.tests",
            "openwisp_radius.integrations.monitoring.tests",
        ),
        allow_subpackages=True,
    )
    try:
        labels, flags = parse_test_arguments(
            arguments, pattern, ("--failfast", "--noinput"), require_label=True
        )
        sample_labels = [
            label for label in labels if label.group("module") in sample_modules
        ]
        if sample_labels and len(sample_labels) != len(labels):
            raise InvalidTestArgument(
                "Unsupported test argument: run sample app tests separately"
            )
        if sample_labels:
            os.environ["SAMPLE_APP"] = "1"
        if any(
            label.group("module").startswith("openwisp_radius.integrations.monitoring.")
            for label in labels
        ):
            os.environ["MONITORING_INTEGRATION"] = "1"
        sys.argv[1:] = ["test", *(label.group(0) for label in labels), *flags]
        django.setup()
        validate_test_labels(labels)
    except InvalidTestArgument as error:
        print(error, file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    from django.core.management import execute_from_command_line

    if sys.argv[1:2] == ["--focused"]:
        run_focused_tests(sys.argv[2:])
        execute_from_command_line(sys.argv)
        sys.exit(0)

    args = sys.argv
    args.insert(1, "test")
    if not os.environ.get("SAMPLE_APP", False):
        args.insert(2, "openwisp2.integrations")
        args.insert(3, "openwisp_radius")
    else:
        args.insert(2, "openwisp2")
    if os.environ.get("MONITORING_INTEGRATION", False):
        args.extend(["--tag", "radius_monitoring"])
    else:
        args.extend(["--exclude-tag", "radius_monitoring"])
    execute_from_command_line(args)
