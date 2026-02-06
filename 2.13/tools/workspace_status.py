#!/usr/bin/env python

# This script will be run by bazel when the build process starts to
# generate key-value information that represents the status of the
# workspace. The output should be like
#
# KEY1 VALUE1
# KEY2 VALUE2
#
# If the script exits with non-zero code, it's considered as a failure
# and the output will be discarded.

from __future__ import print_function
import os
import subprocess
import sys

CMD = ['git', 'describe', '--always', '--match', 'v[0-9].*', '--dirty']
VERSION_FILE = os.path.join(os.path.dirname(__file__), '..', 'VERSION')


def revision_from_version_file():
    try:
        with open(VERSION_FILE, 'r') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('PLUGIN_VERSION'):
                    parts = line.split("'")
                    if len(parts) >= 2 and parts[1]:
                        return 'v' + parts[1]
    except IOError:
        return None
    return None


def revision_from_git():
    try:
        return subprocess.check_output(CMD).strip().decode('utf-8')
    except OSError as err:
        print('could not invoke git: %s' % err, file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as err:
        print('error using git: %s' % err, file=sys.stderr)
        sys.exit(1)


revision = revision_from_version_file()
if not revision:
    revision = revision_from_git()

print('STABLE_BUILD_OAUTH_LABEL %s' % revision)
