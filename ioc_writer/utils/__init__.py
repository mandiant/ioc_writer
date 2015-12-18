"""
__init__.py.py from ioc_writer
Created: 12/17/15

Purpose: Utility functions for use in ioc_writer
"""
# Stdlib
from __future__ import print_function
import logging
import os


__author__ = 'will.gibb'
log = logging.getLogger(__name__)

try:
    # noinspection PyUnboundLocalVariable,PyUnresolvedReferences
    WindowsError('Test')
except NameError:
    WindowsError = OSError


def safe_makedirs(fdir):
    """
    Make an arbitrary directory.  This is safe to call for Python 2 users.

    :param fdir: Directory path to make.
    :return:
    """
    if os.path.isdir(fdir):
        pass
        # print 'dir already exists: %s' % str(dir)
    else:
        try:
            os.makedirs(fdir)
        except WindowsError as e:
            if 'Cannot create a file when that file already exists' in e:
                log.debug('relevant dir already exists')
            else:
                raise WindowsError(e)
    return True
