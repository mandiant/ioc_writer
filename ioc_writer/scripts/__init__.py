# XXX Fill out docstring!
"""
__init__.py.py from ioc_writer
Created: 6/3/16

Purpose:

Examples:

Usage:

"""
# Stdlib
from __future__ import print_function
import argparse
import logging
import os
import sys

# Third Party code
# Custom Code

log = logging.getLogger(__name__)

__author__ = 'will.gibb'
__version__ = '0.0.1'


def main(options):
    if not options.verbose:
        logging.disable(logging.DEBUG)
    pass  # XXX Code goes here!


def makeargpaser():
    # XXX Fill in description!
    parser = argparse.ArgumentParser(description="I am a computer stop all the downloads!")
    parser.add_argument('-i', '--input', dest='input', required=True, action='store',
                        help='Input file.')
    parser.add_argument('-o', '--output', dest='output', required=True, action='store',
                        help='Output file.')
    parser.add_argument('-c', '--config', dest='config', required=True, action='store',
                        help='Configuration file')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true',
                        help='Enable verbose output')
    return parser


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s [%(filename)s:%(funcName)s]')
    p = makeargpaser()
    opts = p.parse_args()
    main(opts)