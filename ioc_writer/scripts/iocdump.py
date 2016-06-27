# iocdump.py
#
# Copyright 2016 FireEye
# Licensed under the Apache 2.0 license.  Developed for Mandiant by William
# Gibb.
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
#
# Allows for the upgrade of OpenIOC 1.0 IOCs to OpenIOC 1.1 format
#
# Stdlib
from __future__ import print_function
import argparse
import logging
import os
import sys
# Third Party code
# Custom Code
from ..managers import IOCManager

log = logging.getLogger(__name__)

def main(options):
    if not options.verbose:
        logging.disable(logging.DEBUG)
    iocm = IOCManager()
    for i in options.input:
        iocm.insert(i)
    for ioc_obj in iocm.iocs.values():
        if options.hide_params:
            ioc_obj.display_params = False
        print(ioc_obj)

def makeargpaser():
    parser = argparse.ArgumentParser(description="Display a textual representation of an IOC or directory of IOCs")
    parser.add_argument('input', type=str, nargs='+',
                        help='Input files or folders')
    parser.add_argument('-n', '--no-params', dest='hide_params', default=False, action='store_true',
                        help='Do not display parameters attached to an IOC.')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true',
                        help='Enable verbose output')
    return parser


def _main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s [%(filename)s:%(funcName)s]')
    p = makeargpaser()
    opts = p.parse_args()
    main(opts)

if __name__ == '__main__':
    _main()