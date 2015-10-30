# check_yara_rules.py
#
# Copyright 2013 Mandiant Corporation.  
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
# Script to quickly check a YARA signature file against a set of files.
#
import argparse
import logging
import os
import sys

log = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    log.exception('Could not import yara')
    sys.exit(1)


def check_rules(rules, fp):
    matches = rules.match(fp)
    if matches:
        log.info('Matched [%s] to %s' % (os.path.basename(fp), str(matches)))
        return True
    else:
        log.debug('No match for [%s]' % os.path.basename(fp))
        return False


def main(options):
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')
    if not options.verbose:
        logging.disable(logging.DEBUG)

    if not os.path.isfile(options.yara):
        log.error('Yara rules file is not a file')
        sys.exit(1)

    try:
        rules = yara.compile(options.yara)
    except yara.SyntaxError:
        log.exception('Failed to process rules.')
        sys.exit(1)

    path = options.fp
    if os.path.isfile(path):
        check_rules(rules, path)
    elif os.path.isdir(path):
        for fn in os.listdir(path):
            fp = os.path.join(path, fn)
            if os.path.isfile(fp):
                check_rules(rules, fp)
    else:
        log.error('input is not a file or a directory')
        sys.exit(1)
    sys.exit(0)


def makeargpaser():
    parser = argparse.ArgumentParser(description='Test a yara rule against a set of files, or file.')
    parser.add_argument('-y', '--yara', dest='yara', required=True, type=str,
                        help='File of yara rules to process.')
    parser.add_argument('-i', '--input', dest='fp', required=True, type=str,
                        help='Path of file or directory to check for yara matches. Will not recurse the directory."')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='Verbose output')
    return parser


if __name__ == "__main__":
    p = makeargpaser()
    opts = p.parse_args()
    main(opts)
