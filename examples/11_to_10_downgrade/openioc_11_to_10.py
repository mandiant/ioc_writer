# openioc_11_to_10.py
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
# Allows for the downgrade of OpenIOC 1.1 IOCs to OpenIOC 1.0 format
#
import argparse
import logging
import os
import sys
from ioc_writer.managers.downgrade_11 import DowngradeManager

log = logging.getLogger(__name__)


def main(options):
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')
    # validate output dir
    if os.path.isfile(options.output):
        log.error('Cannot set output directory to a file')
        sys.exit(1)
    else:
        output_dir = os.path.join(options.output, 'unpruned')
    # read in and convert iocs
    iocm = DowngradeManager()
    iocm.insert(options.iocs)
    errors = iocm.convert_to_10()
    if errors:
        for fn in errors:
            log.error('Failed to process: [%s]' % str(fn))
    if len(iocm.iocs_10) == 0:
        log.error('No IOCs available to write out')
        sys.exit(1)
    # write 1.0 iocs
    if iocm.write_iocs(output_dir, iocm.iocs_10):
        log.info('Wrote unpruned iocs out to %s' % output_dir)
    else:
        log.error('failed to write unpruned iocs out')
    # write pruned 1.0 iocs
    output_dir = os.path.join(options.output, 'pruned')
    if iocm.write_pruned_iocs(output_dir, iocm.pruned_11_iocs):
        log.info('Wrote pruned iocs out to %s' % output_dir)
    else:
        log.error('failed to write pruned iocs out')
    # write null 1.0 iocs
    output_dir = os.path.join(options.output, 'null')
    if iocm.write_pruned_iocs(output_dir, iocm.null_pruned_iocs):
        log.info('Wrote null iocs out to %s' % output_dir)
    else:
        log.error('failed to write null iocs out')
    sys.exit(0)


def makeargpaser():
    parser = argparse.ArgumentParser(description='Downgrade IOCs from 1.1 to 1.0')
    parser.add_argument('-i', '--iocs', dest='iocs', required=True, type=str,
                        help='Directory to iocs or the ioc to process.')
    parser.add_argument('-o', '--output', dest='output', required=True, type=str,
                        help='Dictory to write IOCs too. There will be three folders created in this directory.')
    return parser


if __name__ == "__main__":
    p = makeargpaser()
    opts = p.parse_args()
    main(opts)
