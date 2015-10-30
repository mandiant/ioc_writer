# simple_ioc_writer.py
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
# Provides an example of using the ioc_api library
#
# 
#
# Takes in a CSV of ioc items, and generates a IOC from those items in the
# form of:
#    OR
#        AND
#            <term1> <condition1> <content1>
#            <term2> <condition2> <content2>
#            <term3> <condition3> <content3>
#            ...
#
# Alternatively, the following IOC can also be generated:
#    OR
#        <term1> <condition1> <content1>
#        <term2> <condition2> <content2>
#        <term3> <condition3> <content3>
#        ...
#    
# This structure allows the generation of a list of items that can easily be
# manipulated in a IOC editor such as IOCe.  
#
# The structure of the CSV is expected to be rows of data shaped like:
# condition, document, search, content_type, content
#
import argparse
import csv
import logging
import sys

from ioc_writer import ioc_api

log = logging.getLogger(__name__)


def create_ioc_object(ioc_name, items, and_or=True):
    ioc = ioc_api.IOC(name=ioc_name)
    top_level_or_node = ioc.top_level_indicator
    # build the definition
    if and_or:
        second_level_and_node = ioc_api.make_indicator_node('AND')
        top_level_or_node.append(second_level_and_node)
    for item in items:
        condition, document, search, content_type, content = tuple(item)
        # print condition, document, search, content_type, content
        ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content)
        if and_or:
            second_level_and_node.append(ii_node)
        else:
            top_level_or_node.append(ii_node)
    # update the last modified time
    ioc.set_lastmodified_date()
    return ioc


def process_file(filename):
    rows = []
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 5:
                log.error('row length less than 5 encountered')
                return None
            rows.append(row)
    return rows


def main(options):
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')
    items = process_file(options.src_file)
    if not items:
        log.error('Could not process items')
        log.error('Make sure the input is a CSV file containing condition, document, search, type, content fields')
        sys.exit(-1)
    or_only = options.or_format
    # create IOC
    if or_only:
        ioc = create_ioc_object(options.name, items, and_or=False)
    else:
        ioc = create_ioc_object(options.name, items)
    # Write out the IOC to a file
    ioc.write_ioc_to_file(options.output_dir)
    sys.exit(0)


def makeargpaser():
    parser = argparse.ArgumentParser(description='Create a simple IOC.')
    parser.add_argument('-s', '--source', dest='src_file', required=True, type=str,
                        help='source file (CSV) containing IOC data')
    parser.add_argument('-n', '--name', dest='name', help='ioc name', required=True, type=str)
    parser.add_argument('--or', dest='or_format', action='store_true', default=False,
                        help='Write out all terms under a OR statement.'
                             ' By default, terms are put under a OR-AND structure.')
    parser.add_argument('-o', '--output_dir', dest='output_dir', default=None,
                        help='location to write IOC to. default is current working directory')
    return parser


if __name__ == "__main__":
    p = makeargpaser()
    opts = p.parse_args()
    main(opts)
