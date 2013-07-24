# simple_ioc_writer.py
#
# William Gibb, william.gibb@mandiant.com
# Copyright 2013 Mandiant
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

import os
import sys
import uuid
import xml.etree.ElementTree as et
import csv
import datetime
import optparse

from ioc_writer import ioc_api

    
def create_ioc_object(ioc_name,items,and_or=True):
    IOC = ioc_api.IOC(name=ioc_name)
    top_level_or_node = IOC.top_level_indicator
    # build the definition
    if and_or:
        second_level_and_node = ioc_api.make_Indicator_node('AND')
        top_level_or_node.append(second_level_and_node)
    for item in items:
        condition, document, search, content_type, content = tuple(item)
        #print condition, document, search, content_type, content
        IndicatorItem_node = ioc_api.make_IndicatorItem_node(condition, document, search, content_type, content)
        if and_or:
            second_level_and_node.append(IndicatorItem_node)
        else:
            top_level_or_node.append(IndicatorItem_node)
    # update the last modified time
    IOC.set_lastmodified_date()
    return IOC
    
    
def process_file(filename):
    rows = []
    file = open(filename, 'r')
    reader = csv.reader(file)
    for row in reader:
        if len(row) < 5:
            print 'row length less than 5 encountered'
            return None
        #print row
        rows.append(row)
    return rows

def main(options):
    items = process_file(options.src_file)
    if not items:
        print 'Could not process items'
        print 'Make sure the input is a CSV file containing condition, document, search, type, content fields'
        sys.exit(-1)
    or_only = options.or_format
    # create IOC
    if or_only:
        IOC = create_ioc_object(options.name, items, and_or = False)
    else:
        IOC = create_ioc_object(options.name, items)
    # Write out the IOC to a file
    ioc_api.write_ioc(IOC.root, options.output_dir)
    sys.exit(0)
    
def writer_options():
    opts = []
    opts.append(optparse.make_option('-s','--source', dest='src_file', help='source file (CSV) containing IOC data', default=None))  # argument
    opts.append(optparse.make_option('-n','--name', dest='name', help='ioc name', default=None))  # argument
    opts.append(optparse.make_option('--or', dest='or_format', action = 'store_true', help='Write out all terms under a OR statemet.  By default, terms are put under a OR-AND structure.', default=False))  # argument
    opts.append(optparse.make_option('-o', '--output_dir', dest='output_dir', help='location to write IOC to. default is current working directory', default=None))
    return opts
    
if __name__ == "__main__":
    usage_str = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage_str, option_list=writer_options())
    options, args = parser.parse_args()
    
    if not options.src_file:
        print 'must specify source file'
        parser.print_help()
        sys.exit(-1)
        
    if not options.name:
        print 'must specify an ioc name'
        parser.print_help()
        sys.exit(-1)
    main(options)
    
