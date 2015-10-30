# openioc_10_to_11.py
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
# Allows for the upgrade of OpenIOC 1.0 IOCs to OpenIOC 1.1 format
#

import glob
import logging
import os
import optparse
import sys
from lxml import etree as et
from ioc_writer import ioc_api, xmlutils

log = logging.getLogger(__name__)


class IOCParseError(Exception):
    pass


class UpgradeIOCManager(object):
    def __init__(self):
        self.iocs = {}
        self.iocs_11 = {}
        self.ioc_xml = {}

    def __len__(self):
        return len(self.iocs)

    def insert(self, filename):
        """
        insert(filedir)

        import [all] IOC(s) from a file or directory
        """
        errors = []
        if os.path.isfile(filename):
            log.info('loading IOC from: {}'.format(filename))
            if not self.parse(filename):
                log.warning('Failed to prase [{}]'.format(filename))
                errors.append(filename)
        elif os.path.isdir(filename):
            log.info('loading IOCs from: {}'.format(filename))
            for fn in glob.glob(filename + os.path.sep + '*.ioc'):
                if not os.path.isfile(fn):
                    continue
                else:
                    if not self.parse(fn):
                        log.warning('Failed to prase [{}]'.format(filename))
                        errors.append(fn)
        else:
            pass
        log.info('Parsed [%s] IOCs' % str(len(self)))
        return errors

    def parse(self, fn):
        ioc_xml = xmlutils.read_xml_no_ns(fn)
        if not ioc_xml:
            return False
        root = ioc_xml.getroot()
        iocid = root.get('id', None)
        if not iocid:
            return False
        self.iocs[iocid] = ioc_xml
        return True

    def convert_to_11(self):
        """
        converts the iocs in self.iocs from openioc 1.0 to openioc 1.1 format.
        the converted iocs are stored in the dictionary self.iocs_11
        """
        if len(self) < 1:
            log.error('No iocs available to modify.')
            return False
        log.info('Converting IOCs from 1.0 to 1.1')
        errors = []
        for iocid in self.iocs:
            ioc_xml = self.iocs[iocid]
            root = ioc_xml.getroot()
            if root.tag != 'ioc':
                log.error('IOC root is not "ioc" [%s].' % str(iocid))
                errors.append(iocid)
                continue
            name_10 = root.findtext('.//short_description')
            keywords_10 = root.findtext('.//keywords')
            description_10 = root.findtext('.//description')
            author_10 = root.findtext('.//authored_by')
            created_date_10 = root.findtext('.//authored_date')
            last_modified_date_10 = root.get('last-modified', None)
            if last_modified_date_10:
                last_modified_date_10 = last_modified_date_10.rstrip('Z')
            created_date_10 = created_date_10.rstrip('Z')
            links_10 = []
            for link in root.xpath('//link'):
                link_rel = link.get('rel', None)
                link_text = link.text
                links_10.append((link_rel, link_text, None))
            # get ioc_logic
            try:
                ioc_logic = root.xpath('.//definition')[0]
            except IndexError:
                log.exception(
                    'Could not find definition nodes for IOC [%s].  Did you attempt to convert OpenIOC 1.1 iocs?' % str(
                        iocid))
                errors.append(iocid)
                continue
            # create 1.1 ioc obj
            ioc_obj = ioc_api.IOC(name=name_10, description=description_10, author=author_10, links=links_10,
                                  keywords=keywords_10, iocid=iocid)
            ioc_obj.set_lastmodified_date(last_modified_date_10)
            ioc_obj.set_created_date(created_date_10)

            comment_dict = {}
            tlo_10 = ioc_logic.getchildren()[0]
            try:
                self.convert_branch(tlo_10, ioc_obj.top_level_indicator, comment_dict)
            except IOCParseError:
                log.exception('Problem converting IOC [{}]'.format(iocid))
                errors.append(iocid)
                continue
            for node_id in comment_dict:
                ioc_obj.add_parameter(node_id, comment_dict[node_id])
            self.iocs_11[iocid] = ioc_obj
        return errors

    def convert_branch(self, old_node, new_node, comment_dict={}):
        """
        convert_branch
            recursively walk a indicator logic tree, starting from a Indicator node.
            converts OpenIOC 1.0 Indicator/IndicatorItems to Openioc 1.1 and preserves order.

        input
            old_node: old node, an Indicator node, which we walk down to convert
            new_node: new node, an Indicator node, which we add new IndicatorItem and Indicator nodes too
            comment_dict: maps ids to comment values.  only applied to IndicatorItem nodes
        return
            returns True upon completiong
            may raise ValueError
        """
        expected_tag = 'Indicator'
        if old_node.tag != expected_tag:
            raise ValueError('old_node expected tag is [%s]' % expected_tag)
        for node in old_node.getchildren():
            node_id = node.get('id')
            if node.tag == 'IndicatorItem':
                condition = node.get('condition')
                negation = False
                if condition.endswith('not'):
                    negation = True
                    condition = condition[:-3]
                document = node.xpath('Context/@document')[0]
                search = node.xpath('Context/@search')[0]
                content_type = node.xpath('Content/@type')[0]
                content = node.findtext('Content')
                context_type = node.xpath('Context/@type')[0]
                new_ii_node = ioc_api.make_indicatoritem_node(condition=condition,
                                                              document=document,
                                                              search=search,
                                                              content_type=content_type,
                                                              content=content,
                                                              context_type=context_type,
                                                              negate=negation,
                                                              nid=node_id)
                # set comment
                comment = node.find('Comment')
                if comment is not None:
                    comment_dict[node_id] = comment.text
                new_node.append(new_ii_node)
            elif node.tag == 'Indicator':
                operator = node.get('operator')
                if operator.upper() not in ['OR', 'AND']:
                    raise IOCParseError('Indicator@operator is not AND/OR. [%s] has [%s]' % (node_id, operator))
                new_i_node = ioc_api.make_indicator_node(operator, node_id)
                new_node.append(new_i_node)
                self.convert_branch(node, new_i_node, comment_dict)
            else:
                # should never get here
                raise IOCParseError('node is not a Indicator/IndicatorItem')
        return True

    def write_iocs(self, directory=None, source=None):
        """
        write iocs from self.iocxml to a directory

        if directory is None, write the iocs to the current working directory
        source: allows specifying a different dictionry of elmentTree ioc objects
        """
        if not source:
            source = self.iocs
        if len(source) < 1:
            log.error('no iocs available to write out')
            return False
        if not directory:
            directory = os.getcwd()
        if os.path.isfile(directory):
            log.error('cannot writes iocs to a directory')
            return False
        safe_makedirs(directory)
        output_dir = os.path.abspath(directory)
        log.info('Writing IOCs to %s' % (str(output_dir)))
        # serialize the iocs
        for iocid in source:
            ioc_obj = source[iocid]
            tree = ioc_obj.root.getroottree()
            ioc_encoding = tree.docinfo.encoding
            self.ioc_xml[iocid] = et.tostring(tree, encoding=ioc_encoding, pretty_print=True, xml_declaration=True)
        # write the iocs to disk
        for iocid in self.ioc_xml:
            fn = os.path.join(output_dir, iocid + '.ioc')
            f = open(fn, 'wb')
            f.write(self.ioc_xml[iocid])
            f.close()
        return True


def safe_makedirs(fdir):
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


def main(options):
    # validate output dir
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')
    if os.path.isfile(options.output):
        log.error('Cannot set output directory to a file')
        sys.exit(1)
    # read in and convert iocs
    iocm = UpgradeIOCManager()
    iocm.insert(options.iocs)
    errors = iocm.convert_to_11()
    if errors:
        for iocid in errors:
            log.error('Failed to process: [%s]' % str(iocid))
    if len(iocm.iocs_11) == 0:
        log.error('No IOCs available to write out')
        sys.exit(1)
    # write 1.1 iocs
    if iocm.write_iocs(options.output, iocm.iocs_11):
        log.info('Wrote iocs out to %s' % options.output)
    else:
        log.error('failed to write iocs out')
    sys.exit(0)


def upgrade_options():
    opts = []
    opts.append(optparse.make_option('--iocs', '-i', dest='iocs', help='Directory of iocs or the ioc to process',
                                     action='store', default=None))
    opts.append(
        optparse.make_option('--output', '-o', dest='output', help='Directory to write iocs out too.', action='store',
                             default=None))
    return opts


if __name__ == "__main__":
    usage_str = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage_str, option_list=upgrade_options())
    options, args = parser.parse_args()

    if not options.iocs:
        log.error('Must specify a directory of iocs or an ioc to process.')
        sys.exit(1)
    if not options.output:
        log.error('Must specify a output directory.')
        sys.exit(1)
    main(options)
