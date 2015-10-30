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


import sys
import os
import optparse
import logging
import glob

from lxml import etree as et

from ioc_writer import ioc_api

log = logging.getLogger(__name__)


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


class IOCParseError(Exception):
    pass


class DowngradeIOCManager(object):
    def __init__(self):
        self.iocs = {}  # elementTree representing the IOC
        self.ioc_name = {}  # guid -> name mapping
        self.ioc_xml = {}
        self.iocs_10 = {}  # elementTree representing the IOC, used by ioc_manager.convert_to_10
        self.pruned_11_iocs = set()  # set representing pruned IOCs, used by ioc_manager.convert_to_10
        self.null_pruned_iocs = set()  # set representing null IOCs, used by ioc_manager.convert_to_10
        self.openioc_11_only_conditions = ['starts-with', 'ends-with', 'greater-than', 'less-than', 'matches']
        self.default_encoding = 'utf-8'

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
            try:
                self.parse(ioc_api.IOC(filename))
            except ioc_api.IOCParseError:
                log.exception('Parse Error')
                errors.append(filename)
        elif os.path.isdir(filename):
            log.info('loading IOCs from: {}'.format(filename))
            for fn in glob.glob(filename + os.path.sep + '*.ioc'):
                if not os.path.isfile(fn):
                    continue
                else:
                    try:
                        self.parse(ioc_api.IOC(fn))
                    except ioc_api.IOCParseError:
                        log.exception('Parse Error')
                        errors.append(fn)
        else:
            pass
        log.info('Parsed [{}] IOCs'.format(len(self)))
        return errors

    def parse(self, ioc_obj):
        """
        parse

        input: lxml.etree._ElementTree object, representing a OpenIOC 1.1 IOC.

        parses an ioc to populate
        """
        if ioc_obj is None:
            return
        iocid = ioc_obj.root.get('id')
        if iocid in self.iocs:
            sd = ioc_obj.metadata('.//short_description') or 'NoName'
            msg = 'duplicate IOC UUID [{}] [orig_shortName: {}][new_shortName: {}]'.format(iocid,
                                                                                           self.ioc_name[iocid],
                                                                                           sd)
            log.warning(msg)
        self.iocs[iocid] = ioc_obj
        return True

    def convert_to_10(self):
        """
        convert_to_10

        converts the iocs in self.iocs from openioc 1.1 to openioc 1.0 format.
        the converted iocs are stored in the dictionary self.iocs_10
        """
        if len(self) < 1:
            log.error('no iocs available to modify')
            return False
        log.info('Converting IOCs from 1.1 to 1.0.')
        errors = []
        for iocid in self.iocs:
            pruned = False
            ioc_obj_11 = self.iocs[iocid]
            metadata = ioc_obj_11.metadata
            # record metadata
            name_11 = metadata.findtext('.//short_description')
            keywords_11 = metadata.findtext('.//keywords')
            description_11 = metadata.findtext('.//description')
            author_11 = metadata.findtext('.//authored_by')
            created_date_11 = metadata.findtext('.//authored_date')
            last_modified_date_11 = ioc_obj_11.root.get('last-modified')
            links_11 = []
            for link in metadata.xpath('//link'):
                link_rel = link.get('rel')
                link_text = link.text
                links_11.append((link_rel, None, link_text))
            # get ioc_logic
            try:
                ioc_logic = ioc_obj_11.root.xpath('.//criteria')[0]
            except IndexError:
                log.exception(
                    'Could not find criteria nodes for IOC [{}].  Did you attempt to convert OpenIOC 1.0 iocs?'.format(
                        iocid))
                errors.append(iocid)
                continue
            try:
                tlo_11 = ioc_logic.getchildren()[0]
            except IndexError:
                log.exception(
                    'Could not find children for the top level criteria/children nodes for IOC [{}]'.format(iocid))
                errors.append(iocid)
                continue
            tlo_id = tlo_11.get('id')
            # record comment parameters
            comment_dict = {}
            for param in ioc_obj_11.parameters.xpath('//param[@name="comment"]'):
                param_id = param.get('ref-id')
                param_text = param.findtext('value')
                comment_dict[param_id] = param_text
            # create a 1.1 indicator and populate it with the metadata from the existing 1.1
            # we will then modify this new IOC to conform to 1.1 schema
            ioc_obj_10 = ioc_api.IOC(name=name_11, description=description_11, author=author_11, links=links_11,
                                     keywords=keywords_11, iocid=iocid)
            ioc_obj_10.root.attrib['last-modified'] = last_modified_date_11
            authored_date_node = ioc_obj_10.metadata.find('authored_date')
            authored_date_node.text = created_date_11

            # convert 1.1 ioc object to 1.0
            # change xmlns
            ioc_obj_10.root.attrib['xmlns'] = 'http://schemas.mandiant.com/2010/ioc'
            # remove published data
            del ioc_obj_10.root.attrib['published-date']
            # remove parameters node
            ioc_obj_10.root.remove(ioc_obj_10.parameters)
            # change root tag
            ioc_obj_10.root.tag = 'ioc'
            # metadata underneath the root node
            metadata_node = ioc_obj_10.metadata
            criteria_node = ioc_obj_10.top_level_indicator.getparent()
            for child in metadata_node:
                ioc_obj_10.root.append(child)
            ioc_obj_10.root.remove(metadata_node)
            ioc_obj_10.root.remove(criteria_node)
            criteria_node.tag = 'definition'
            ioc_obj_10.root.append(criteria_node)

            ioc_obj_10.top_level_indicator.attrib['id'] = tlo_id
            # identify indicator items with 1.1 specific operators
            # we will skip them when converting IOC from 1.1 to 1.0.
            ids_to_skip = set()
            indicatoritems_to_remove = set()
            for condition_type in self.openioc_11_only_conditions:
                for elem in ioc_logic.xpath('//IndicatorItem[@condition="%s"]' % condition_type):
                    pruned = True
                    indicatoritems_to_remove.add(elem)
            for elem in ioc_logic.xpath('//IndicatorItem[@preserve-case="true"]'):
                pruned = True
                indicatoritems_to_remove.add(elem)
            # walk up from each indicatoritem
            # to build set of ids to skip when downconverting
            for elem in indicatoritems_to_remove:
                nid = None
                current = elem
                while nid != tlo_id:
                    parent = current.getparent()
                    nid = parent.get('id')
                    if nid == tlo_id:
                        current_id = current.get('id')
                        ids_to_skip.add(current_id)
                    else:
                        current = parent
            # walk the 1.1 IOC to convert it into a 1.0 IOC
            try:
                self.convert_branch(tlo_11, ioc_obj_10.top_level_indicator, ids_to_skip, comment_dict)
            except IOCParseError:
                log.exception('Problem converting IOC [{}]'.format(iocid))
                errors.append(iocid)
                continue
            except Exception:
                log.exception('Unknown error occured while converting [{}]'.format(iocid))
                errors.append(iocid)
            # bucket pruned iocs / null iocs
            if not ioc_obj_10.top_level_indicator.getchildren():
                self.null_pruned_iocs.add(iocid)
            elif pruned is True:
                self.pruned_11_iocs.add(iocid)
            # Check the original to see if there was a comment prior to the root node, and if so, copy it's content
            comment_node = ioc_obj_11.root.getprevious()
            while comment_node is not None:
                log.debug('found a comment node')
                c = et.Comment(comment_node.text)
                ioc_obj_10.root.addprevious(c)
                comment_node = comment_node.getprevious()
            # Record the IOC
            # ioc_10 = et.ElementTree(root_10)
            self.iocs_10[iocid] = ioc_obj_10
        return errors

    def convert_branch(self, old_node, new_node, ids_to_skip, comment_dict=None):
        """
        convert_branch
            recursively walk a indicator logic tree, starting from a Indicator node.
            converts OpenIOC 1.1 Indicator/IndicatorItems to Openioc 1.0 and preserves order.

        input
            old_node: old node, an Indicator node, which we walk down to convert
            new_node: new node, an Indicator node, which we add new IndicatorItem and Indicator nodes too
            ids_to_skip: set of ids not to convert
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
            if node_id in ids_to_skip:
                continue
            if node.tag == 'IndicatorItem':
                negation = node.get('negate')
                condition = node.get('condition')
                if 'true' in negation.lower():
                    new_condition = condition + 'not'
                else:
                    new_condition = condition
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
                                                              nid=node_id)
                # set condition
                new_ii_node.attrib['condition'] = new_condition
                # set comment
                if node_id in comment_dict:
                    comment = comment_dict[node_id]
                    comment_node = et.Element('Comment')
                    comment_node.text = comment
                    new_ii_node.append(comment_node)
                # remove preserver-case and negate
                del new_ii_node.attrib['negate']
                del new_ii_node.attrib['preserve-case']
                new_node.append(new_ii_node)
            elif node.tag == 'Indicator':
                operator = node.get('operator')
                if operator.upper() not in ['OR', 'AND']:
                    raise IOCParseError('Indicator@operator is not AND/OR. [%s] has [%s]' % (node_id, operator))
                new_i_node = ioc_api.make_indicator_node(operator, node_id)
                new_node.append(new_i_node)
                self.convert_branch(node, new_i_node, ids_to_skip, comment_dict)
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
        source_iocs = set(source.keys())
        source_iocs = source_iocs.difference(self.pruned_11_iocs)
        source_iocs = source_iocs.difference(self.null_pruned_iocs)
        if not source_iocs:
            log.error('no iocs available to write out after removing pruned/null iocs')
            return False
        safe_makedirs(directory)
        output_dir = os.path.abspath(directory)
        log.info('Writing IOCs to %s' % (str(output_dir)))
        # serialize the iocs
        for iocid in source_iocs:
            ioc_obj = source[iocid]
            tree = ioc_obj.root.getroottree()
            try:
                ioc_encoding = tree.docinfo.encoding
            except:
                ioc_encoding = self.default_encoding
            self.ioc_xml[iocid] = et.tostring(tree, encoding=ioc_encoding, pretty_print=True, xml_declaration=True)
        # write the iocs to disk
        for iocid in source_iocs:
            fn = os.path.join(output_dir, iocid + '.ioc')
            f = open(fn, 'wb')
            f.write(self.ioc_xml[iocid])
            f.close()
        return True

    def write_pruned_iocs(self, directory=None, pruned_source=None):
        """
        write_pruned_iocs to a directory

        if directory is None, write the iocs to the current working directory
        """
        if pruned_source is None:
            pruned_source = self.pruned_11_iocs
        if len(pruned_source) < 1:
            log.error('no iocs available to write out')
            return False
        if not directory:
            directory = os.getcwd()
        if os.path.isfile(directory):
            log.error('cannot writes iocs to a directory')
            return False
        safe_makedirs(directory)
        output_dir = os.path.abspath(directory)
        # serialize the iocs
        for iocid in pruned_source:
            ioc_obj = self.iocs_10[iocid]
            tree = ioc_obj.root.getroottree()
            try:
                ioc_encoding = tree.docinfo.encoding
            except:
                ioc_encoding = self.default_encoding
            self.ioc_xml[iocid] = et.tostring(tree, encoding=ioc_encoding, pretty_print=True, xml_declaration=True)
        # write the iocs to disk
        for iocid in pruned_source:
            fn = os.path.join(output_dir, iocid + '.ioc')
            f = open(fn, 'wb')
            f.write(self.ioc_xml[iocid])
            f.close()
        return True


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
    iocm = DowngradeIOCManager()
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


def downgrade_options():
    opts = []
    opts.append(
        optparse.make_option('--iocs', '-i', dest='iocs', help='Directory to iocs or the ioc to process', default=None))
    opts.append(optparse.make_option('--output', '-o', dest='output',
                                     help='Directory to write iocs out too.  There will be three folders created in this directory.',
                                     default=None))
    return opts


if __name__ == "__main__":
    usage_str = "usage: %prog [options]"
    parser = optparse.OptionParser(usage=usage_str, option_list=downgrade_options())
    options, args = parser.parse_args()

    if not options.iocs:
        log.error('Must specify a directory of iocs or an ioc to process.')
        sys.exit(1)
    if not options.output:
        log.error('Must specify a output directory.')
        sys.exit(1)
    main(options)
