"""
upgrade_10.py from ioc_writer
Created: 12/17/15

Purpose: Provide a single reference class for converting OpenIOC 1.0 documents to 1.1.

This upgrade process is a non-lossy process, as all conditions that can be expressed in
OpenIOC 1.0 can also be expressed in OpenIOC 1.1.

Usage Example:
::
    iocm = UpgradeManager()
    iocm.insert(iocs_dir)
    iocm.convert_to_11()
    output_dir = './iocs'
    iocm.write_iocs(output_dir)

"""
# Stdlib
from __future__ import print_function
import glob
import logging
import os
# Third Party code
# Custom Code
import ioc_writer.ioc_api as ioc_api
import ioc_writer.utils as utils
import ioc_writer.utils.xmlutils as xmlutils


log = logging.getLogger(__name__)
__author__ = 'will.gibb'


class UpgradeError(ioc_api.IOCParseError):
    """
    Exception raised when there is an error in the conversion
    """
    pass


# We cannot use the IOCManager base class here since that assumes we are working with OpenIOC 1.1 documents.
class UpgradeManager(object):
    def __init__(self):
        self.iocs = {}
        self.iocs_11 = {}
        self.ioc_xml = {}

    def __len__(self):
        return len(self.iocs)

    def insert(self, filename):
        """
        Parses files to load them into memory and insert them into the class.

        :param filename: File or directory pointing to .ioc files.
        :return: A list of .ioc files which could not be parsed.
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
                        log.warning('Failed to parse [{}]'.format(filename))
                        errors.append(fn)
        else:
            pass
        log.info('Parsed [%s] IOCs' % str(len(self)))
        return errors

    def parse(self, fn):
        """
        Parses a file into a lxml.etree structure with namespaces remove.  This tree is added to self.iocs.

        :param fn: File to parse.
        :return:
        """
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
            except UpgradeError:
                log.exception('Problem converting IOC [{}]'.format(iocid))
                errors.append(iocid)
                continue
            for node_id in comment_dict:
                ioc_obj.add_parameter(node_id, comment_dict[node_id])
            self.iocs_11[iocid] = ioc_obj
        return errors

    def convert_branch(self, old_node, new_node, comment_dict=None):
        """
        recursively walk a indicator logic tree, starting from a Indicator node.
        converts OpenIOC 1.0 Indicator/IndicatorItems to Openioc 1.1 and preserves order.

        :param old_node: Indicator node, which we walk down to convert
        :param new_node: Indicator node, which we add new IndicatorItem and Indicator nodes too
        :param comment_dict: maps ids to comment values.  only applied to IndicatorItem nodes
        :return: True upon completion
        :raises: UpgradeError if there is a problem during the conversion.
        """
        expected_tag = 'Indicator'
        if old_node.tag != expected_tag:
            raise UpgradeError('old_node expected tag is [%s]' % expected_tag)
        if not comment_dict:
            comment_dict = {}
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
                    raise UpgradeError('Indicator@operator is not AND/OR. [%s] has [%s]' % (node_id, operator))
                new_i_node = ioc_api.make_indicator_node(operator, node_id)
                new_node.append(new_i_node)
                self.convert_branch(node, new_i_node, comment_dict)
            else:
                # should never get here
                raise UpgradeError('node is not a Indicator/IndicatorItem')
        return True

    def write_iocs(self, directory=None, source=None):
        """

        :param directory: Directory to write IOCs to.  If not provided, the current working directory is used.
        :param source:  Dictionary contianing iocid -> IOC mapping.  Defaults to self.iocs_11.
        :return:
        """
        """
        write iocs from self.iocxml to a directory

        if directory is None, write the iocs to the current working directory
        source: allows specifying a different dictionry of elmentTree ioc objects
        """
        if not source:
            source = self.iocs_11
        if len(source) < 1:
            log.error('no iocs available to write out')
            return False
        if not directory:
            directory = os.getcwd()
        if os.path.isfile(directory):
            log.error('cannot writes iocs to a directory')
            return False
        output_dir = os.path.abspath(directory)
        utils.safe_makedirs(output_dir)
        log.info('Writing IOCs to %s' % (str(output_dir)))
        # serialize the iocs
        for iocid in source:
            ioc_obj = source[iocid]
            ioc_obj.write_ioc_to_file(output_dir=output_dir, force=True)
        return True
