"""
downgrade_11.py from ioc_writer
Created: 12/17/15

Purpose:  Provide a single reference class for converting an OpenIOC 1.1 document to OpenIOC 1.0.

This downgrade process is lossy as there are conditions, parameters and link metadata which may be present in the 1.1 indicator that cannot be expressed in the 1.0 indicator.
The data that is lost is detailed below:

Data that will be removed in the downgrade:

#.For items directly underneath the top-level Indicator node (OpenIOC/criteria/Indicator/@operator='OR'for a valid MIR IOC):

    #. Any IndicatorItems under the top which use the preserve-case attribute will be removed.
    #. Any IndicatorItems which use the conditions 'begins-with', 'ends-with', 'greater-than', 'less-than', or 'matches' will be removed.
    #. Any Indicator nodes which contains a IndicatorItem node underneath it which match the conditions described above in 1) & 2) will be removed.

#.Metadata:

    #. Any links which contain link/@href will lose the @href attribute.

#. Parmeters:

    #. Any parmeters which point to a Indicator node will be removed.
    #. Any parmeters which point to a IndicatorItem node which do not have param/@name='comment' set will be removed.

#. General:

    #. The published date, OpenIOC/@published-date, will be removed.

Usage example:
::
    iocm = DowngradeManager()
    iocm.insert(iocs_dir)
    errors = iocm.convert_to_10()
    output_dir = './iocs'
    iocm.write_iocs(output_dir)
    iocm.write_pruned_iocs(output_dir, iocm.pruned_11_iocs)
    iocm.write_pruned_iocs(output_dir, iocm.null_pruned_iocs

"""
# Stdlib
from __future__ import print_function
import logging
import os
# Third Party code
from lxml import etree as et
# Custom Code
import ioc_writer.ioc_api as ioc_api
import ioc_writer.utils as utils
from ioc_writer.managers import IOCManager

log = logging.getLogger(__name__)

__author__ = 'will.gibb'
__version__ = '0.0.1'


METADATA_ORDER_10 = ['short_description',
                     'description',
                     'keywords',
                     'authored_by',
                     'authored_date',
                     'links']
METADATA_REQUIRED_10 = ['authored_date']


class DowngradeError(ioc_api.IOCParseError):
    """
    Exception raised when there is an error in the conversion
    """
    pass


class DowngradeManager(IOCManager):
    """
    Convert the OpenIOC 1.1 documents into a 1.0 format.  The converts IOCs are stored in self.iocs_10.
    IOCs which would have all nodes removed from under their top-level OR would be added to self.null_pruned_iocs
    IOCs which have at least one node, but not all nodes, removed would be added to self.prunded_11_iocs.
    """
    def __init__(self):
        IOCManager.__init__(self)
        self.iocs_10 = {}  # elementTree representing the IOC, used by ioc_manager.convert_to_10
        self.pruned_11_iocs = set()  # set representing pruned IOCs, used by ioc_manager.convert_to_10
        self.null_pruned_iocs = set()  # set representing null IOCs, used by ioc_manager.convert_to_10
        self.openioc_11_only_conditions = ['starts-with', 'ends-with', 'greater-than', 'less-than', 'matches']
        self.default_encoding = 'utf-8'

    def convert_to_10(self):
        """
        converts the iocs in self.iocs from openioc 1.1 to openioc 1.0 format.
        the converted iocs are stored in the dictionary self.iocs_10
        :return: A list of iocid values which had errors downgrading.
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
            metadata_dictionary = {}
            for child in metadata_node:
                metadata_dictionary[child.tag] = child
            for tag in METADATA_REQUIRED_10:
                if tag not in metadata_dictionary:
                    msg = 'IOC {} is missing required metadata: [{}]'.format(iocid, tag)
                    raise DowngradeError(msg)
            for tag in METADATA_ORDER_10:
                if tag in metadata_dictionary:
                    ioc_obj_10.root.append(metadata_dictionary.get(tag))
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
            # noinspection PyBroadException
            try:
                self.convert_branch(tlo_11, ioc_obj_10.top_level_indicator, ids_to_skip, comment_dict)
            except DowngradeError:
                log.exception('Problem converting IOC [{}]'.format(iocid))
                errors.append(iocid)
                continue
            except Exception:
                log.exception('Unknown error occured while converting [{}]'.format(iocid))
                errors.append(iocid)
                continue
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
        Recursively walk a indicator logic tree, starting from a Indicator node.
        Converts OpenIOC 1.1 Indicator/IndicatorItems to Openioc 1.0 and preserves order.


        :param old_node: An Indicator node, which we walk down to convert
        :param new_node: An Indicator node, which we add new IndicatorItem and Indicator nodes too
        :param ids_to_skip: set of node @id values not to convert
        :param comment_dict: maps ids to comment values.  only applied to IndicatorItem nodes
        :return: returns True upon completion.
        :raises: DowngradeError if there is a problem during the conversion.
        """
        expected_tag = 'Indicator'
        if old_node.tag != expected_tag:
            raise DowngradeError('old_node expected tag is [%s]' % expected_tag)
        if not comment_dict:
            comment_dict = {}
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
                    raise DowngradeError('Indicator@operator is not AND/OR. [%s] has [%s]' % (node_id, operator))
                new_i_node = ioc_api.make_indicator_node(operator, node_id)
                new_node.append(new_i_node)
                self.convert_branch(node, new_i_node, ids_to_skip, comment_dict)
            else:
                # should never get here
                raise DowngradeError('node is not a Indicator/IndicatorItem')
        return True

    def write_iocs(self, directory=None, source=None):
        """
        Serializes IOCs to a directory.

        :param directory: Directory to write IOCs to.  If not provided, the current working directory is used.
        :param source: Dictionary contianing iocid -> IOC mapping.  Defaults to self.iocs_10. This is not normally modifed by a user for this class.
        :return:
        """
        """


        if directory is None, write the iocs to the current working directory
        source: allows specifying a different dictionry of elmentTree ioc objects
        """
        if not source:
            source = self.iocs_10
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
        utils.safe_makedirs(directory)
        output_dir = os.path.abspath(directory)
        log.info('Writing IOCs to %s' % (str(output_dir)))
        # serialize the iocs
        for iocid in source_iocs:
            ioc_obj = source[iocid]
            ioc_obj.write_ioc_to_file(output_dir=output_dir, force=True)
        return True

    def write_pruned_iocs(self, directory=None, pruned_source=None):
        """
        Writes IOCs to a directory that have been pruned of some or all IOCs.

        :param directory: Directory to write IOCs to.  If not provided, the current working directory is used.
        :param pruned_source: Iterable containing a set of iocids.  Defaults to self.iocs_10.
        :return:
        """
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
        utils.safe_makedirs(directory)
        output_dir = os.path.abspath(directory)
        # serialize the iocs
        for iocid in pruned_source:
            ioc_obj = self.iocs_10[iocid]
            ioc_obj.write_ioc_to_file(output_dir=output_dir, force=True)
        return True
