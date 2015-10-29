# ioc_api.py
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
# Provides an API for creating OpenIOC 1.1 IOC objects.
#
import os
import re
import logging

from lxml import etree as et

import ioc_et
import xmlutils

log = logging.getLogger(__name__)


#XXX: Consider changing this to a dictionary, with condition values that point
# to the types of operators (string, datetime, etc) in order to do more 
# validation
valid_indicatoritem_conditions = ['is',
                                   'contains',
                                   'matches',
                                   'starts-with',
                                   'ends-with',
                                   'greater-than',
                                   'less-than',
                                   ]

date_regex = r'^[12][9012][0-9]{2}-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-6][0-9]:[0-6][0-9]$'
                                   
class IOCParseError(Exception):
    pass
                                   
class IOC(object):
    """
    Class for easy creation and manipulation of IOCs.

    class attributes
        id:                     Unique identifier for the ioc
        metadata:               The metadata node
        parameters:             The Parameters node
        top_level_indicator:    Top level Indicator node, typically a toplevel
                                OR node for a valid MIR IOC.
        root:                   Root node of the IOC (OpenIOC element)
    """
    def __init__(self,
                fn=None,
                name = None, 
                description = 'Automatically generated IOC', 
                author = 'IOC_api', 
                links = None,
                keywords = None,
                iocid = None):
        """
        creates an IOC class object, populating the class attributes from a
        file or by creating them.

        Input
            fn: This is a path to a file to open, or a string containing XML
                representing an IOC.
            name:       string, Name of the ioc
            description:    string, description of the ioc
            author:     string, author name/email address
            links:      list of tuples.  Each tuple should be in the form
                        (rel, href, value).
            keywords:   string.  This is normally a space delimited string of
                        values that may be used as keywords
            iocid: GUID for the IOC.  This should not be specified under normal circumstances.
        """
        self.root = None
        self.top_level_indicator = None
        self.parameters = None
        self.metadata = None
        if fn:
            ioc_parts = self.open_ioc(fn)
            self.root, self.metadata, self.top_level_indicator, self.parameters = ioc_parts
        else:
            ioc_parts = self.make_ioc(name, description, author, links, keywords, iocid)
            self.root, self.metadata, self.top_level_indicator, self.parameters = ioc_parts
        self.iocid = self.root.get('id','NoID')
            
    @classmethod
    def open_ioc(self, fn):
        """
                Opens an IOC file, or XML string.  Returns the root element, top level
                indicator element, and parameters element.  If the IOC or string fails
                to parse, an IOCParseError is raised.

                This does not need to be called if using the IOC class to open an IOC
                file.

                input
                    fn: This is a path to a file to open, or a string containing XML
                        representing an IOC.

                returns
                    a tuple containing three elementTree Element objects
                    The first element, the root, contains the entire IOC itself.
                    The second element, the top level OR indicator, allows the user to add
                        additional IndicatorItem or Indicator nodes to the IOC easily.
                    The third element, the parameters node, allows the user to quickly
                        parse the parameters.
                """
        parsed_xml = xmlutils.read_xml_no_ns(fn)
        if not parsed_xml:
            raise IOCParseError('Error occured parsing XML')
        root = parsed_xml.getroot()
        metadata_node = root.find('metadata')
        top_level_indicator = get_top_level_indicator_node(root)
        parameters_node = root.find('parameters')
        if parameters_node is None:
            # parameters node is not required by schema; but we add it if it is not present
            parameters_node = ioc_et.make_parameters_node()
            root.append(parameters_node)
        return (root, metadata_node, top_level_indicator, parameters_node)
    
    @classmethod    
    def make_ioc(self,
                name = None, 
                description = 'Automatically generated IOC', 
                author = 'IOC_api', 
                links = None,
                keywords = None,
                iocid = None):
        """
        This generates all parts of an IOC, but without any definition.

        It allows the caller to then add IndicatorItems/Indicator nodes to the
        top level OR statement.

        This does not need to be called if using the IOC class to create an IOC

        input
            name:   string, Name of the ioc
            description:    string, description of the iocs
            author: string, author name/email address
            links:  list of tuples.  Each tuple should be in the form
                (rel, href, value).
            keywords:   string.  This is normally a space delimited string of
                values that may be used as keywords
            iocid: GUID for the IOC.  This should not be specified under normal
                circumstances.

        returns
            a tuple containing three elementTree Element objects
            The first element, the root, contains the entire IOC itself.
            The second element, the top level OR indicator, allows the user to add
                additional IndicatorItem or Indicator nodes to the IOC easily.
            The third element, the parameters node, allows the user to quickly
                parse the parameters.

        """
        root = ioc_et.make_IOC_root(iocid)
        root.append(ioc_et.make_metadata_node(name, description, author, links))
        metadata_node = root.find('metadata')
        top_level_indicator = make_Indicator_node('OR')
        parameters_node = (ioc_et.make_parameters_node())
        root.append(ioc_et.make_criteria_node(top_level_indicator))
        root.append(parameters_node)
        ioc_et.set_root_lastmodified(root)
        return (root, metadata_node, top_level_indicator, parameters_node)

    def set_lastmodified_date(self, date=None):
        """
        Set the last modified date of a IOC to the current date.
        User may specify the date they want to set as well.

        input
            date:   Date value to set the last modified date to.  This should be
                in the xsdDate form.
                This defaults to the current date if it is not provided.
                xsdDate Form: YYYY-MM-DDTHH:MM:SS

        output:
            returns True
        """
        if date:
            match = re.match(date_regex, date)
            if not match:
                raise IOCParseError('last-modified date is not valid.  Must be in the form YYYY-MM-DDTHH:MM:SS')
        ioc_et.set_root_lastmodified(self.root, date)
        return True
    
    def set_published_date(self, date=None):
        """
        Set the published date of a IOC to the current date.
        User may specify the date they want to set as well.

        input
            date:   Date value to set the published date to.  This should be in the xsdDate form.
                    This defaults to the current date if it is not provided.
                    xsdDate Form: YYYY-MM-DDTHH:MM:SS
        output:
            returns True
        """
        if date:
            match = re.match(date_regex, date)
            if not match:
                raise IOCParseError('Published date is not valid.  Must be in the form YYYY-MM-DDTHH:MM:SS')
        ioc_et.set_root_published_date(self.root, date)
        return True
    
    def set_created_date(self, date=None):
        """
        Set the created date of a IOC to the current date.
        User may specify the date they want to set as well.

        input
            date:   Date value to set the created date to.  This should be in the xsdDate form.
                    This defaults to the current date if it is not provided.
                    xsdDate form: YYYY-MM-DDTHH:MM:SS
        output:
            returns True

        exception:
            will raise a ValueError if the authored_date node does not exist.

        """
        if date:
            match = re.match(date_regex, date)
            if not match:
                raise IOCParseError('Created date is not valid.  Must be in the form YYYY-MM-DDTHH:MM:SS')
        #XXX can this use self.metadata?
        ioc_et.set_root_created_date(self.root, date)
        return True
    
    def add_parameter(self, indicator_id, content, name='comment', ptype='string'):
        """
        Add a a parameter to the IOC.

        input
            id:         The unique Indicator/IndicatorItem id the parameter is
                        associated with.
            content:    The value of the parameter.
            name:       The name of the parameter.  This defaults to 'comment'.
            type:       The type of the parameter content.  This defaults to
                        'string'.

            All input values must be string or unicode objects.

        returns True

        Will raise a IOCParseError if the id is not associated with a Indicator
        or IndicatorItem id.
        """
        parameters_node = self.parameters
        criteria_node = self.top_level_indicator.getparent()
        # first check for duplicate id,name pairs    
        elems = parameters_node.xpath('.//param[@ref-id="{}" and @name="{}"]'.format(indicator_id, name))
        if len(elems) > 0:
            # there is no actual restriction on duplicate parameters
            log.info('Duplicate (id,name) parameter pair will be inserted [{}][{}].'.format(indicator_id, name))
        # now check to make sure the id is present in the IOC logic
        elems = criteria_node.xpath('.//IndicatorItem[@id="{}"]|.//Indicator[@id="{}"]'.format(indicator_id,indicator_id))
        if len(elems) == 0:
            raise IOCParseError('ID does not exist in the IOC [{}][{}].'.format(str(indicator_id), str(content)))
        parameters_node.append(ioc_et.make_param_node(indicator_id, content, name, ptype))
        return True
    
    def add_link(self, rel, value, href=None):
        """
        Add a Link metadata element to the IOC, with the

        input
            rel:    The type of link
            value:  The content of the link
            href:   An href value for the link.  This defaults to None
            rel:    The link/@rel value
            value:  The link/text() value
            href:   A uri or url value

        returns True
        """
        links_node = self.metadata.find('links')
        if links_node is None:
            links_node = ioc_et.make_links_node()
            self.metadata.append(links_node)
        link_node = ioc_et.make_link_node(rel,value,href)
        links_node.append(link_node)
        return True
    
    def update_name(self, name):
        """
        Update the name (short description) of an IOC

        This creates the short description node if it is not present.

        input
            name:   Value to set the short description too

        returns True.
        """
        short_desc_node = self.metadata.find('short_description')
        if short_desc_node is None:
            log.debug('Could not find short description node for [{}].'.format(str(self.iocid)))
            log.debug('Creating & inserting the short description node')
            short_desc_node = ioc_et.make_short_description_node(name)
            self.metadata.insert(0, short_desc_node)
        else:
            short_desc_node.text = name
        return True
        
    def update_description(self, description):
        """
        Update the description) of an IOC

        This creates the description node if it is not present.

        input
            description:   Value to set the description too

        returns True.
        """
        desc_node = self.metadata.find('description')
        if desc_node is None:
            log.debug('Could not find short description node for [{}].'.format(str(self.iocid)))
            log.debug('Creating & inserting the short description node')
            desc_node = ioc_et.make_description_node(description)
            insert_index = 0
            for child in self.metadata.getchildren():
                if child.tag == 'short_description':
                    index = self.metadata.index(child)
                    insert_index = index + 1
                    break
            self.metadata.insert(insert_index, desc_node)
        else:
            desc_node.text = description 
        return True
    
    def update_link_rel_based(self, old_rel, new_rel=None, new_text=None, single_link=False):
        """
        Update link nodes, based on the existing link/@rel values.

        This requires specifying a link/@rel value to update, and either a new
        link/@rel value, or a new link/text() value for all links which match
        the link/@rel value.  Optionally, only the first link which matches the
        link/@rel value will be modified.

        input
            old_rel:        The link/@rel value used to select link nodes to
                            update.
            new_rel:        The new link/@rel value
            new_text:       The new link/text() value
            single_link:    Determine if only the first, or multiple, linkes
                            are modified.

        Returns True, unless there are no links with link[@rel='old_rel']
        """
        links = self.metadata.xpath('./links/link[@rel="{}"]'.format(old_rel))
        if len(links) < 1:
            log.warning('No links with link/[@rel="{}"]'.format(str(old_rel)))
            return False
        if new_rel and not new_text:
            # update link/@rel value
            for link in links:
                link.attrib['rel'] = new_rel
                if single_link:
                    break
        elif not new_rel and new_text:
            # update link/@text() value
            for link in links:
                link.text = new_text
                if single_link:
                    break
        elif (new_rel and new_text):
            log.warning('Cannot update rel and text at the same time')
            return False
        else:
            log.warning('Must specify either new_rel or new_text arguments')
            return False
        return True
        
    def update_link_rewrite(self, old_rel, old_text, new_text, single_link=False):
        """
        Rewrite the text() value of a link based on the link/@rel and link/text() value.

        This is similar to update_link_rel_based but users link/@rel AND link/text() values
        to determine which links have their link/@text() values updated.

        input
            old_rel:        The link/@rel value used to select link nodes to
                            update.
            old_text:       The link/text() value used to select link nodes to
                            update.
            new_text:       The new link/text() value to set on link nodes.
            single_link:    Determine if only the first, or multiple, linkes
                            are modified.

        Returns True, unless there are no links with link/[@rel='old_rel' and text()='old_text']
        """
        links = self.metadata.xpath('./links/link[@rel="{}" and text()="{}"]'.format(old_rel, old_text))
        if len(links) < 1:
            log.warning('No links with link/[@rel="{}"and text()="{}"]'.format(str(old_rel),str(old_text)))
            return False
        for link in links:
            link.text = new_text
            if single_link:
                break
        return True
        
    def update_parameter(self, parameter_id, content=None, name=None, param_type=None):
        """
        Updates the parameter attached to an Indicator or IndicatorItem node.

        Input
            parameter_id:   The unique id of the parameter to modify
            content:        The value of the parameter.
            name:           The name of the parameter.
            param_type:     The type of the parameter content.

            All inputs must be strings or unicode objects.

        Returns True, unless no arguments are supplied.

        Will raise a IOCParseError if the parameter id is not present
        """
        if not (content or name or param_type):
            log.warning('Must specify at least the value/text(), param/@name or the value/@type values to update.')
            return False
        parameters_node = self.parameters
        elems = parameters_node.xpath('.//param[@id="{}"]'.format(parameter_id))
        if len(elems) != 1:
            msg = 'Did not find a single parameter with the supplied ID[{}]. Found [{}] parameters'.format(parameter_id,
                                                                                                           len(elems))
            raise IOCParseError(msg)

        param_node = elems[0]
        value_node = param_node.find('value')
        
        if name:
            param_node.attrib['name'] = name
        
        if value_node is None:
            msg = 'No value node is associated with param [{}].  Not updating value node with content or tuple.'\
                .format(parameter_id)
            log.warning(msg)
        else:
            if content:
                value_node.text = content
            if param_type:
                value_node.attrib['type'] = param_type
        return True
    
    def remove_link(self, rel, value=None, href=None):
        """

        Removes link nodes based on the function arguments.

        This can remove link nodes based on the following combinations of arguments:
            link/@rel
            link/@rel & link/text()
            link/@rel & link/@href
            link/@rel & link/text() & link/@href

        Input
            rel:    link/@rel value to remove.  Required.
            value   link/text() value to remove. This is used in conjunction with link/@rel.  Optional.
            href   link/@href value to remove. This is used in conjunction with link/@rel.  Optional.

        Returns False, or the number of link nodes removed.
        """
        links_node = self.metadata.find('links')
        if links_node is None:
            log.warning('No links node present')
            return False
        counter = 0
        links = links_node.xpath('.//link[@rel="{}"]'.format(rel))
        for link in links:
            if value and href:
                if link.text == value and link.attrib['href'] == href:
                    links_node.remove(link)
                    counter += 1
            elif value and not href:
                if link.text == value:
                    links_node.remove(link)
                    counter += 1
            elif not value and href:
                if link.attrib['href'] == href:
                    links_node.remove(link)
                    counter += 1
            else:
                links_node.remove(link)
                counter += 1
        return counter
        
    def remove_indicator(self, nid, prune=False):
        """
        Removes a Indicator or IndicatorItem node from the IOC.  By default,
        if nodes are removed, any children nodes are inherited by the removed
        node. It has the  ability to delete all children Indicator and
        IndicatorItem nodes underneath an Indicator node if the 'prune'
        argument is set.

        This will not remove the top level Indicator node from an IOC.
        If the id value has been reused within the IOC, this will remove the
        first node which contains the id value.

        This also removes any parameters associated with any nodes that are
        removed.

        inputs
            id:     The Indicator/@id or IndicatorItem/@id value indicating a
                    specific node to remove.
            prune:  Remove all children of the deleted node.

        Returns
            True if nodes are removed
            False if there are no nodes removed.
        """
        try:
            node_to_remove = self.top_level_indicator.xpath('//IndicatorItem[@id="{}"]|//Indicator[@id="{}"]'.format(str(nid),str(nid)))[0]
        except IndexError as e:
            log.warning('Node [{}] not present'.format(nid))
            return False
        if node_to_remove.tag == 'IndicatorItem':
            node_to_remove.getparent().remove(node_to_remove)
            self.remove_parameter(ref_id=nid)
            return True
        elif node_to_remove.tag == 'Indicator':
            if node_to_remove == self.top_level_indicator:
                raise IOCParseError('Cannot remove the top level indicator')
            if prune:
                pruned_ids = node_to_remove.xpath('.//@id')
                node_to_remove.getparent().remove(node_to_remove)
                for pruned_id in pruned_ids:
                    self.remove_parameter(ref_id=pruned_id)
            else:
                for child_node in node_to_remove.getchildren():
                    node_to_remove.getparent().append(child_node)
                node_to_remove.getparent().remove(node_to_remove)
                self.remove_parameter(ref_id=nid)
            return True
        else:
            raise IOCParseError('Bad tag found.  Expected "IndicatorItem" or "Indicator", got [[}]'.format(node_to_remove.tag))
        
    def remove_parameter(self, param_id=None, name=None, ref_id=None,):
        """
        Removes parameters based on function arguments.

        This can remove parameters based on the following param values:
            param/@id
            param/@name
            param/@ref_id

        input:
            param_id:   The id of the parameter to remove.
            name:       The name of the parameter to remove.
            ref_id:     The IndicatorItem/Indicator id of the parameter to remove.

            Each input is mutually exclusive.  Calling this function with multiple values set will cause  exception.  Calling this function without setting one value will throw cause exception.

        Returns the number of parameters removed (may be 0).

        May raise a IOCParseError
        """
        l = []
        if param_id:
            l.append('param_id')
        if name:
            l.append('name')
        if ref_id:
            l.append('ref_id')
        if len(l) > 1:
            raise IOCParseError('Must specify only param_id, name or ref_id.  Specified {}'.format(str(l)))
        elif len(l) <1:
            raise IOCParseError('Must specifiy an param_id, name or ref_id to remove a paramater')

        counter = 0
        parameters_node = self.parameters
        
        if param_id:
            params = parameters_node.xpath('//param[@id="{}"]'.format(param_id))
            for param in params:
                parameters_node.remove(param)
                counter += 1
        elif name:
            params = parameters_node.xpath('//param[@name="{}"]'.format(name))
            for param in params:
                parameters_node.remove(param)
                counter += 1
        elif ref_id:
            params = parameters_node.xpath('//param[@ref-id="{}"]'.format(ref_id))
            for param in params:
                parameters_node.remove(param)
                counter += 1
        return counter

    def remove_name(self):
        """
        Removes the name (short_description node) from the metadata node, if present.

        Returns True if the short_description node is removed.  Returns False if the node is not present.
        """
        short_description_node = self.metadata.find('short_description')
        if short_description_node is not None:
            self.metadata.remove(short_description_node)
            return True
        else:
            return False

    def remove_description(self):
        """
        Removes the description node from the metadata node, if present.

        Returns True if the description node is present.  Returns False if the node is not present.
        """
        description_node = self.metadata.find('description')
        if description_node is not None:
            self.metadata.remove(description_node)
            return True
        else:
            return False
            
    def write_ioc_to_file(self, output_dir=None):
        """
        Writes the IOC to a .ioc file.

        input
            output_dir: directory to write the ioc out to.  default is the current
            working directory.

        output: return True, unless an error occurs while writing the IOC.
        """
        return write_ioc(self.root, output_dir)
    
    def write_ioc_to_string(self):
        """
        Writes the IOC to a string.

        output: returns a string, which is the XML representation of the IOC.
        """
        return write_ioc_string(self.root)
    
def make_Indicator_node(operator, nid = None):
    """
    This makes a Indicator node element.  These allow the construction of a
        logic tree within the IOC.

    input
        operator:   'AND' or 'OR'.
        nid: a string value.  This is used to provide a GUID for the Indicator.
            The ID should NOT be specified under normal circumstances.

    return: elementTree element
    """
    Indicator_node = et.Element('Indicator')
    if nid:
        Indicator_node.attrib['id'] = nid
    else:
        Indicator_node.attrib['id'] = ioc_et.get_guid()
    if operator.upper() not in ['AND','OR']:
        raise ValueError('Indicator operator must be "AND" or "OR".')
    Indicator_node.attrib['operator'] = operator.upper()
    return Indicator_node

def make_IndicatorItem_node(condition,
                            document, 
                            search, 
                            content_type, 
                            content, 
                            preserve_case = False,
                            negate = False,
                            context_type = 'mir', 
                            nid = None):
    """
    This makes a IndicatorItem element.  This contains the actual threat
    intelligence in the IOC.

    input
        condition: This is the condition of the item ('is', 'contains',
            'matches', etc).
        document: String value.  Denotes the type of document to look for
            the encoded artifact in.
        search: String value.  Specifies what attribute of the doucment type
            the encoded value is.
        content_type: This is the display type of the item, which is derived
            from the iocterm for the search value.
        content: a string value, containing the data to be identified.
        preserve_case: Boolean value.  Specify if the
            IndicatorItem/content/text() is case sensitive.
        negate: Boolean value.  Specify if the IndicatorItem/@condition is
            negated, ie:
                @condition = 'is' & @negate = 'true' would be equal to the
                @condition = 'isnot' in OpenIOC 1.0.
        context_type: a string value, giving context to the document/search
            information.  This defaults to 'mir'.
        nid: a string value.  This is used to provide a GUID for the IndicatorItem
            The ID should NOT be specified under normal circumstances.

    returns
        an elementTree Element item

    """
    # validate condition
    if condition not in valid_indicatoritem_conditions:
        raise ValueError('Invalid IndicatorItem condition [{}]'.format(condition))
    IndicatorItem_node = et.Element('IndicatorItem')
    if nid:
        IndicatorItem_node.attrib['id'] = nid
    else:
        IndicatorItem_node.attrib['id'] = ioc_et.get_guid()
    IndicatorItem_node.attrib['condition'] = condition
    if preserve_case:
        IndicatorItem_node.attrib['preserve-case'] = 'true'
    else:
        IndicatorItem_node.attrib['preserve-case'] = 'false'
    if negate:
        IndicatorItem_node.attrib['negate'] = 'true'
    else:
        IndicatorItem_node.attrib['negate'] = 'false'
    context_node = ioc_et.make_context_node(document, search, context_type)
    content_node = ioc_et.make_content_node(content_type, content)
    IndicatorItem_node.append(context_node)
    IndicatorItem_node.append(content_node)
    return IndicatorItem_node

def get_top_level_indicator_node(root_node):
    """
    This returns the first top level Indicator node under the criteria node.

    input
        root:   root node of an IOC

    return
        The top level level In
    """
    if root_node.tag != 'OpenIOC':
        raise IOCParseError('Root tag is not "OpenIOC" [{}].'.format(root_node.tag))
    elems = root_node.xpath('criteria/Indicator')
    if len(elems) == 0:
        log.warning('No top level Indicator node found.')
        return None
    elif len(elems) > 1:
        log.warning('Multiple top level Indicator nodes found.  This is not a valid MIR IOC.')
        return None
    else:
        top_level_indicator_node = elems[0]
    if top_level_indicator_node.get('operator').lower() != 'or':
        log.warning('Top level Indicator/@operator attribute is not "OR".  This is not a valid MIR IOC.')
    return top_level_indicator_node
    
def write_ioc(root, output_dir=None):
    """
    writes an IOC, as defined by a set of etree Elements, to a .IOC file.

    input
        root: etree Element to write out.  Should have the tag 'OpenIOC'
        output_dir: directory to write the ioc out to.  default is current
        working directory.

    output: return True, unless an error occurs while writing the IOC.
    """
    root_tag = 'OpenIOC'
    if root.tag != root_tag:
        raise ValueError('Root tag is not "{}".'.format(root_tag))
    default_encoding = 'utf-8'
    tree = root.getroottree()
    try:
        encoding = tree.docinfo.encoding
    except:
        log.debug('Failed to get encoding from docinfo')
        encoding = default_encoding
    ioc_id = root.attrib['id']
    fn = ioc_id + '.ioc'
    if output_dir:
        fn = os.path.join(output_dir, fn)
    else:
        fn = os.path.join(os.getcwd(),fn)
    try:
        fout = open(fn, 'wb')
        fout.write(et.tostring(tree, encoding=encoding, xml_declaration=True, pretty_print = True))
        fout.close()
    except (IOError, OSError):
        log.exception('Failed to write out IOC')
        return False
    except:
        raise
    return True

def write_ioc_string(root):
    """
    writes an IOC, as defined by a set of etree Elements, to a String.

    input
        root: etree Element to write out.  Should have the tag 'OpenIOC'

    output: return the XML as String.
    """
    root_tag = 'OpenIOC'
    if root.tag != root_tag:
        raise ValueError('Root tag is not "{}".'.format(root_tag))
    default_encoding = 'utf-8'
    tree = root.getroottree()
    try:
        encoding = tree.docinfo.encoding
    except:
        log.debug('Failed to get encoding from docinfo')
        encoding = default_encoding
    return et.tostring(tree, encoding=encoding, xml_declaration=True, pretty_print = True)
