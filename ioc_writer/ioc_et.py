# ioc_et.py
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
# Provides support for ioc_api.
#

import uuid
import datetime

from lxml import etree as et

##############################################
NSMAP = {'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
         'xsd': 'http://www.w3.org/2001/XMLSchema', }


def make_ioc_root(iocid=None):
    root = et.Element('OpenIOC', nsmap=NSMAP)
    root.attrib['xmlns'] = 'http://openioc.org/schemas/OpenIOC_1.1'
    if iocid:
        root.attrib['id'] = iocid
    else:
        root.attrib['id'] = get_guid()
    # default dates
    root.attrib['last-modified'] = '0001-01-01T00:00:00'
    root.attrib['published-date'] = '0001-01-01T00:00:00'
    return root


def make_metadata_node(name=None,
                       description='Automatically generated IOC',
                       author='IOC_et',
                       links=None,
                       keywords=None):
    metadata_node = et.Element('metadata')
    metadata_node.append(make_short_description_node(name))
    metadata_node.append(make_description_node(description))
    metadata_node.append(make_keywords_node(keywords))
    metadata_node.append(make_authored_by_node(author))
    metadata_node.append(make_authored_date_node())
    metadata_node.append(make_links_node(links))
    return metadata_node


def make_keywords_node(keywords=None):
    keywords_node = et.Element('keywords')
    if keywords:
        keywords_node.text = keywords
    return keywords_node


def make_short_description_node(name):
    description_node = et.Element('short_description')
    description_node.text = name
    return description_node


def update_node_text(node, text):
    node.text = text
    return node


def make_description_node(text):
    description_node = et.Element('description')
    description_node.text = text
    return description_node


def make_authored_by_node(author='ioc_et'):
    authored_node = et.Element('authored_by')
    authored_node.text = author
    return authored_node


def make_links_node(links=None):
    links_node = et.Element('links')
    if links:
        for rel, href, value in links:
            links_node.append(make_link_node(rel, value, href))
    return links_node


def set_root_lastmodified(root_node, date=None):
    if date:
        root_node.attrib['last-modified'] = date
    else:
        root_node.attrib['last-modified'] = get_current_date()


def set_root_published_date(root_node, date=None):
    if date:
        root_node.attrib['published-date'] = date
    else:
        root_node.attrib['published-date'] = get_current_date()


def set_root_created_date(root_node, date=None):
    date_node = root_node.find('.//authored_date')
    if date_node is None:
        raise ValueError('authored_date node does not exist.  IOC is not schema compliant.')
    if date:
        date_node.text = date
    else:
        date_node.text = get_current_date()


def make_criteria_node(indicator_node=None):
    definition_node = et.Element('criteria')
    if indicator_node is not None:
        if indicator_node.tag != 'Indicator':
            raise ValueError('IndicatorNode has the incorrect tag.')
        definition_node.append(indicator_node)
    return definition_node


def make_parameters_node():
    parameters_node = et.Element('parameters')
    return parameters_node


def make_param_node(nid, content, name='comment', ptype='string', ):
    param_node = et.Element('param')
    param_node.attrib['id'] = get_guid()
    param_node.attrib['ref-id'] = nid
    param_node.attrib['name'] = name
    value_node = et.Element('value')
    value_node.attrib['type'] = ptype
    value_node.text = content
    param_node.append(value_node)
    return param_node


##############################################

def make_authored_date_node():
    authored_node = et.Element('authored_date')
    authored_node.text = get_current_date()
    return authored_node


def make_link_node(rel, value, href=None):
    link_node = et.Element('link')
    link_node.attrib['rel'] = rel
    if href:
        link_node.attrib['href'] = href
    link_node.text = value
    return link_node


def make_context_node(document, search, context_type='mir'):
    context_node = et.Element('Context')
    context_node.attrib['document'] = document
    context_node.attrib['search'] = search
    if context_type:
        context_node.attrib['type'] = context_type
    return context_node


def make_content_node(ctype, content):
    content_node = et.Element('Content')
    content_node.attrib['type'] = ctype
    content_node.text = content
    return content_node


##############################################

def get_guid():
    return str(uuid.uuid4())


def get_current_date():
    # xsdDate format.  not TZ format.
    time = datetime.datetime.utcnow()
    timestring = time.strftime('%Y-%m-%dT%H:%M:%S')
    return timestring
