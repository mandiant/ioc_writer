# xmlutils.py
#
# Copyright 2013 Mandiant Corporation.  
# Licensed under the Apache 2.0 license.  Developed for Mandiant by William 
# Gibb and Seth.
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
# Provides an wrapper for et & reading in xml documents
#


import os.path
import logging
from lxml import etree as et

log = logging.getLogger(__name__)


def read_xml(filename):
    """
    Use et to read in a xml file, or string, into a Element object.

    :param filename: File to parse.
    :return: lxml._elementTree object or None
    """
    parser = et.XMLParser(remove_blank_text=True)
    isfile=False
    try:
        isfile = os.path.exists(filename)
    except ValueError as e:
        if 'path too long for Windows' in str(e):
            pass
        else:
            raise
    try:
        if isfile:
            return et.parse(filename, parser)
        else:
            r = et.fromstring(filename, parser)
            return r.getroottree()
    except IOError:
        log.exception('unable to open file [[}]'.format(filename))
    except et.XMLSyntaxError:
        log.exception('unable to parse XML [{}]'.format(filename))
        return None
    return None


def remove_namespace(doc, namespace):
    """
    Takes in a ElementTree object and namespace value.  The length of that
    namespace value is removed from all Element nodes within the document.
    This effectively removes the namespace from that document.

    :param doc: lxml.etree
    :param namespace: Namespace that needs to be removed.
    :return: Returns the source document with namespaces removed.
    """
    # http://homework.nwsnet.de/products/45be_remove-namespace-in-an-xml-document-using-elementtree
    #
    # Permission is hereby granted, free of charge, to any person obtaining
    # a copy of this software and associated documentation files (the
    # "Software"), to deal in the Software without restriction, including
    # without limitation the rights to use, copy, modify, merge, publish,
    # distribute, sublicense, and/or sell copies of the Software, and to
    # permit persons to whom the Software is furnished to do so, subject to
    # the following conditions:
    #
    # The above copyright notice and this permission notice shall be
    # included in all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    # EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    # NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    # LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    # WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    ns = '{{{}}}'.format(namespace)
    nsl = len(ns)
    # print 'DEBUG: removing',ns
    for elem in doc.getiterator():
        if elem.tag.startswith(ns):
            elem.tag = elem.tag[nsl:]
    return doc


def delete_namespace(parsed_xml):
    """
    Identifies the namespace associated with the root node of a XML document
    and removes that names from the document.

    :param parsed_xml: lxml.Etree object.
    :return: Returns the sources document with the namespace removed.
    """
    if parsed_xml.getroot().tag.startswith('{'):
        root = parsed_xml.getroot().tag
        end_ns = root.find('}')
        remove_namespace(parsed_xml, root[1:end_ns])
    return parsed_xml


def read_xml_no_ns(filename):
    """
    read in the file or data, populating a lxml._elementTree object
    stripping out namespaces

    :param filename: filename representing a xml file or a string of xml data
    :return: lxml._elementTree object or None
    """
    parsed_xml = read_xml(filename)
    if parsed_xml is None:
        return None
    return delete_namespace(parsed_xml)
