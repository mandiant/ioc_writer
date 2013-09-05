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
import cStringIO as sio
from lxml import etree as et
import logging

# logging config
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')

def read_xml(filename):
    '''
    read_xml
    
    Use et to read in a xml file, or string, into a Element object.
    
    return: lxml._elementTree object or None
    '''
    parser = et.XMLParser(remove_blank_text = True)
    try:
        if os.path.exists(filename):
            return et.parse(filename, parser)
        else:
            d = sio.StringIO(filename)
            return et.parse(d, parser)
    except IOError:
        logging.exception('unable to open file [%s]' % (filename))
    except (XMLParseError, XMLSyntaxError), e:
        logging.exception('unable to parse XML [%s]' % (filename))
        return None
    return None

def remove_namespace(doc, namespace):
    '''
    XXX: http://homework.nwsnet.de/products/45be_remove-namespace-in-an-xml-document-using-elementtree

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    
    remove_namespace
    
    Takes in a ElementTree object and namespace value.  The length of that 
    namespace value is removed from all Element nodes within the document.
    This effectively removes the namespace from that document.
    
    Returns the source document.
    '''
    ns = u'{%s}' % namespace
    nsl = len(ns)
    #print 'DEBUG: removing',ns
    for elem in doc.getiterator():
        if elem.tag.startswith(ns):
            elem.tag = elem.tag[nsl:]
    return doc

def delete_namespace(parsedXML):
    '''
    delete_namespace
    
    Identifies the namespace associated with the root node of a XML document
    and removes that names from the document.
    
    Returns the sources document.
    '''
    #namespaces are lame, just nic it
    if parsedXML.getroot().tag.startswith('{'):
        root = parsedXML.getroot().tag
        end_ns = root.find('}')
        remove_namespace(parsedXML, root[1:end_ns])
    return parsedXML

def read_xml_no_ns(filename):
    '''
    read_xml_lxml_no_ns_no_blanks
    
    read in the file or data, populating a lxml._elementTree object
    stripping out namespaces
    
    input: filename representing a xml file or a string of xml data 
    
    return: lxml._elementTree object or None
    '''
    parsedXML = read_xml(filename)
    if parsedXML is None:
        return None
    return delete_namespace(parsedXML)
    