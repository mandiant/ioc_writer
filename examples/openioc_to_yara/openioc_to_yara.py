import os
import sys
import logging
import glob

import copy

from string import Template

# third party common
from lxml import etree as et
# third party - custom
from ioc_writer import ioc_api

# logging config
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s  [%(filename)s:%(funcName)s]')

class IOCParseError(Exception):
    pass

class yara:
    def __init__(self):
        self.YARA_TEMPLATE = Template("""rule ${rule_name}
{
    ${meta}
    
    ${strings}
    
    ${condition}
}
""")
        self.CONDITION_TEMPLATE = Template("""condition:
        ${condition}""")
        self.META_TEMPLATE = Template("""meta:
        ${meta}""")
        self.STRINGS_TEMPLATE = Template("""strings:
        ${strings}""")
        
    @classmethod
    def param_yara_wide(self):
        pass
    
    @classmethod
    def param_yara_ascii(self):
        pass
    
    @classmethod
    def param_yara_fullword(self):
        pass

class ioc_manager:
    def __init__(self):
        self.iocs = {} # elementTree representing the IOC
        self.ioc_name = {} # guid -> name mapping
        
        self.metadata_fields = ['short_description', 'description', 'keywords', 'authored_by', 'authored_date']
        
    def __len__(self):
        return len(self.iocs)
    
    def insert(self, filename):
        '''
        insert(filedir)
        
        import [all] IOC(s) from a file or directory
        '''
        errors = []
        if os.path.isfile(filename):
            logging.info('loading IOC from: %s' % (filename))
            self.parse(ioc_api.IOC(filename))
        elif os.path.isdir(filename):
            logging.info('loading IOCs from: %s' % (filename))
            for fn in glob.glob(filename+os.path.sep+'*.ioc'):
                if not os.path.isfile(fn):
                    continue
                else:
                    self.parse(ioc_api.IOC(fn))
        else:
            pass
        return errors
    
    def parse(self, IOC_obj):
        if IOC_obj is None:
            return
        iocid = IOC_obj.iocid
        if iocid in self.iocs:
            logging.warning('duplicate IOC UUID [%s] [orig_shortName: %s][new_shortName: %s]' % (iocid, self.ioc_name[iocid], IOC_obj.root.findtext('.//short_description') or 'NoName'))
        self.ioc_name[iocid] = IOC_obj.root.findtext('.//short_description') or 'NoName'
        self.iocs[iocid] = IOC_obj
    
    def emit_yara(self):
        if len(self) < 1:
            logging.error('No IOCs to convert')
        for iocid in self.iocs:
            print iocid
            ioc_obj = self.iocs[iocid]
            name = self.ioc_name[iocid]
            # handle metadata first
            metadata_string = self.get_yara_metadata(iocid)
            #print name
            #print metadata_string
            # build strings list
            strings_list = self.get_yara_stringlist(iocid)
            print strings_list
            
    def get_yara_stringlist(self, iocid):
        stringlist = []
        
        ioc_obj = self.iocs[iocid]
        for node in ioc_obj.top_level_indicator.xpath('.//IndicatorItem[Context/@search = "Yara/HexString" or Context/@search = "Yara/TextString" or Context/@search = "Yara/RegexString"]'):
            modifiers = []
            
            id = node.get('id')
            #print id
            condition = node.get('condition')
            context_node = node.find('Context')
            content_node = node.find('Content')
            context = context_node.get('search')
            
            params = ioc_obj.parameters.xpath('.//param[@ref-id="%s" and (@name="yara/wide" or @name="yara/ascii" or @name="yara/fullword")]' % str(id))
            pc = node.get('preserve-case',None)
            
            if context == 'Yara/HexString' and (len(params) > 0 or pc.lower() == 'True'):
                logging.error('Cannot apply string modifiers to Yara/HexString values')
            
            if pc.lower() == 'false':
                modifiers.append('nocase')
            for param in params:
                name = param.get('name', None)
                if name == 'yara/wide':
                    modifiers.append('wide')
                elif name == 'yara/ascii':
                    modifiers.append('ascii')
                elif name == 'yara/fullword':
                    modifiers.append('fullword')
                else:
                    logging.error('Unknown parameter name encountered[%s][%s]' % (str(name),str(param.get('id'))))
            string_modifier = ' '.join(modifiers)
            indicator_content = content_node.text
            temp_string = '$%s = "%s" %s' % (str(id), indicator_content, string_modifier)
            stringlist.append(temp_string)
        # build data for yara
        yara_string = ''
        for row in stringlist:
            yara_string += '        %s\n' % row
        return yara_string
            
                    
    def get_yara_metadata(self, iocid):
        metadata = []
        ioc_obj = self.iocs[iocid]
        for key in self.metadata_fields:
            value = ioc_obj.metadata.findtext(key, None)
            if value:
                # cleanup linebreaks
                value = value.replace('\n', ' ').replace('\r', ' ')
                temp_string = '%s = %s' % (str(key),str(value))
                metadata.append(temp_string)
        count = 1
        for link in ioc_obj.metadata.xpath('.//link'):
            rel = link.get('rel', None)
            if not rel:
                raise IOCParseError('link node without rel attribute. [%s] is not schema compliant' % (str(iocid)))
            href = link.get('href', None)
            text = link.text
            if text and href:
                value = '%s %s %s' % (rel, text, href)
            elif text and not href:
                value = '%s %s' % (rel, text)
            elif not text and href:
                value = '%s %s' % (rel, href)
            else:
                value = '%s' % rel
            key = 'link%s' % (str(count))
            # cleanup linebreaks
            value = value.replace('\n', ' ').replace('\r', ' ')
            temp_string = '%s = %s' % (str(key),str(value))
            metadata.append(temp_string)
            count = count + 1
        # build data for yara
        yara_string = ''
        for row in metadata:
            yara_string += '        %s\n' % row
        return yara_string
            
            


