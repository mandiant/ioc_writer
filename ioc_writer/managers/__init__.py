"""
__init__.py.py from ioc_writer
Created: 12/17/15

Purpose: Provide a generic IOC management class for parsing a large set of IOCs into memory.
"""
# Stdlib
from __future__ import print_function
import glob
import logging
import os
# Custom Code
from ioc_writer import ioc_api

log = logging.getLogger(__name__)

__author__ = 'will.gibb'


class IOCManager(object):
    """
    Generic class for managing IOC objects in memory.
    This base class just provides a mechanism for loading the .ioc files into memory and storing them in a dictionary.
    This is designed to be subclassed.
    The original parsing can be extended by a subclass which just needs to have a callback function registered which will consume a IOC object.

    The following is a subclass example:
    ::
        class IOCTestManager(managers.IOCManager):
            def __init__(self):
                managers.IOCManager.__init__(self)
                self.child_count = {}
                self.register_parser_callback(self.parse_callback)

            def parse_callback(self, ioc_obj):
                c = ioc_obj.top_level_indicator.getchildren()
                self.child_count[ioc_obj.iocid] = len(c)
    """

    def __init__(self):
        self.iocs = {}  # iocid -> ioc_api.IOC object
        self.ioc_name = {}  # guid -> name mapping
        self.parser_callback = None  #

    def __len__(self):
        """
        :return: Number of iocs in self.iocs
        """
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
        parses an ioc to populate self.iocs and self.ioc_name

        :param ioc_obj:
        :return:
        """
        if ioc_obj is None:
            return
        iocid = ioc_obj.iocid
        try:
            sd = ioc_obj.metadata.xpath('.//short_description/text()')[0]
        except IndexError:
            sd = 'NoName'
        if iocid in self.iocs:
            msg = 'duplicate IOC UUID [{}] [orig_shortName: {}][new_shortName: {}]'.format(iocid,
                                                                                           self.ioc_name[iocid],
                                                                                           sd)
            log.warning(msg)
        self.iocs[iocid] = ioc_obj
        self.ioc_name[iocid] = sd
        if self.parser_callback:
            self.parser_callback(ioc_obj)
        return True

    def register_parser_callback(self, func):
        """
        Register a callback function that is called after self.iocs and self.ioc_name is populated.

        This is intended for use by subclasses that may have additional parsing requirements.

        :param func:  A callable function.  This should accept a single input, which will be an IOC class.
        :return:
        """
        if hasattr(func, '__call__'):
            self.parser_callback = func
            log.debug('Set callback to {}'.format(func))
        else:
            raise TypeError('Provided function is not callable: {}'.format(func))
