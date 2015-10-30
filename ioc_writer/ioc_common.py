# ioc_common.py
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
# Provides common indicatorItem templates
#
# These templates allow the rapid construction of IOCs, without having to know
# any specific iocterm information that would otherwise be neccesary for 
# creating indicatorItem nodes.

from . import ioc_api


def make_dnsentryitem_recordname(dns_name, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for DnsEntryItem/RecordName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'DnsEntryItem'
    search = 'DnsEntryItem/RecordName'
    content_type = 'string'
    content = dns_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_driveritem_deviceitem_devicename(device_name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for DriverItem/DeviceItem/DeviceName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'DriverItem'
    search = 'DriverItem/DeviceItem/DeviceName'
    content_type = 'string'
    content = device_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_driveritem_drivername(driver_name, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for DriverItem/DriverName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'DriverItem'
    search = 'DriverItem/DriverName'
    content_type = 'string'
    content = driver_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_eventlogitem_eid(eid, condition='is', negate=False):
    """
    Create a node for EventLogItem/EID
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'EventLogItem'
    search = 'EventLogItem/EID'
    content_type = 'int'
    content = eid
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_eventlogitem_log(log, condition='is', negate=False, preserve_case=False):
    """
    Create a node for EventLogItem/log
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'EventLogItem'
    search = 'EventLogItem/log'
    content_type = 'string'
    content = log
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_eventlogitem_message(message, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for EventLogItem/message
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'EventLogItem'
    search = 'EventLogItem/message'
    content_type = 'string'
    content = message
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_fileattributes(attributes, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for FileItem/FileAttributes
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/FileAttributes'
    content_type = 'string'
    content = attributes
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_fileextension(extension, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/FileExtension
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/FileExtension'
    content_type = 'string'
    content = extension
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_filename(filename, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/FileName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/FileName'
    content_type = 'string'
    content = filename
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_filepath(filepath, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for FileItem/FilePath
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/FilePath'
    content_type = 'string'
    content = filepath
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_fullpath(fullpath, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for FileItem/FullPath
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/FullPath'
    content_type = 'string'
    content = fullpath
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_md5sum(md5, condition='is', negate=False):
    """
    Create a node for FileItem/Md5sum
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/Md5sum'
    content_type = 'md5'
    content = md5
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_fileitem_peinfo_detectedanomalies_string(anomaly, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/PEInfo/DetectedAnomalies/string
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/DetectedAnomalies/string'
    content_type = 'string'
    content = anomaly
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_detectedentrypointsignature_name(entrypoint_name, condition='is', negate=False,
                                                          preserve_case=False):
    """
    Create a node for FileItem/PEInfo/DetectedEntryPointSignature/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/DetectedEntryPointSignature/Name'
    content_type = 'string'
    content = entrypoint_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_digitalsignature_signatureexists(sig_exists, condition='is', negate=False):
    """
    Create a node for FileItem/PEInfo/DigitalSignature/SignatureExists
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/DigitalSignature/SignatureExists'
    content_type = 'bool'
    content = sig_exists
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_fileitem_peinfo_digitalsignature_signatureverified(sig_verified, condition='is', negate=False):
    """
    Create a node for FileItem/PEInfo/DigitalSignature/SignatureVerified
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/DigitalSignature/SignatureVerified'
    content_type = 'bool'
    content = sig_verified
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_fileitem_peinfo_exports_dllname(dll_name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/PEInfo/Exports/DllName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/Exports/DllName'
    content_type = 'string'
    content = dll_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_exports_exportedfunctions_string(export_function, condition='is', negate=False,
                                                          preserve_case=False):
    """
    Create a node for FileItem/PEInfo/Exports/ExportedFunctions/string
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/Exports/ExportedFunctions/string'
    content_type = 'string'
    content = export_function
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_exports_numberoffunctions(function_count, condition='is', negate=False):
    """
    Create a node for FileItem/PEInfo/Exports/NumberOfFunctions
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/Exports/NumberOfFunctions'
    content_type = 'int'
    content = function_count
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_fileitem_peinfo_importedmodules_module_importedfunctions_string(imported_function, condition='is',
                                                                         negate=False, preserve_case=False):
    """
    Create a node for FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string'
    content_type = 'string'
    content = imported_function
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_importedmodules_module_name(imported_module, condition='is', negate=False,
                                                     preserve_case=False):
    """
    Create a node for FileItem/PEInfo/ImportedModules/Module/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/ImportedModules/Module/Name'
    content_type = 'string'
    content = imported_module
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_petimestamp(compile_time, condition='is', negate=False):
    """
    Create a node for FileItem/PEInfo/PETimeStamp
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/PETimeStamp'
    content_type = 'date'
    content = compile_time
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_fileitem_peinfo_resourceinfolist_resourceinfoitem_name(resource_name, condition='is', negate=False,
                                                                preserve_case=False):
    """
    Create a node for FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/ResourceInfoList/ResourceInfoItem/Name'
    content_type = 'string'
    content = resource_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_sections_section_name(section_name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/PEInfo/Sections/Section/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/Sections/Section/Name'
    content_type = 'string'
    content = section_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_type(petype, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/PEInfo/Type
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/Type'
    content_type = 'string'
    content = petype
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_sizeinbytes(filesize, condition='is', negate=False):
    """
    Create a node for FileItem/SizeInBytes
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/SizeInBytes'
    content_type = 'int'
    content = filesize
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_fileitem_streamlist_stream_name(stream_name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/StreamList/Stream/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/StreamList/Stream/Name'
    content_type = 'string'
    content = stream_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_stringlist_string(file_string, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for FileItem/StringList/string
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/StringList/string'
    content_type = 'string'
    content = file_string
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_username(file_owner, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/Username
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/Username'
    content_type = 'string'
    content = file_owner
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_hookitem_hookedfunction(hooked_function, condition='is', negate=False, preserve_case=False):
    """
    Create a node for HookItem/HookedFunction
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'HookItem'
    search = 'HookItem/HookedFunction'
    content_type = 'string'
    content = hooked_function
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_hookitem_hookingmodule(hooking_module, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for HookItem/HookingModule
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'HookItem'
    search = 'HookItem/HookingModule'
    content_type = 'string'
    content = hooking_module
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_portitem_remoteip(remote_ip, condition='is', negate=False):
    """
    Create a node for PortItem/remoteIP
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'PortItem'
    search = 'PortItem/remoteIP'
    content_type = 'IP'
    content = remote_ip
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_portitem_remoteport(remote_port, condition='is', negate=False):
    """
    Create a node for PortItem/remotePort
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'PortItem'
    search = 'PortItem/remotePort'
    content_type = 'int'
    content = remote_port
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_prefetchitem_accessedfilelist_accessedfile(accessed_file, condition='contains', negate=False,
                                                    preserve_case=False):
    """
    Create a node for PrefetchItem/AccessedFileList/AccessedFile
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'PrefetchItem'
    search = 'PrefetchItem/AccessedFileList/AccessedFile'
    content_type = 'string'
    content = accessed_file
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_prefetchitem_applicationfilename(application_filename, condition='is', negate=False, preserve_case=False):
    """
    Create a node for PrefetchItem/ApplicationFileName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'PrefetchItem'
    search = 'PrefetchItem/ApplicationFileName'
    content_type = 'string'
    content = application_filename
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_prefetchitem_applicationfullpath(application_fullpath, condition='contains', negate=False,
                                          preserve_case=False):
    """
    Create a node for PrefetchItem/ApplicationFullPath
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'PrefetchItem'
    search = 'PrefetchItem/ApplicationFullPath'
    content_type = 'string'
    content = application_fullpath
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_handlelist_handle_name(handle_name, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ProcessItem/HandleList/Handle/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/HandleList/Handle/Name'
    content_type = 'string'
    content = handle_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_portlist_portitem_remoteip(remote_ip, condition='is', negate=False):
    """
    Create a node for ProcessItem/PortList/PortItem/remoteIP
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/PortList/PortItem/remoteIP'
    content_type = 'IP'
    content = remote_ip
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_processitem_sectionlist_memorysection_name(section_name, condition='contains', negate=False,
                                                    preserve_case=False):
    """
    Create a node for ProcessItem/SectionList/MemorySection/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/SectionList/MemorySection/Name'
    content_type = 'string'
    content = section_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_sectionlist_memorysection_peinfo_exports_exportedfunctions_string(export_function, condition='is',
                                                                                       negate=False,
                                                                                       preserve_case=False):
    """
    Create a node for ProcessItem/SectionList/MemorySection/PEInfo/Exports/ExportedFunctions/string
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/SectionList/MemorySection/PEInfo/Exports/ExportedFunctions/string'
    content_type = 'string'
    content = export_function
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_stringlist_string(string, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ProcessItem/StringList/string
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/StringList/string'
    content_type = 'string'
    content = string
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_username(username, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ProcessItem/Username
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/Username'
    content_type = 'string'
    content = username
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_arguments(arguments, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ProcessItem/arguments
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/arguments'
    content_type = 'string'
    content = arguments
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_name(name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for ProcessItem/name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/name'
    content_type = 'string'
    content = name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_processitem_path(path, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ProcessItem/path
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ProcessItem'
    search = 'ProcessItem/path'
    content_type = 'string'
    content = path
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_registryitem_keypath(keypath, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for RegistryItem/KeyPath
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'RegistryItem'
    search = 'RegistryItem/KeyPath'
    content_type = 'string'
    content = keypath
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_registryitem_path(path, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for RegistryItem/Path
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'RegistryItem'
    search = 'RegistryItem/Path'
    content_type = 'string'
    content = path
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_registryitem_text(text, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for RegistryItem/Text
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'RegistryItem'
    search = 'RegistryItem/Text'
    content_type = 'string'
    content = text
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_registryitem_valuename(valuename, condition='is', negate=False, preserve_case=False):
    """
    Create a node for RegistryItem/ValueName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'RegistryItem'
    search = 'RegistryItem/ValueName'
    content_type = 'string'
    content = valuename
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_serviceitem_description(description, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ServiceItem/description
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/description'
    content_type = 'string'
    content = description
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_serviceitem_descriptivename(descriptive_name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for ServiceItem/descriptiveName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/descriptiveName'
    content_type = 'string'
    content = descriptive_name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_serviceitem_name(name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for ServiceItem/name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/name'
    content_type = 'string'
    content = name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_serviceitem_path(path, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ServiceItem/path
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/path'
    content_type = 'string'
    content = path
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_serviceitem_pathmd5sum(path_md5, condition='is', negate=False):
    """
    Create a node for ServiceItem/pathmd5sum
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/pathmd5sum'
    content_type = 'md5'
    content = path_md5
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_serviceitem_servicedll(servicedll, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for ServiceItem/serviceDLL
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/serviceDLL'
    content_type = 'string'
    content = servicedll
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_serviceitem_servicedllsignatureexists(dll_sig_exists, condition='is', negate=False):
    """
    Create a node for ServiceItem/serviceDLLSignatureExists
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/serviceDLLSignatureExists'
    content_type = 'bool'
    content = dll_sig_exists
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_serviceitem_servicedllsignatureverified(dll_sig_verified, condition='is', negate=False):
    """
    Create a node for ServiceItem/serviceDLLSignatureVerified
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/serviceDLLSignatureVerified'
    content_type = 'bool'
    content = dll_sig_verified
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_serviceitem_servicedllmd5sum(servicedll_md5, condition='is', negate=False):
    """
    Create a node for ServiceItem/serviceDLLmd5sum
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'ServiceItem'
    search = 'ServiceItem/serviceDLLmd5sum'
    content_type = 'md5'
    content = servicedll_md5
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate)
    return ii_node


def make_systeminfoitem_hostname(hostname, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for SystemInfoItem/hostname
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'SystemInfoItem'
    search = 'SystemInfoItem/hostname'
    content_type = 'string'
    content = hostname
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_systemrestoreitem_originalfilename(original_filename, condition='contains', negate=False, preserve_case=False):
    """
    Create a node for SystemRestoreItem/OriginalFileName
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'SystemRestoreItem'
    search = 'SystemRestoreItem/OriginalFileName'
    content_type = 'string'
    content = original_filename
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_taskitem_name(name, condition='is', negate=False, preserve_case=False):
    """
    Create a node for TaskItem/Name
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'TaskItem'
    search = 'TaskItem/Name'
    content_type = 'string'
    content = name
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node


def make_fileitem_peinfo_versioninfoitem(key, value, condition='is', negate=False, preserve_case=False):
    """
    Create a node for FileItem/PEInfo/VersionInfoList/VersionInfoItem/ + key name
    
    No validation of the key is performed.
    
    Returns a IndicatorItem represented as an Element node
    """
    document = 'FileItem'
    search = 'FileItem/PEInfo/VersionInfoList/VersionInfoItem/' + key  # XXX: No validation of key done.
    content_type = 'string'
    content = value
    ii_node = ioc_api.make_indicatoritem_node(condition, document, search, content_type, content,
                                              negate=negate, preserve_case=preserve_case)
    return ii_node
