===============================================================================
OpenIOC 1.1 to 1.0 Upgrade script

openioc_11_to_10.py
===============================================================================

The source code in this package is made available under the terms of the
Apache License , Version 2.0. See the "LICENSE " file for more information.

===============================================================================
Author:
William Gibb
william.gibb at mandiant dot com

===============================================================================
Purpose:

This script is designed to upgrade Indicators Of Compromise (IOCs) in the 
OpenIOC 1.0 format, to the OpenIOC 1.1 format.  This upgrade process is a 
non-lossy process, as all conditions that can be expressed in OpenIOC 1.0 can
also be expressed in OpenIOC 1.1.

===============================================================================
Options:
    -i IOCS, --iocs=IOCS        Directory containing .ioc files to upgrade.  
                                This may point to a single .ioc file.
    
    -o OUTPUT, --output=OUTPUT
                                Directory to write the .ioc file out too.

===============================================================================
Usage Examples:

To upgrade a directory of IOCs:

    python openioc_10_to_11.py -i /path/to/ioc/files -o /path/to/upgrade_directory

To upgrade a single IOC:

    python openioc_10_to_11.py -i /path/to/ioc/file/12341234-1234-1234-1234-123412341234.ioc 
        -o /path/to/upgrade_directory

===============================================================================
Requirements:

The python "lxml" library must be installed.  This can be obtained from one of
following locations.
    https://pypi.python.org/pypi/lxml/3.2.1
    http://lxml.de/

===============================================================================
Bug reports / questions / feedback / feature requests:
william.gibb at fireeye dot com