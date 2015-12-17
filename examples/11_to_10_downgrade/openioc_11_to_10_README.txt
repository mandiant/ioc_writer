===============================================================================
OpenIOC 1.1 to 1.0 Downgrade script

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

This script is designed to downgrade Indicators Of Compromise (IOCs) in the 
OpenIOC 1.1 format, to the OpenIOC 1.0 format.  This downgrade process is lossy
as there are conditions, parameters and link metadata which may be present in
the 1.1 indicator that cannot be expressed in the 1.0 indicator.  The data that
is lost is detailed below:

Data that will be removed in the downgrade:
For items directly underneath the top-level Indicator node 
(OpenIOC/criteria/Indicator/@operator='OR'for a valid MIR IOC):
1) Any IndicatorItems under the top which use the preserve-case attribute
will be removed.
2) Any IndicatorItems which use the conditions 'begins-with', 'ends-with', 
'greater-than', 'less-than', or 'matches' will be removed.
3) Any Indicator nodes which contains a IndicatorItem node underneath it which
match the conditions described above in 1) & 2) will be removed.
Metadata:
4) Any links which contain link/@href will lose the @href attribute.
Parmeters:
5) Any parmeters which point to a Indicator node will be removed.
6) Any parmeters which point to a IndicatorItem node which do not have 
param/@name='comment' set will be removed.
General:
7) The published date, OpenIOC/@published-date, will be removed.

The output of this script is binned into three folders.  Each folder represents
the level of loss that occured with that IOC:
    Unpruned - This directory represents IOCs which did have any Indicator or 
        IndicatorItem nodes removed from them.
    Pruned - This directory represents IOCs which did have some, but not all,
        Indicator or IndicatorItem nodes removed from them.
    Null - This directory represents IOCs which did have ALL of their Indicator
        or IndicatorItem nodes removed from them.

There is no bucketing done for IOCs which had metatadata or parameters loss.
===============================================================================
Options:
    -i IOCS, --iocs=IOCS        Directory containing .ioc files to downgrade.  
                                This may point to a single .ioc file.
    
    -o OUTPUT, --output=OUTPUT
                                Directory to write the .ioc file out too. There
                                are three folders created in this directory.

===============================================================================
Usage Examples:

To downgrade a directory of IOCs:

    python openioc_11_to_10.py -i /path/to/ioc/files -o downgraded_iocs

To downgrade a single IOC:

    python openioc_11_to_10.py -i /path/to/ioc/file/12341234-1234-1234-1234-123412341234.ioc 
        -o downgraded_ioc_file

===============================================================================
Requirements:

The python "lxml" library must be installed.  This can be obtained from one of
following locations.
    https://pypi.python.org/pypi/lxml/3.2.1
    http://lxml.de/

===============================================================================
Bug reports / questions / feedback / feature requests:
william.gibb at fireeye dot com