openioc_to_yara

===============================================================================

The source code in this package is made available under the terms of the
Apache License , Version 2.0. See the "LICENSE " file for more information.

===============================================================================
Author:
William Gibb
william.gibb@mandiant.com

===============================================================================
Purpose:

This is a python script that is designed to extract YARA signatures from 
OpenIOC objects.  This allows an end user to embed a YARA signature in the
OpenIOC format, and later extract that YARA signature and use it for matching.

This is currently implemented through the use of paramters, a new OpenIOC 1.1
feature, which allows specifying application-specific processing instructions.
We can attach parameters to Indicator or IndicatorItem nodes, which can futher
expand the meaning of that node.

Numerous example .ioc files, with embedded YARA signatures, are made available
in the directory "example_iocs".  These .ioc files can be visualized with the 
experimental OpenIOC 1.1 editor, which can be otained by request to the author.

These IOCs are modeled from examples in the YARA documentation, and contain a 
set of test documents in the folder 'example_files' which can be used to test
the YARA signatures generated from the IOCs.


===============================================================================
List of currently supported YARA features, and associated YARA Documentation 
numbers:
- Hex Strings, Text Strings, and Regular Expression strings (3.1, 3.2, 3.3)
- Modifiers for Text Strings and Regular Expressions (3.2.1 -> 3.2.3)
- Referenceing Rules by Name (4.9)
- Explicit filesize declarations (4.3))
    example condition: "filesize > 200KB"
- Counting the number of strings in a file (4.1)
- 'at' and 'in' offset specifiers. (4.2)
- Executable entrypoint variable (4.4)
    This is a virtual address, applied as a modifier to offsets typically.
    This is supported as a result of supporting offsets.
- Sets of strings (4.6)
    #XXX EXPAND ON THIS
- Metadata (5.4)

List of currently unsupported YARA features:
- Negated Operators ("$a and not $b") are not currently supported.
- Accessing data at a given position (4.5)
- 'For' expressions (4.7)
- Iterating string occurences (4.9)
- Global Rules (5.1)
- Private Rules (5.2)
- Rule Tags (5.3)
- Includes (6)

===============================================================================

Technical details for embeding YARA signatures into OpenIOC format:

The following items are currently supported, as IndicatorItems:
- Yara Hex Strings
- Yara Text Strings
- Yara Regular Expressions
There is no need to place string delimiters (", /, {, }) into the 
Content/text() node of the IndicatorItem node, as the conversion tool will
automatically insert those as appropriate.

In addition, the filesize operator and the ability to specify a rule by name,
are also implemented as IndicatorItem nodes.

For Text Strings and Regular Expressions, the modifiers are implemented in the
following way:
- "nocase"
    In OpenIOC 1.1, IndicatorItem nodes can contain case sensitive strings.
    The boolean IndicatorItem attribute, IndicatorItem/@preserve-case, is used
    to apply the "nocase" modifier.
- "ascii"
    This requires applying a parameter to the IndicatorItem node with
    param/@name='ascii'.  The parameter type or value does not matter.
- "wide"
    This requires applying a parameter to the IndicatorItem node with
    param/@name='wide'.  The parameter type or value does not matter.
- "fullword"
    This requires applying a parameter to the IndicatorItem node with
    param/@name='wide'.  The parameter type or value does not matter.

In addition, a variety of conditions are supported.
    
===============================================================================





===============================================================================
Bug reports / questions / feedback / feature requests:
william.gibb@mandiant.com




