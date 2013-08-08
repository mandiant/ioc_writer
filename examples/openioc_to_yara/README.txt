openioc_to_yara

===============================================================================

The source code in this package is made available under the terms of the
Apache License , Version 2.0. See the "LICENSE " file for more information.

===============================================================================
Author:
William Gibb
william.gibb at mandiant dot com

===============================================================================
Purpose:

This is a python script that is designed to extract YARA signatures from 
OpenIOC objects.  This allows an end user to embed a YARA signature in the
OpenIOC format, and later extract that YARA signature and use it for matching.
This does not affect any existing portions of an OpenIOC, allowing the embedded
YARA signature to sit next to existing OpenIOC indicators.

This is currently implemented through the use of parameters, a new OpenIOC 1.1
feature, which allows specifying application-specific processing instructions.
We can attach parameters to Indicator or IndicatorItem nodes, which can further
expand the meaning of that node.

Numerous example .ioc files, with embedded YARA signatures, are made available
in the directory "example_iocs".  These .ioc files can be visualized with the 
experimental OpenIOC 1.1 editor, which can be obtained by request to the author.

These example IOCs are modelled from examples in the YARA documentation, and
can match against a set of test documents in the folder 'example_files' which
can be used to test the YARA signatures generated from the IOCs.  The script
'check_yara_rules.py' can quickly be used to check a file containing YARA 
signatures against a file or directory of files.
===============================================================================
List of currently supported YARA features, and associated YARA Documentation 
numbers:
- Hex Strings, Text Strings, and Regular Expression strings (3.1, 3.2, 3.3)
- Modifiers for Text Strings and Regular Expressions (3.2.1 -> 3.2.3)
- Referencing Rules by Name (4.9)
- Explicit filesize declarations (4.3))
    example condition: "filesize > 200KB"
- Counting the number of strings in a file (4.1)
- 'at' and 'in' offset specifiers. (4.2)
- Executable entrypoint variable (4.4)
    This is a virtual address, applied as a modifier to offsets typically.
    This is supported as a result of supporting offsets.
- Sets of strings (4.6)
    YARA conditions, such as '2 of ($a, $b, $c)', '1 of them', '1 of ($foo*)',
	are all effectively checking for the existence of a member in a set.
- Metadata (5.4)

List of currently unsupported YARA features:
- Negated Operators ("$a and not $b") are not currently supported.
- Accessing data at a given position (4.5)
- 'For' expressions (4.7)
- Iterating string occurrences (4.9)
- Global Rules (5.1)
- Private Rules (5.2)
- Rule Tags (5.3)
- Includes (6)

===============================================================================
Quick start: Using YARA in IOCe 3.x, the experimental OpenIOC 1.1 IOC editor

1) You will need to copy the yara.iocterms file to the IOCe installation
directory, under the 'Configuration/IOCTerms' folder.
2) Open IOCe
3) You can now start adding IndicatorItem terms for YARA items using the IOCe
interface.
4) To add parameters to an Indicator/IndicatorItem node, you need to use the
Properties Pane.  The keyboard command 'Ctrl + p' will enable the properties
pane.  Once the properties pane is enabled, you can hit the '+' symbol to add
a Parameter to the IndicatorItem node.

See the example IOCs, especially the DUQU IOC, for examples of how this works.

===============================================================================
Technical details for embedding YARA signatures into OpenIOC format:
	Example IOCs are included for each of these, showing their implementation
	in OpenIOC format.

The following items are currently supported, as IndicatorItems:
- YARA Hex Strings
- YARA Text Strings
- YARA Regular Expressions
There is no need to place string delimiters (", /, {, }) into the 
Content/text() node of the IndicatorItem node, as the conversion tool will
automatically insert these based on the term type.

In addition, the filesize operator and the ability to specify a rule by name,
are also implemented as IndicatorItem nodes.  More information about that is
included below.

For Text Strings and Regular Expressions, the modifiers are implemented in the
following way:
- "nocase"
    In OpenIOC 1.1, IndicatorItem nodes can contain case sensitive strings.
    The boolean IndicatorItem attribute, IndicatorItem/@preserve-case, is used
    to apply the "nocase" modifier.
	Example IOC ids:
		cf0d2d75-162a-4793-a2ba-7fe2c47407d1
		095e05ed-68f1-41a6-a39f-bba250d7ddcf
		
- "ascii"
    This requires applying a parameter to the IndicatorItem node with
    param/@name='yara/ascii'.  The parameter type or value does not matter.
	Example IOC ids:
		04f522c1-efc9-492a-a07f-25501f395255
		
- "wide"
    This requires applying a parameter to the IndicatorItem node with
    param/@name='yara/wide'.  The parameter type or value does not matter.
	Example IOC ids:
		04f522c1-efc9-492a-a07f-25501f395255
		72669174-dd77-4a4e-82ed-99a96784f36e
		
- "fullword"
    This requires applying a parameter to the IndicatorItem node with
    param/@name='yara/fullword'.  The parameter type or value does not matter.

In addition, a variety of conditions are supported.

Boolean expressions, such as '$a or ($b and $c)' are derived from the logic
tree that is represented an the OpenIOC XML.  The children of Indicator nodes,
IndicatorItem or more Indicator nodes, are used to generate the necessary
boolean operators and string identifiers.
	Example IOC ids:
		1ae7c501-12bf-41a4-b8a2-7d5209a01bb7
		c346142a-c3e9-409c-b569-73693a33bdd2

Counting conditions, such as '#a > 10', are supported through the use of a
parameter attached to the IndicatorItem that needs to be counted.  The 
parameter needs to have the name param/@name='yara/count' and the count number
set to the parameter value.  The operator, such as greater than or less than, 
is set on the IndicatorItem/@condition attribute.  The relational operators 
'!=', '<=' and '>=' are not currently supported.
	Example IOC ids:
		6915a80e-4cde-4137-8bae-9ddd3c5a3d54
		72669174-dd77-4a4e-82ed-99a96784f36e

Offset conditionas, such as '$a at 100' or '$b in (0..100)' are supported 
through the use of a parameter attached to the IndciatorItem that is present at
the desired offset.  The parameter with the name 'yara/offset/at' needs to have
the integer offset specified in the value.  The parameter with the name 
'yara/offset/in' needs to have the range, "(0..100)", specified in the value.
	Example IOC ids:
		131ef9d1-9330-4fe6-b52f-45d618cb8f60
		31bdd683-368a-4920-ab6e-1a20fea10bf5

Set conditions, as mentioned earlier, are supported through the use of a
parameter that is attached to the Indicator node that is the parent node of the
strings that are being tested for.  The parameter with the name 'yara/set' is
used to determine if a indicator node is used to describe a set expression.
The value of the parameter is used to determine how many items are required in
the set for a match to occur.  There are several YARA set expressions, such as
'1 of ($foo*, $bar1, $bar2)' which actually map to effectively OR'ing all of
strings of interest together.
	Example IOC ids:
		5e4c5d7b-0fc0-47a3-ae4d-bfaf9310bf38
		37a3a459-220f-4b71-bb9b-cd4f089305d0
		72669174-dd77-4a4e-82ed-99a96784f36e

The filesize keyword is supported as an IndicatorItem term, for standalone
comparisons, such as "$a and filesize < 200KB".  The greater-than/less-than 
conditions can be used to specify the filesize operators.
	Example IOC ids:
		c6049b90-d5b0-4472-b414-ba400f04dca3

The ability to specify a rule by name to match on, such as '$a and Rule1', is
supported as an IndicatorItem term.
	Example IOC ids:
		cf584976-c91e-49f3-b50e-be1e5f8f9555
		5abb4ee9-f9fe-4ee6-a90f-2aece8907338

Rules which require operators that are not currently supported can be directly
inserted into an OpenIOC, with the IndicatorItem term 'Yara/Yara'.  Rules 
stored in this manner are extracted directly.  In order to view/edit these in 
IOCe, double click on the term for a pop-up editor.
	Example IOC ids:
		7a6377d1-ae5e-4cdd-8461-9497f1bc4211
		e9e37871-e6e2-4673-a9c1-880a5baac3b1
		
===============================================================================
Bug reports / questions / feedback / feature requests:
william.gibb at mandiant dot com
