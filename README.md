# ioc_writer


The source code in this package is made available under the terms of the
Apache License , Version 2.0. See the "LICENSE " file for more information.

## Status
* [![Build Status](https://travis-ci.org/mandiant/ioc_writer.svg?branch=master)](https://travis-ci.org/mandiant/ioc_writer)
* [![Coverage Status](https://coveralls.io/repos/github/mandiant/ioc_writer/badge.svg?branch=master)](https://coveralls.io/github/mandiant/ioc_writer?branch=master)


## Author
William Gibb
william.gibb at fireeye dot com

## Purpose

Provide a python library that allows for basic creation and editing of OpenIOC
objects.  It supports a basic CRUD (Create, Read, Update, Delete) for various
items:


| item |Create | Read | Update | Delete |
| --- | --- | --- | --- | --- |
| IOC name | Yes | No | Yes | Yes |
| IOC description | Yes | No | Yes | Yes |
| created date | Yes | No | Yes | N/A |
| last modified date | Yes | No | Yes | N/A |
| published date | Yes | No | Yes | N/A |
| link metadata | Yes | No | Yes | Yes |
| IndicatorItem nodes | Yes | No | NotYet | Yes |
| Indicator nodes | Yes | No | NotYet | Yes |
| Parameters | Yes | No | Yes | Yes |


Items do not have built in Read operations, since all items can be accesed
with built in ElementTree syntax or the use of XPATH to select portions
of the IOC.

No decision has been made about whether or not to support changing of
existing Indicator/IndicatorItem nodes.

See the Docs located at https://pythonhosted.org/ioc_writer/ and the examples
directory for examples of working with the library.  The user code should
avoid having to call functionality in ioc_writer.ioc_et.


## Requirements

The python "lxml" library must be installed.  This can be obtained from https://pypi.python.org/pypi/lxml


## Installation
See the file named "INSTALL" for instructions on installing this library
locally.

## Examples

Example code lives in the examples folder of the repository.

1. examples/11_to_10_downgrade
    Script to downgrade OpenIOC 1.1 to OpenIOC 1.1.
1. examples/openioc_to_yara
    Scripts that support encapsulating YARA signatures in OpenIOC 1.1 format.
1. examples/simple_ioc_writer
    Script that consumes a csv of data to build an IOC.  this csv contains the content, context, et cetera. An example CSV is provided.


# Bug reports / questions / feedback / feature requests

william.gibb at fireeye dot com