import os
from setuptools import setup, find_packages


try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    try:
        long_description = open('README.md').read()
    except:
        long_description = 'README.md not found.'

version = '0.3.3'

setup(name="ioc_writer",
      version=version,
      author="William Gibb",
      author_email="william.gibb@mandiant.com",
      url="http://www.github.com/mandiant/ioc_writer/",
      packages=find_packages(exclude=['docs', 'tests']),
      description="""API providing a limited CRUD for manipulating OpenIOC formatted Indicators of Compromise.""",
      long_description=long_description,
      install_requires=['lxml'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Console',
          'Intended Audience :: Developers',
          'Intended Audience :: Information Technology',
          'Intended Audience :: System Administrators',
          'License :: OSI Approved :: Apache Software License',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: 3.5',
          'Topic :: Security',
          'Topic :: Text Processing :: Markup :: XML'
      ],
      entry_points={
          "console_scripts": ["openioc_10_to_11 = ioc_writer.scripts.openioc_10_to_11:_main",
                              "openioc_11_to_10 = ioc_writer.scripts.openioc_11_to_10:_main",
                              "iocdump = ioc_writer.scripts.iocdump:_main",
                              ]
      }
      )
