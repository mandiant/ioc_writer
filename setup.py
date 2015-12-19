import os
from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(name="ioc_writer",
      version="0.3.2",
      author="William Gibb",
      author_email="william.gibb@mandiant.com",
      url="http://www.github.com/mandiant/ioc_writer/",
      packages=find_packages(exclude=['docs', 'tests']),
      description="""API providing a limited CRUD for manipulating OpenIOC formatted Indicators of Compromise.""",
      long_description=read('README'),
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
      ]
      )
