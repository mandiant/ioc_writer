from distutils.core import setup

#This is a list of files to install, and where
#(relative to the 'root' dir, where setup.py is)
#You could be more specific.
files = ["ioc_writer/*"]

setup(name = "ioc_writer",
    version = "0.1.0",
    description = "",
    author = "William Gibb",
    author_email = "william.gibb@mandiant.com",
    url = "http://www.github.com/mandiant/iocwriter_11/",
    packages = ['ioc_writer'],
    package_data = {'package' : files },
    #scripts = ["runner"],
    long_description = """API providing a limited CRUD for manipulating OpenIOC formatted Indicators of Compromise.""",
    #This next part it for the Cheese Shop, look a little down the page.
    classifiers=[
      'Development Status :: 4 - Beta',
      'Environment :: Console',
      'Intended Audience :: Developers',
      'Intended Audience :: Information Technology',
      'Intended Audience :: System Administrators',
      'License :: OSI Approved :: Apache Software License',
      'Natural Language :: English',
      'Operating System :: OS Independent',
      'Programming Language :: Python',
      'Topic :: Security',
      'Topic :: Text Processing :: Markup :: XML'
      ]  
) 
