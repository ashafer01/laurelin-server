from setuptools import setup, find_packages

desc = 'An LDAP server frontend with pluggable backends'

setup(
    name='laurelin-server',
    version='0.1.0',
    description=desc,
    long_description=desc,
    author='Alex Shafer',
    author_email='ashafer@pm.me',
    url='https://github.com/ashafer01/laurelin',
    license='LGPLv3+',
    keywords='ldap',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Programming Language :: Python :: Implementation :: CPython',
        'Operating System :: OS Independent',
        'Topic :: Database',
        'Topic :: Database :: Database Engines/Servers',
        'Topic :: System',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
    ],
    namespace_packages=['laurelin'],
    packages=find_packages(exclude=['tests']),
    install_requires=['laurelin-ldap'],
    include_package_data=True,
)
