#!/usr/bin/env python

from setuptools import find_packages, setup

with open('README.md') as readme_file:
    readme = readme_file.read()

requirements = [
    'fastlogging',
]

test_requirements = []

setup(
    name='debug',
    version='0.1.0',
    description="Windows Debugger",
    long_description=readme,
    author="Glen Harmon",
    author_email='glencharmon@gmail.com',
    packages=find_packages(exclude=['contrib', u'docs', u'tests']),
    # entry_points={
    #     'console_scripts': [
    #         'debug=package:commands'
    #     ]
    # },
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords='aci',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    # executables=executables,
    # options=options,
)
