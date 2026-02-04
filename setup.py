#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name='nfspider',
    version='1.0.0',
    description='Spider NFS shares for sensitive files during penetration tests',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='Security Researcher',
    license='GPL-3.0',
    python_requires='>=3.8',
    py_modules=['nfspider'],
    entry_points={
        'console_scripts': [
            'nfspider=nfspider:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
    ],
)
