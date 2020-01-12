import os
from setuptools import setup

with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'README.md')) as f:
    README = f.read()

setup(
    name='lil-pwny',
    version='1.0.1',
    url='https://github.com/PaperMtn/little-pwny',
    license='GPL-3.0',
    classifiers=[
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    author='PaperMtn',
    author_email='ab10adg@gmail.com',
    long_description=README,
    long_description_content_type='text/markdown',
    description='Auditing Active Directory Passwords ',
    keywords='audit active-directory have-i-been-pwned hibp lil-pwny little-pwny password password-audit',
    packages=['src'],
    entry_points={
        'console_scripts': ['lil-pwny=src:main']
    }
)
