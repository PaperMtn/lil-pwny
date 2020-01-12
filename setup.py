from setuptools import setup

setup(
    name='lil-pwny',
    version='1.0.0',
    packages=['src'],
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
    author_email='',
    long_description='A multiprocessing approach to auditing Active Directory passwords against HIBP using Python.',
    description='Auditing Active Directory Passwords ',
    # scripts=['src/password_audit.py']
    entry_points={
        'console_scripts': ['lil-pwny=src:main']
    }
)
