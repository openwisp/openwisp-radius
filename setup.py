#!/usr/bin/env python
import os
import sys

from setuptools import find_packages, setup

from openwisp_radius import get_version

if sys.argv[-1] == 'publish':
    # delete any *.pyc, *.pyo and __pycache__
    os.system('find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf')
    os.system('python setup.py sdist bdist_wheel')
    os.system('twine upload -s dist/*')
    os.system('rm -rf dist build')
    args = {'version': get_version()}
    print('You probably want to also tag the version now:')
    print("  git tag -a %(version)s -m 'version %(version)s'" % args)
    print('  git push --tags')
    sys.exit()


setup(
    name='openwisp-radius',
    version=get_version(),
    license='GPL3',
    author='OpenWISP',
    author_email='support@openwisp.io',
    description='OpenWISP Radius',
    long_description=open('README.rst').read(),
    url='https://openwisp.org',
    download_url='https://github.com/openwisp/openwisp-radius/releases',
    platforms=['Platform Independent'],
    keywords=['django', 'freeradius', 'networking', 'openwisp'],
    packages=find_packages(exclude=['tests*', 'docs*']),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        (
            'openwisp-users '
            '@ https://github.com/openwisp/openwisp-users/tarball/master'
        ),
        (
            'openwisp-utils[rest,celery] @ '
            'https://github.com/openwisp/openwisp-utils/tarball/master'
        ),
        'passlib~=1.7.1',
        'djangorestframework-link-header-pagination~=0.1.1',
        'weasyprint~=59.0',
        'pydyf~=0.10.0',  # remove this once we upgrade wasyprint
        'dj-rest-auth~=4.0.1',
        'django-sendsms~=0.5.0',
        'jsonfield~=3.1.0',
        'django-private-storage~=3.1.0',
        'django-ipware~=5.0.0',
        'pyrad~=2.4',
    ],
    extras_require={
        'saml': ['djangosaml2~=1.9.2'],
        'openvpn_status': ['openvpn-status~=0.2.1'],
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable ',
        'Environment :: Web Environment',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: System :: Networking',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Framework :: Django',
        'Programming Language :: Python :: 3',
    ],
)
