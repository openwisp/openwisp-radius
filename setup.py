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
        'django>=3.0,<=4.1.0',
        'openwisp-users~=1.0.0',
        'openwisp-utils[rest,celery]~=1.0.0',
        'passlib~=1.7.1',
        'djangorestframework-link-header-pagination~=0.1.1',
        'weasyprint>=43,<53',
        'dj-rest-auth~=2.1.6',
        'django-sendsms~=0.5.0',
        'jsonfield~=3.1.0',
        'django-private-storage~=3.0',
        'django-ipware~=3.0.0',
    ],
    extras_require={
        'saml': ['djangosaml2~=1.5.0'],
        'openvpn_status': ['openvpn-status~=0.2.1'],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
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
