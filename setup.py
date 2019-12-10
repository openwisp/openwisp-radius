#!/usr/bin/env python
import os
import sys

from setuptools import find_packages, setup

from openwisp_radius import get_version


def get_install_requires():
    """
    parse requirements.txt, ignore links, exclude comments
    """
    requirements = []
    for line in open('requirements.txt').readlines():
        # skip to next iteration if comment or empty line
        if line.startswith('#') or line == '' or line.startswith('http') or line.startswith('git'):
            continue
        # add line to requirements
        requirements.append(line)
    return requirements


if sys.argv[-1] == 'publish':
    # delete any *.pyc, *.pyo and __pycache__
    os.system('find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf')
    os.system("python setup.py sdist bdist_wheel")
    os.system("twine upload -s dist/*")
    os.system("rm -rf dist build")
    args = {'version': get_version()}
    print("You probably want to also tag the version now:")
    print("  git tag -a %(version)s -m 'version %(version)s'" % args)
    print("  git push --tags")
    sys.exit()


setup(
    name='openwisp-radius',
    version=get_version(),
    license='GNU GPL v3',
    author='Rohith Asrk',
    author_email='rohith.asrk@gmail.com',
    description='OpenWISP 2 Radius',
    long_description=open('README.rst').read(),
    url='http://openwisp.org',
    download_url='https://github.com/openwisp/openwisp-radius/releases',
    platforms=['Platform Independent'],
    keywords=['django', 'freeradius', 'networking', 'openwisp'],
    packages=find_packages(exclude=['tests', 'docs']),
    include_package_data=True,
    zip_safe=False,
    install_requires=get_install_requires(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: System :: Networking',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU GPL v3',
        'Operating System :: OS Independent',
        'Framework :: Django',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
    ]
)
