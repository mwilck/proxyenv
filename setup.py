from setuptools import setup
import os
import warnings
from proxyenv import __version__ as version

def get_description():
    if (not os.path.exists("README.txt") or
        (os.path.exists("README.md") and os.stat("README.txt").st_mtime < os.stat("README.md").st_mtime)):
        try:
            import pypandoc
            pypandoc.convert("README.md", "rst", outputfile="README.txt")
        except (ImportError, OSError, IOError) as exc:
            warnings.warn("Markdown to RST conversion failed (%s), using plain markdown for description" % exc)
            return open("README.md", "rt").read()
    return open("README.txt", "rt").read()

setup(
    name='proxyenv',
    version=version,
    author='Martin Wilck',
    author_email='mwilck@arcor.de',
    packages=['proxyenv'],
    scripts=[],
    url='http://pypi.python.org/pypi/proxyenv/',
    license='LICENSE.txt',
    description='Create HTTP proxy environment using docker',
    long_description = get_description(),
    install_requires=[
        "docker-py >= 1.8",
        "htpasswd >= 2.3",
    ],
    entry_points={
        'console_scripts': [
            'proxyenv = proxyenv.proxyenv:main',
        ]
    },
    keywords = 'squid, testing, http, proxy, docker',

    # See https://pypi.python.org/pypi?:action=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Environment :: Console',
        'Natural Language :: English',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Testing',
        'Topic :: Internet :: Proxy Servers'
    ],
)
