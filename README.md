# proxyenv: set up a Squid proxy and related process environment

This is a python module that starts a [Squid](http://www.squid-cache.org/) proxy running in a docker container, and sets up an environment for using this proxy to handle HTTP(S) requests both from python code and external programs. The purpose is mainly for testing proxy support in code that needs to make HTTP(S) requests. The proxy supports both HTTP and HTTPS, and Basic proxy authorization.

## Using an existing HTTP proxy

If a proxy is already set in the `http_proxy` environment variable, the newly created squid proxy will still work by using the existing proxy as "cache peer". If you don't want this, delete `http_proxy` from the environment before starting the temporary proxy.

## Usage

```
from proxyenv.proxyenv import ProxyFactory
proxyfact=ProxyFactory()

# Example for using urllib
from six.moves.urllib import request
with proxyfact() as proxy:
    opener  = request.build_opener(proxy.get_handler)
    opener.open(url)

# Example for starting external program with proxy-related environment
# variables
from subprocess import check_output
with proxyfact(user="johndoe:secret", port=3077) as proxy:
    check_output(["/usr/bin/wget", url])

```
Please use the `main` program in `proxyenv/proxyenv.py` as additional source of documentation.

## The proxyenv script

The package also contains a console script `proxyenv`.
```
usage: proxyenv [-h] [-p PORT] [-u USER] [-i IMPL] [-s] [-w] [-v]
                [URL [URL ...]]

positional arguments:
  URL                   an URL to retrieve

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  proxyport to use (default: 3128)
  -u USER, --user USER  proxy user in user:password format
  -i IMPL, --impl IMPL  set implementaton (cmdline or api, default: api)
  -s, --shell           open a shell in new environment
  -w, --wait            wait for input
  -v, --verbose         verbose output
```
