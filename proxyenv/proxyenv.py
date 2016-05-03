import sys
import os
import logging
from six import iteritems, itervalues
from six.moves.urllib.request import ProxyHandler
from six.moves.urllib.parse import urlparse
from time import sleep
from shutil import rmtree
from htpasswd import Basic
from tempfile import mkdtemp
from subprocess import check_output, PIPE, CalledProcessError, call
from docker import Client
from docker.errors import NotFound
from socket import socket, AF_INET, SOCK_STREAM, error as SocketError
from datetime import datetime, timedelta
from traceback import format_stack
from errno import ECONNREFUSED
__all__ = [ "DockerClient", "ProxyContainer", "ProxyFactory", "DockerClientFactory" ]

logger = logging.getLogger(__name__)

def lookup_in_PATH(cmd):
    """lookup cmd in PATH as the shell does"""
    for p in os.environ["PATH"].split(":"):
        exe = os.path.join(p, cmd)
        if os.path.exists(exe) and os.access(exe, os.X_OK):
            return exe
    raise RuntimeError("command %s not found in PATH" % cmd)

class DockerClient(object):
    """Abstract base class for simple docker client"""

    def test_if_running(self, id):
        """Return True if container <id> is in running state"""
        return False

    def get_ip(self, id):
        """Return IPv4 Address ot container <id>"""
        return ""

    def stop(self, id):
        """Stop container <id>"""
        pass

    def kill(self, id):
        """Kill container <id>"""
        pass

    def rm(self, id):
        """Remove container <id>"""
        pass

    def run(self, image, volumes, args):
        """Create and start container <id>"""
        pass

class DockerClientCmdline(DockerClient):
    """DockerClient implementation using docker command line"""
    @classmethod
    def __cls_init__(cls):
        if hasattr(cls, "DOCKER"):
            return
        docker = lookup_in_PATH("docker")
        try:
            check_output([docker, "ps"])
        except CalledProcessError as exc:
            logger.error(
                """\Failed to run %s (error code %d). Do you have permissions to run %s?
--- command output: ---
%s
--- end command output ---
""" % (exc.cmd, exc.returncode, docker, exc.output))
        else:
            cls.DOCKER = docker

    def __init__(self):
        self.__cls_init__()

    @classmethod
    def _docker_call(cls):
        return [cls.DOCKER]

    def cmd(self, args):
        try:
            ret = check_output(self._docker_call() + args)
        except CalledProcessError as exc:
            logger.error("%s returned %d, output:\n%s" % (exc.cmd, exc.returncode, exc.output))
            raise
        else:
            return ret.rstrip()

    def test_if_running(self, id):
        try:
            nid = self.cmd(["ps", "-q", "--no-trunc=true", "-f", "id=%s" % id])
        except CalledProcessError:
            return False
        return nid == id

    def get_ip(self, id):
        return self.cmd([ "inspect", "-f", "{{.NetworkSettings.IPAddress}}", id])

    def stop(self, id):
        return self.cmd(["stop", id])

    def kill(self, id):
        return self.cmd(["kill", id])

    def rm(self, id):
        return self.cmd(["rm", id])

    def run(self, image, volumes, args):
        tmp = [ ["-v", "%s:%s" % (x, y) ] for x, y in iteritems(volumes) ]
        vol = reduce(lambda x, y: x + y, tmp)
        return self.cmd(["run"] + args + vol + [ image ])

class DockerClientApi(DockerClient):
    """DockerClient implementation using python docker API"""

    def __init__(self):
        self._api = Client(base_url='unix://var/run/docker.sock', version="auto")
        self._containers = {}

    def get_container(self, id):
        return self._containers[id]

    def test_if_running(self, id):
        try:
            config = self._get_config(id)
        except NotFound:
            return False
        return config["State"]

    def _get_config(self, id):
        return self._api.inspect_container(id)

    def get_ip(self, id):
        config = self._get_config(id)
        return config["NetworkSettings"]["IPAddress"]

    def stop(self, id):
        self._api.stop(id)

    def kill(self, id):
        self._api.kill(id)

    def rm(self, id):
        self._api.remove_container(id)
        del self._containers[id]

    def run(self, image, volumes, args):
        hc = self._api.create_host_config(
            binds = dict([(x, { "bind": y, "mode": "ro" }) for x, y in iteritems(volumes)]))
        kwargs = {
            "image": image,
            "volumes": list(volumes.values()),
            "host_config": hc
        }
        for x in args:
            if x == "-d":
                kwargs["detach"] = True
            else:
                raise ValueError("unsupported argument %s" % x)
        cont = self._api.create_container(**kwargs)
        id = cont.get("Id")
        self._containers[id] = cont
        self._api.start(container=id)
        return id

class DockerClientFactory(object):
    """Factory class for DockerClient"""
    _default = "api"

    @classmethod
    def get_default(cls):
        return cls._default

    @classmethod
    def set_default(cls, method):
        """Set default implementation method ("api" or "cmdline")"""
        if method in ("api", "cmdline"):
            cls._default = method
        else:
            raise RuntimeError("method %s is unsupported" % method)

    def __call__(self, method=None):
        """Return a DockerClient object"""
        if method is None:
            method = self._default
        if method == "api":
            return DockerClientApi()
        elif method == "cmdline":
            return DockerClientCmdline()
        else:
            raise RuntimeError("method %s is unsupported" % method)

class ProxyContainer(object):
    """\
Class representing a squid proxy running in a docker container.
This base class allows access from the docker internal network.
This class can be used as a context generator for the with statement.

The object returned by with in the "as" clause is a "getter" object
that supports the methods "get_proxy()" or "get_handler()", and returns
the proxy to use or the urllib2 ProxyHandler object, respectively.

If an existing proxy is already configured via the http_proxy environment
variable, this proxy will be used by the Squid proxy as "cache peer"."""

    SQUID_CONF = "squid.conf"
    SQUID_CONF_DIR = "/etc/squid3"
    DOCKER_IMG = "docker.io/sameersbn/squid"
    # Max seconds to wait for squid to come up
    TIMEOUT = 10

    env_vars = ("http_proxy", "https_proxy")
    files = [ SQUID_CONF ]

    STATE_INIT = 0
    STATE_OFF = 1
    STATE_STOPPED = 2
    STATE_RUNNING = 3
    STATE_UP = 4
    STATE_DESTROYED = 5

    states = {
        STATE_INIT: "initializing",
        STATE_OFF: "off",
        STATE_STOPPED: "stopped",
        STATE_RUNNING: "running",
        STATE_UP: "up",
        STATE_DESTROYED: "destroyed"
    }

    all_states = set(states.keys())

    ### SQUID configuration - override in subclasses
    conf_auth = ""
    conf_acl = "acl localnet src 172.16.0.0/12"
    conf_allow = "http_access allow localnet"

    class WrongState(RuntimeError):
        def __init__(self, proxy):
            RuntimeError.__init__(self, "Unexpected state: %s" % proxy)

    def assert_id(self):
        assert(self._id is not None)

    def get_id(self):
        """Return container ID"""
        self.assert_id()
        return self._id

    def assert_state(self, *allowed):
        """Check internal status"""
        if self._state in allowed:
            return
        raise self.WrongState(self)

    def is_running(self):
        """Check that container is running"""
        self.assert_state(self.STATE_RUNNING, self.STATE_UP)

    def check_state(self, *allowed):
        try:
            self.assert_state(*allowed)
        except self.WrongState:
            si = sys.exc_info()
            logger.warning("%s:\n%s" % (si[1], "".join(format_stack(limit=2))))

    def host_path(self, fn):
        return os.path.join(self._tmpdir, fn)

    @classmethod
    def docker_path(cls, fn):
        return os.path.join(cls.SQUID_CONF_DIR, fn)

    def __init__(self, port=None):
        """port: TCP port to use, default is 3128"""
        self._client = DockerClientFactory()()
        if port is None:
            port = 3128
        self._port = port
        self._id = None
        self._saved_env = {}
        self._tmpdir = mkdtemp()
        self.create_squid_conf()
        self._state = self.STATE_INIT

    @staticmethod
    def detect_parent_proxy():
        """Return squid configuration to use a parent proxy if a proxy is already configured
in the environment."""
        if "http_proxy" not in os.environ:
            return ""

        parent = urlparse(os.environ["http_proxy"])
        if parent.scheme != "http":
            logger.warning("parent proxy scheme %s in unsupported" % parent.scheme)
            return ""

        logger.debug("Parent proxy detected: %s" % parent.geturl())
        login = "login=%s:%s" % (parent.username, parent.password) if parent.username else ""

        # See http://www.christianschenk.org/blog/using-a-parent-proxy-with-squid/
        # http://www.squid-cache.org/Doc/config/cache_peer/
        parent = """\
cache_peer {host} parent {port} 0 no-query no-digest {login}
never_direct allow all
""".format (host = parent.hostname, port=parent.port, login=login)
        return parent

    def create_squid_conf(self):
        parent = self.detect_parent_proxy()
        conf = """\
{auth}
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT
{acl}
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access deny to_localhost
{allow}
http_access allow localhost
http_access deny all
http_port {port}
{parent}
""".format (auth=self.conf_auth, acl=self.conf_acl, allow=self.conf_allow, port=self._port,
            parent=parent)
        logger.debug("Squid configuration:\n%s" % conf)
        with open(self.host_path(self.SQUID_CONF), "wt") as output:
            output.write(conf)

    def short_id(self):
        return self.get_id()[:12]

    def __str__(self):
        if self._id is not None:
            return "%s (%s with id %s)" % (self.__class__.__name__,
                                           self.states[self._state], self.short_id())
        else:
            return "%s (%s)" % (self.__class__.__name__, self.states[self._state])

    def _volumes(self):
        return dict ( (self.host_path(x), self.docker_path(x)) for x in self.files )

    def start(self, *args):
        """Create and run the container"""
        self.assert_state(self.STATE_INIT)
        self._id = self._client.run(self.DOCKER_IMG, self._volumes(), ["-d"] )
        self._state = self.STATE_RUNNING
        logger.debug("created: %s" % self)

    def wait(self):
        """Wait for the squid proxy to be operational (call after start)"""
        self.assert_state(self.STATE_RUNNING, self.STATE_UP)
        ip = self.get_ip()
        ok = False
        begin = datetime.now()
        waitfor = timedelta(seconds=self.TIMEOUT)
        while not ok and datetime.now() - begin  < waitfor:
            try:
                sock = socket(AF_INET, SOCK_STREAM)
                try:
                    sock.connect((ip, self._port))
                except SocketError as exc:
                    if exc.errno == ECONNREFUSED:
                        sleep(0.1)
                    else:
                        raise
                else:
                    ok = True
            finally:
                sock.close()
        if ok:
            self._state = self.STATE_UP
            logger.debug("proxy was up after %s" % (datetime.now() - begin))
        else:
            logger.error("proxy was not up after %d seconds", self.TIMEOUT)
            self.stop()
            raise RuntimeError("Proxy timeout")
        return ok

    def get_ip(self):
        """Returns proxy IPv4 address"""
        self.is_running()
        ip  = self._client.get_ip(self.get_id())
        if ip == "":
            raise RuntimeError("Unable to detect proxy IP address")
        return ip

    def test_if_running(self):
        """Check status of docker container using client call"""
        if self._state in (self.STATE_RUNNING, self.STATE_UP):
            if not self._client.test_if_running(self.get_id()):
                self._state = self.STATE_STOPPED

    def _close(self):
        rmtree(self._tmpdir)
        self._tmpdir = None
        self._state = self.STATE_DESTROYED

    def _rm(self):
        """Remove container"""
        self._client.rm(self.get_id())
        self._id = None
        self._state = self.STATE_DESTROYED
        self._close()

    def stop(self):
        """Stop container. Object can't be used any more after this."""

        self.check_state(self.STATE_UP, self.STATE_RUNNING)
        try:
            self._client.kill(self.get_id())
        except CalledProcessError:
            pass
        self._state = self.STATE_STOPPED
        self._rm()

    def _get_proxy(self):
        return "http://%s:%d" % (self.get_ip(), self._port)

    def get_proxy(self):
        """Return proxy address to use"""
        self.assert_state(self.STATE_UP)
        return self._get_proxy()

    def get_proxies(self):
        """Return dictionary of proxy addresses"""
        p = self.get_proxy()
        return { "http": p, "https": p }

    def get_ProxyHandler(self):
        """Return suitable urllib2 ProxyHandler object"""
        return ProxyHandler(self.get_proxies())

    def enter_environment(self):
        """\
Set proxy environment variables.
CAUTION: this will not affect the running python instance, only exec'd children.
Use get_ProxyHandler() and urllib2.build_opener instead to affect python calls."""
        self.assert_state(self.STATE_UP)
        if self.env_vars[0] in self._saved_env:
            return
        proxy = self.get_proxy()
        for p in self.env_vars:
            try:
                self._saved_env[p] = os.environ[p]
            except KeyError:
                self._saved_env[p] = None
            os.environ[p] = proxy

    def leave_environment(self):
        """Restore proxy environment variables"""
        if self.env_vars[0] not in self._saved_env:
            return
        for p in self.env_vars:
            var = self._saved_env[p]
            if var is None:
                del os.environ[p]
            else:
                os.environ[p] = var
            del self._saved_env[p]

    class ProxyGetter(object):
        """Utility class for retrieving proxy properties in with statement"""
        def __init__(self, proxy):
            self.__proxy = proxy
        def get_proxy(self):
            """Return proxy setting"""
            return self.__proxy.get_proxy()
        def get_handler(self):
            """Return urllib2 ProxyHandler object"""
            return self.__proxy.get_ProxyHandler()

    def __enter__(self):
        self.start()
        self.wait()
        self.enter_environment()
        return self.ProxyGetter(self)

    def __exit__(self, type, value, traceback):
        self.leave_environment()
        try:
            self.stop()
        except:
            pass

class ProxyContainerBasic(ProxyContainer):
    """A derived class of ProxyContainer that uses Basic Proxy Authorization"""

    HTPASSWD = "htpasswd"

    conf_auth  = ("auth_param basic program /usr/lib/squid3/basic_ncsa_auth %s"
                  % ProxyContainer.docker_path(HTPASSWD))
    conf_acl = "acl password proxy_auth REQUIRED"
    conf_allow = "http_access allow password"

    def __init__(self, user, password, port=None):
        super(ProxyContainerBasic, self).__init__(port=port)
        self._user = user
        self._password = password
        self.create_htpasswd()

    def create_htpasswd(self):
        htpasswd = os.path.join(self._tmpdir, self.HTPASSWD)
        open(htpasswd, "w").close()
        with Basic(htpasswd, mode="md5") as userdb:
            userdb.add(self._user, self._password)
        self.files.append(self.HTPASSWD)

    def _get_proxy(self):
        user = "%s:%s@" % (self._user, self._password)
        return "http://%s%s:%d" % (user, self.get_ip(), self._port)

class ProxyFactory():
    """A factory class for ProxyContainer"""
    def __call__(self, port=None, user=None, password=None):
        if user is not None:
            if password is None:
                user, password = user.split(":")
            return ProxyContainerBasic(user, password, port=port)
        else:
            return ProxyContainer(port=port)

def print_py_environment():
    logger.debug("== Environment from os.environ ==")
    for p in ProxyContainer.env_vars:
        logger.debug("%s => %s" % (p, os.environ[p]))

def print_real_environment():
    env = open("/proc/%d/environ" % os.getpid()).read()
    logger.debug("== Environment from /proc/%d/environ: ==" % os.getpid())
    for x in env.split("\0"):
        try:
            var, val = x.split("=", 1)
        except ValueError:
            # empty line
            continue
        if var.endswith("_proxy"):
            logger.debug("%s => %s" % (var, val))

def commandline_args():
    from argparse import ArgumentParser
    args = ArgumentParser()
    args.add_argument('URLs', metavar='URL', type=str, nargs='*',
                      help = 'an URL to retrieve')
    args.add_argument('-p', '--port', type=int, help='proxy port to use (default: 3128)')
    args.add_argument('-u', '--user', help='proxy user in user:password format')
    args.add_argument('-i', '--impl',
                      help='set implementaton (cmdline or api, default: %s)'
                      % DockerClientFactory.get_default())
    args.add_argument('-s', '--shell', help='open a shell in new environment',
                      action='store_true')
    args.add_argument('-w', '--wait', help='wait for input', action='store_true')
    args.add_argument('-v', '--verbose', help='verbose output', action='store_true')
    return args.parse_args()

def main():
    
    from six.moves.urllib import request as urllib2
    logging.basicConfig(level=logging.INFO)
    options = commandline_args()

    if options.verbose:
        logger.setLevel(logging.DEBUG)
    if options.impl:
        DockerClientFactory.set_default(options.impl)

    with ProxyFactory()(port=options.port, user=options.user) as proxy:

        print_py_environment()
        print_real_environment()
        dbglvl = 1 if options.verbose else 0

        opener = urllib2.build_opener(
            proxy.get_handler(),
            urllib2.HTTPHandler(debuglevel=dbglvl),
            urllib2.HTTPSHandler(debuglevel=dbglvl))

        if options.wait:
            raw_input("Waiting. Hit enter to quit")

        for url in options.URLs:
            resp = opener.open(url)
            logger.info("Code: %d\n%s\n" % (resp.code, resp.info()))

        if options.shell:
            sys.stderr.write("== Opening shell, exit to quit ==\n")
            call(["/bin/bash"])
            sys.stderr.write("== Shell has exited, thank you ==\n")

if __name__ == "__main__":
    main()

