import sys
import re
import os
from time import sleep
from shutil import rmtree
from subprocess import Popen, call, check_call, check_output, PIPE, CalledProcessError
from htpasswd import Basic
from tempfile import mkdtemp
import logging

logger = logging.getLogger(__name__)

def lookup_in_PATH(cmd):
    for p in os.environ["PATH"].split(":"):
        exe = os.path.join(p, cmd)
        if os.path.exists(exe) and os.access(exe, os.X_OK):
            return exe
    raise RuntimeError("command %s not found in PATH" % cmd)

class ProxyContainer(object):

    SQUID_CONF = "squid.conf"
    SQUID_CONF_DIR = "/etc/squid3"
    DOCKER_IMG = "docker.io/sameersbn/squid"

    env_vars = ("http_proxy", "https_proxy")
    files = [ SQUID_CONF ]

    ### SQUID configuration - override in subclasses
    conf_auth = ""
    conf_acl = "acl localnet src 172.16.0.0/12"
    conf_allow = "http_access allow localnet"

    def host_path(self, fn):
        return os.path.join(self._tmpdir, fn)

    @classmethod
    def docker_path(cls, fn):
        return os.path.join(cls.SQUID_CONF_DIR, fn)
    
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

    def __init__(self, port=None):
        self.__cls_init__()
        if port is None:
            port = 3128
        self._port = port
        self.id = None
        self._saved_env = {}
        self._tmpdir = mkdtemp()
        self.create_squid_conf()

    def close(self):
        rmtree(self._tmpdir)
        self._tmpdir = None

    def create_squid_conf(self):
        with open(self.host_path(self.SQUID_CONF), "wb") as output:
            output.write("""\
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
""".format (auth=self.conf_auth, acl=self.conf_acl, allow=self.conf_allow, port=self._port))

    def short_id(self):
        return self.id[:12]
    
    def __str__(self):
        if self.id is not None:
            return "%s (running with id %s)" % (self.__class__.__name__, self.short_id())
        else:
            return "%s (not running)" % (self.__class__.__name__)

    @classmethod
    def _docker_call(cls):
        return [cls.DOCKER]

    def _volumes(self):
        tmp = [ ["-v", "%s:%s" % (self.host_path(x), self.docker_path(x)) ] for x in self.files ]
        return reduce(lambda x, y: x + y, tmp)

    def start(self, *args):
        if self.id is not None:
            raise RuntimeError("%s is already running" % self)
        id = check_output(
            self._docker_call() +
            ["run", "-d"] +
            # [  "--name", "python_squid_container" ] +
            self._volumes() +
            [ self.DOCKER_IMG ])
        self.id = id.strip()

    def is_running(self):
        if self.id is None:
            raise RuntimeError("%s is not running" % self)

    def get_ip(self):
        self.is_running()
        ip = check_output([self.DOCKER,
                           "inspect", "-f", "{{.NetworkSettings.IPAddress}}", self.id])
        ip = ip.strip()
        if ip == "":
            raise RuntimeError
        return ip

    def test_if_running(self):
        try:
            id = check_output(
                [self.DOCKER, "ps", "-q", "--no-trunc=true", "-f", "id=%s" % self.id])
        except CalledProcessError as exc:
            logger.error("%s returned %d, output:\n%s" % (exc.cmd, exc.returncode, exc.output))
            id = ""
        id = id.strip()
        if id != self.id:
            self.id = None
        self.is_running()

    def remove(self):
        try:
            check_output(
                [self.DOCKER, "rm", self.id])
        except CalledProcessError:
            logger.error("Failed to remove %s\n" % self)
        
    def kill(self):
        self.is_running()
        try:
            check_output(
                [self.DOCKER, "kill", self.id])
        except CalledProcessError:
            logger.error("Failed to kill %s\n" % self)
            raise
        self.id = None

    def stop(self):
        self.is_running()
        try:
            check_output(
                [self.DOCKER, "stop", self.id])
        except CalledProcessError:
            logger.warning("Failed to stop %s\n" % self)
        else:
            self.id = None

    def get_proxy(self):
        return "http://%s:%d" % (self.get_ip(), self._port)
            
    def get_proxies(self):
        p = self.get_proxy()
        return { "http": p, "https": p }

    def get_ProxyHandler(self):
        return urllib2.ProxyHandler(self.get_proxies())
    
    def enter_environment(self):
        if self._saved_env.has_key(self.env_vars[0]):
            return
        proxy = self.get_proxy()
        for p in self.env_vars:
            try:
                self._saved_env[p] = os.environ[p]
            except KeyError:
                self._saved_env[p] = None
            os.environ[p] = proxy

    def leave_environment(self):
        if not self._saved_env.has_key(self.env_vars[0]):
            return
        for p in self.env_vars:
            var = self._saved_env[p]
            if var is None:
                del os.environ[p]
            else:
                os.environ[p] = var
            del self._saved_env[p]

    def __enter__(self):
        def getter(arg):
            if arg == "proxy":
                return self.get_proxy()
            elif arg == "handler":
                return self.get_ProxyHandler()
            
        self.start()
        self.test_if_running()
        self.enter_environment()
        sleep(0.1)
        return getter

    def __exit__(self, type, value, traceback):
        self.leave_environment()
        try:
            self.kill()
            self.remove()
            self.close()
        except:
            pass
        
class ProxyContainerBasic(ProxyContainer):

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

    def get_proxy(self):
        user = "%s:%s@" % (self._user, self._password) 
        return "http://%s%s:%d" % (user, self.get_ip(), self._port)

class ProxyFactory():

    def __call__(self, port=None, user=None, password=None):
        if user is not None:
            if password is None:
                user, password = user.split(":")
            return ProxyContainerBasic(user, password, port=port)
        else:
            return ProxyContainer(port=port)

def print_real_environment():
    env = open("/proc/%d/environ" % os.getpid()).read()
    for x in env.split("\0"):
        try:
            var, val = x.split("=", 1)
        except ValueError:
            # empty line?
            continue
        if var.endswith("_proxy"):
            print "%s => %s (%s)" % (var, val, os.environ[var])

if __name__ == "__main__":

    import urllib2
    from argparse import ArgumentParser
    logging.basicConfig()
    
    args = ArgumentParser()
    args.add_argument('URLs', metavar='URL', type=str, nargs='*',
                      help = 'an URL to retrieve')
    args.add_argument('-p', '--port', type=int, help='proxy port to use (default: 3128)')
    args.add_argument('-u', '--user', help='proxy user in user:password format')
    args.add_argument('-s', '--shell', help='open a shell in new environment', action='store_true')
    args.add_argument('-w', '--wait', help='wait for input', action='store_true')
    
    options = args.parse_args()
    
    with ProxyFactory()(port=options.port, user=options.user) as proxy:

        for p in ProxyContainer.env_vars:
            print "%s: %s" % (p, os.environ[p])

        opener = urllib2.build_opener(
            proxy("handler"),
            urllib2.HTTPHandler(debuglevel=1),
            urllib2.HTTPSHandler(debuglevel=1))

        if options.wait:
            print_real_environment()
            raw_input("Waiting. Hit enter to quit")

        for url in options.URLs:
            resp = opener.open(url)
            print "Code: %d\n%s\n" % (resp.code, resp.info())
            
        if options.shell:
            sys.stderr.write("== Opening shell, exit to quit ==\n")
            call(["/bin/bash"])
            sys.stderr.write("== Shell has exited, thank you ==\n")
            
    for p in ProxyContainer.env_vars:
        try:
            print "%s: %s" % (p, os.environ[p])
        except KeyError: pass
