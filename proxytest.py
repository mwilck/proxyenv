import sys
import re
import os
from time import sleep
from shutil import rmtree
from htpasswd import Basic
from tempfile import mkdtemp
from subprocess import check_output, PIPE, CalledProcessError
from docker import Client
import logging

logger = logging.getLogger(__name__)

def lookup_in_PATH(cmd):
    for p in os.environ["PATH"].split(":"):
        exe = os.path.join(p, cmd)
        if os.path.exists(exe) and os.access(exe, os.X_OK):
            return exe
    raise RuntimeError("command %s not found in PATH" % cmd)

class DockerClient(object):

    def test_if_running(self, id):
        return False

    def get_ip(self, id):
        return ""

    def stop(self, id):
        pass
        
    def kill(self, id):
        pass
        
    def rm(self, id):
        pass

    def run(self, image, volumes, args):
        pass

class DockerClientCmdline(DockerClient):

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
        tmp = [ ["-v", "%s:%s" % (x, y) ] for x, y in volumes.iteritems() ]
        vol = reduce(lambda x, y: x + y, tmp)
        return self.cmd(["run"] + args + vol + [ image ])

class DockerClientApi(DockerClient):

    def __init__(self):
        self._clt = Client()

    def test_if_running(self, id):
        return False

    def get_ip(self, id):
        return ""

    def stop(self, id):
        pass
        
    def kill(self, id):
        pass
        
    def rm(self, id):
        pass

    def run(self, image, volumes, args):
        pass

class DockerClientFactory(object):
    def __call__(self):
        return DockerClientCmdline()

class ProxyContainer(object):

    SQUID_CONF = "squid.conf"
    SQUID_CONF_DIR = "/etc/squid3"
    DOCKER_IMG = "docker.io/sameersbn/squid"

    env_vars = ("http_proxy", "https_proxy")
    files = [ SQUID_CONF ]

    STATE_OFF = 0
    STATE_STOPPED = 1
    STATE_RUNNING = 2

    states = {
        STATE_OFF: "off",
        STATE_STOPPED: "stopped",
        STATE_RUNNING: "running"
    }
    
    ### SQUID configuration - override in subclasses
    conf_auth = ""
    conf_acl = "acl localnet src 172.16.0.0/12"
    conf_allow = "http_access allow localnet"

    def host_path(self, fn):
        return os.path.join(self._tmpdir, fn)

    @classmethod
    def docker_path(cls, fn):
        return os.path.join(cls.SQUID_CONF_DIR, fn)
    
    def __init__(self, port=None):
        self._client = DockerClientFactory()()
        if port is None:
            port = 3128
        self._port = port
        self.id = None
        self._saved_env = {}
        self._tmpdir = mkdtemp()
        self.create_squid_conf()
        self._state = self.STATE_OFF
        
    def close(self):
        rmtree(self._tmpdir)
        self._tmpdir = None
        self._state = self.STATE_OFF

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
        if self.id is None:
            return None
        return self.id[:12] 
    def __str__(self):
        if self.id is not None:
            return "%s (%s with id %s)" % (self.__class__.__name__, self._state, self.short_id())
        else:
            return "%s (%s)" % (self.__class__.__name__, self._state)

    def _volumes(self):
        return dict ( (self.host_path(x), self.docker_path(x)) for x in self.files )

    def start(self, *args):
        if self.id is not None:
            raise RuntimeError("%s is already running" % self)
        
        self.id = self._client.run(self.DOCKER_IMG, self._volumes(), ["-d"] )
        self._state = self.STATE_RUNNING
        
    def is_running(self):
        if self._state is not self.STATE_RUNNING:
            raise RuntimeError("%s is not running" % self)

    def get_ip(self):
        self.is_running()
        ip  = self._client.get_ip(self.id)
        if ip == "":
            raise RuntimeError("Unable to detect proxy IP address")
        return ip

    def test_if_running(self):
        if self._state is self.STATE_RUNNING:
            if not self._client.test_if_running(self.id):
                self._state = self.STATE_STOPPED

    def rm(self):
        self._client.rm(self.id)
        self.id = None
        self._state = self.STATE_OFF
        
    def kill(self):
        self.is_running()
        try:
            self._client.kill(self.id)
        except CalledProcessError:
            pass
        self._state = self.STATE_STOPPED

    def stop(self):
        self.is_running()
        try:
            self._client.stop(self.id)
        except CalledProcessError:
            pass
        self._state = self.STATE_STOPPED

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
        self.enter_environment()
        sleep(0.1)
        return getter

    def __exit__(self, type, value, traceback):
        self.leave_environment()
        try:
            self.kill()
            self.rm()
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
