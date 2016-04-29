import sys
import re
import os
from shutil import rmtree
from subprocess import Popen, check_call, check_output, PIPE, CalledProcessError
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

class ProxyContainer:

    HTPASSWD = "htpasswd"
    SQUID_CONF = "squid.conf"
    SQUID_CONF_DIR = "/etc/squid3"
    DOCKER_IMG = "docker.io/sameersbn/squid"

    env_vars = ("http_proxy", "https_proxy")
    
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

    def __init__(self, user=None, password='pass', port=3128):
        self.__cls_init__()
        self._tmpdir = mkdtemp()
        self._port = port
        self._user = user
        self._password = password
        if user is not None:
            htpwasswd = os.path.join(self._tmpdir, self.HTPASSWD)
            os.open(htpasswd, "w").close()
            with Basic(htpasswd, mode="md5") as userdb:
                userdb.add(user, password)
            self.create_squid_conf(os.path.join(self._tmpdir, self.SQUID_CONF), self._port,
                                   htpasswd_path = os.path.join(self.SQUID_CONF_DIR, htpasswd))
        else:
            self.create_squid_conf(os.path.join(self._tmpdir, self.SQUID_CONF), self._port)
        self.id = None
        self._saved_env = {}

    def __del__(self):
        self.leave_environment()
        if self.id is not None:
            try:
                self.kill()
            except:
                pass
        rmtree(self._tmpdir)

    @staticmethod
    def create_squid_conf(path, port, htpasswd_path=None):
        if htpasswd_path is not None:
            auth  = "auth_param basic program /usr/lib/squid3/basic_ncsa_auth %s" % htpasswd_path
            acl = "acl password proxy_auth REQUIRED"
            allow = "password"
        else:
            auth = ""
            acl = "acl localnet src 172.16.0.0/12"
            allow = "localnet"

        with open(path, "wb") as output:
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
http_access allow {allow}
http_access allow localhost
http_access deny all
http_port {port}
""".format (auth=auth, acl=acl, allow=allow, port=port))


    def short_id(self):
        return self.id[:12]
    
    def __str__(self):
        if self.id is not None:
            return "%s (running with id %s)" % (self.__class__.__name__, self.short_id())
        else:
            return "%s (not running)" % (self.__class__.__name__)

    def start(self):
        if self.id is not None:
            raise RuntimeError("%s is already running" % self)
        id = check_output(
            [self.DOCKER,
             "run", "-d",
             # "--name", "python_squid_container",
             "-v", "%s/%s:%s/%s" % (self._tmpdir, self.SQUID_CONF,
                                    self.SQUID_CONF_DIR, self.SQUID_CONF),
             "-v", "%s/%s:%s/%s" % (self._tmpdir, self.HTPASSWD,
                                    self.SQUID_CONF_DIR, self.HTPASSWD),
             self.DOCKER_IMG])
        self.id = id.strip()
        # self.test_if_running()

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
        user = "" if self._user is None else "%s:%s@" % (self._user, self._password) 
        return "http://%s%s:%d" % (user, self.get_ip(), self._port)
            
    def enter_environment(self):
        if self._saved_env.has_key("http"):
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
        self.start()
        self.enter_environment()
        return self.get_proxy()

    def __exit__(self, type, value, traceback):
        self.leave_environment()
        try:
            self.kill()
        except:
            pass
        

if __name__ == "__main__":

    import urllib2
    logging.basicConfig()

    try:
        url = sys.argv[1]
    except IndexError:
        logging.error("Usage: %s url [-i] [user password [port]]" % sys.argv[0])
        sys.exit(1)

    first = 2
    try:
        if sys.argv[2] == "-i":
            first = 3
    except IndexError:
        pass

    opener = urllib2.build_opener(urllib2.HTTPHandler(debuglevel=1),
                                  urllib2.HTTPSHandler(debuglevel=1))

    with ProxyContainer(*sys.argv[first:]):
        for p in ProxyContainer.env_vars:
            print "%s: %s" % (p, os.environ[p])
        resp = opener.open(url)
        print "Code: %d\n%s\n" % (resp.code, resp.info())
        if first == 3:
            raw_input ("interactive mode, hit return")
        
    for p in ProxyContainer.env_vars:
        try:
            print "%s: %s" % (p, os.environ[p])
        except KeyError: pass


