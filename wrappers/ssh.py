#!/usr/bin/env python3
import os
import sys
import socket
import errno
import re
import json
import time
import argparse
import logging
import uuid
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'shared')))
from isolate_config import load_config
from isolate_identity import local_identity
from isolate_logging import SessionLogger
from isolate_ssh import SSHArgumentError, build_ssh_argv

LOGGER = logging.getLogger('ssh-wrapper')
LOG_FORMAT = '[%(asctime)s] [%(levelname)6s] %(name)s %(message)s'

__version__ = '0.0.24'

# set proper working dir
working_dir = os.path.dirname(os.path.realpath(__file__))
os.chdir(working_dir)

# Get user real name
local_sudo_user = os.getenv('SUDO_USER', 'NO_SUDO_USER_ENV')

data_root = '/opt/auth'
ssh_configs_path = data_root + '/configs'
logs_base_path = data_root + '/logs'

# args prepare
# args = sys.argv[1:]

# misc
local_timestamp = int(time.time())

term_colors = {
    'gray': '\033[38;5;249m',
    'blue': '\033[38;5;45m',
    'red': '\033[38;5;160m',
    'green': '\033[38;5;40m',
    'reset': '\033[0m',
    'orange': '\033[38;5;220m',
    'bebe': '\033[38;5;142m'
}


def mkdir(path):
    try:
        os.makedirs(path)
        return True
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            return True
            pass
        else:
            raise


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return True
    except socket.error:
        return False

    return True


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        return False
    return True


def is_valid_fqdn(hostname):
    hostname = str(hostname).lower()
    if len(hostname) > 255:
        return False
    if hostname[-1] == '.' or hostname[0] == '.':
        return False
    if re.match(r'^([a-z\d\-.]*)$', hostname) is None:
        return False
    if hostname.startswith('-'):
        return False
    return True


def verify_args(args):

    host = dict()
    host['hostname'] = None
    host['port'] = None
    host['user'] = None
    host['proxy_id'] = args.proxy_id
    host['proxy_host'] = None
    host['proxy_port'] = None
    host['proxy_user'] = None
    host['nosudo'] = bool(args.nosudo)
    host['debug'] = bool(args.debug)

    # host
    hostname = args.hostname[0]

    if is_valid_ipv4_address(hostname) or is_valid_ipv6_address(hostname) or is_valid_fqdn(hostname):
        host['hostname'] = hostname
    else:
        LOGGER.critical('[hostname] Validation not passed')
        sys.exit(1)

    if args.user is not None:
        user = args.user[0]
        if re.match(r'^[A-Za-z,\d\-]*$', user) is None or \
                                        len(user) > 48 or \
                                        user.startswith('-'):
            LOGGER.critical('[user] Validation not passed')
            sys.exit(1)

        host['user'] = user
        LOGGER.debug('[user] override is set: ' + user)

    if args.port is not None:
        port = int(args.port)
        if port > 65535 or port <= 0:
            LOGGER.critical('[port] Validation not passed')
            sys.exit(1)
        else:
            host['port'] = int(port)
            LOGGER.debug('[port] override is set: ' + str(port))

    # proxy_host
    if args.proxy_host is not None:
        proxy_host = args.proxy_host[0]
        if (is_valid_ipv4_address(proxy_host) or \
                is_valid_ipv6_address(proxy_host) or \
                is_valid_fqdn(proxy_host)) and not proxy_host.startswith('-'):
            host['proxy_host'] = proxy_host
        else:
            LOGGER.critical('[proxy_host] Validation not passed')
            sys.exit(1)

    if args.proxy_user is not None:
        proxy_user = args.proxy_user[0]
        if re.match(r'^[A-Za-z\d\-]*$', proxy_user) is None or \
                                                   len(proxy_user) > 48 or \
                                                   proxy_user.startswith('-'):
            LOGGER.critical('[proxy_user] Validation not passed')
            sys.exit(1)

        host['proxy_user'] = proxy_user
        LOGGER.debug('[proxy_user] override is set: ' + proxy_user)

    if args.proxy_port is not None:
        proxy_port = int(args.proxy_port)
        if proxy_port > 65535 or proxy_port <= 0:
            LOGGER.critical('[proxy_port] Validation not passed')
            sys.exit(1)
        else:
            host['proxy_port'] = proxy_port
            LOGGER.debug('[proxy_port] override is set: ' + str(proxy_port))

    return host


# make dirs and prepare files
def init_log_file(host):

    host['wrap_ver'] = __version__
    host['uuid'] = str(uuid.uuid4())
    host['auth_user'] = local_sudo_user
    host['auth_ts'] = local_timestamp
    host['sys_argv'] = sys.argv
    host['server_ip'] = args.hostname[0]

    current_user_log_dir = '{0}/{1}'.format(logs_base_path, local_sudo_user)
    mkdir(current_user_log_dir)

    # example: /tmp/root/root_127.0.0.1_22_common_1485110002_<uuid>.log
    current_log_path = '{0}/{1}_{2}_{3}_{4}_{5}.log'.format(current_user_log_dir,
                                                            local_sudo_user,
                                                            host['hostname'],
                                                            host['port'],
                                                            local_timestamp,
                                                            host['uuid'][:12])

    host['log_path'] = current_log_path
    LOGGER.debug(current_log_path)

    # write logfile metadata
    log_meta = '{0}'.format(json.dumps(host, indent=4))
    with open(current_log_path + '.meta', 'w') as log_f:
        log_f.write(log_meta)

    LOGGER.debug(log_meta)

    return current_log_path


def run_command(argv, raw_log_path, audit, metadata):

    LOGGER.debug(argv)
    audit.event("ssh_start", argv=argv, **metadata)
    started = time.time()

    with open(raw_log_path, 'a', encoding='utf-8', errors='replace') as raw_log:
        proc = subprocess.Popen(
            argv,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        while True:
            chunk = proc.stdout.readline()
            if not chunk:
                break
            text = chunk.decode('utf-8', errors='replace')
            sys.stdout.write(text)
            sys.stdout.flush()
            raw_log.write('{0:.6f}\n{1}'.format(time.time(), text))
            raw_log.flush()
        exit_code = proc.wait()

    if exit_code != 0:
        msg = 'Exit code: {1}{0}{2}'.format(exit_code, term_colors['red'], term_colors['reset'])
        msg = '\n  {0}\n'.format(msg)
        LOGGER.warning(msg)
    audit.event("ssh_end", exit_code=exit_code, duration=round(time.time() - started, 3), **metadata)
    return exit_code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='ssh-wrapper', epilog='------',
                                     description='ssh sudo wrapper')
    #
    parser.add_argument('hostname', type=str, help='server address (allowed FQDN,[a-z-],ip6,ip4)', nargs=1)
    parser.add_argument('--user', type=str, help='set target username', nargs=1)
    parser.add_argument('--port', type=int, help='set target port')
    parser.add_argument('--nosudo', action='store_true', help='run connection without sudo terminating command')
    parser.add_argument('--config', help='DEPRECATED', type=str, nargs=1)
    parser.add_argument('--debug', action='store_true')
    #
    parser.add_argument('--proxy-host', type=str, nargs=1)
    parser.add_argument('--proxy-user', type=str, nargs=1)
    parser.add_argument('--proxy-port', type=int)
    parser.add_argument('--proxy-id', type=str, nargs=1, help='just for pretty logs')
    args, extra_args = parser.parse_known_args()
    #
    if args.debug:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                            format=LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
        LOGGER.info('ssh wrapper debug mode on')
        LOGGER.info(sys.argv)
        LOGGER.info(vars(args))
    else:
        logging.basicConfig(stream=sys.stderr, level=logging.WARN,
                            format=LOG_FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
    #
    LOGGER.info(__version__)
    LOGGER.debug(working_dir)
    LOGGER.debug(args)
    #
    host_meta = verify_args(args)
    raw_log_path = init_log_file(host_meta)
    config = load_config()
    identity = local_identity(local_sudo_user, [])
    audit = SessionLogger(config["logging"]["base_path"], identity, session_id=host_meta["uuid"])
    remote_command = None if host_meta['nosudo'] else 'sudo -i'
    proxy = None
    if args.proxy_host:
        proxy = {
            "host": host_meta["proxy_host"],
            "port": host_meta["proxy_port"],
            "user": host_meta["proxy_user"],
        }
    try:
        argv = build_ssh_argv(
            config["ssh"],
            {
                "hostname": host_meta["hostname"],
                "port": host_meta["port"],
                "user": host_meta["user"],
                "debug": host_meta["debug"],
            },
            extra_args=extra_args,
            proxy=proxy,
            remote_command=remote_command,
        )
    except SSHArgumentError as exc:
        audit.event("ssh_argument_denied", reason=str(exc), **host_meta)
        LOGGER.critical(str(exc))
        sys.exit(1)

    LOGGER.debug(argv)
    LOGGER.debug(host_meta)

    host_meta['argv'] = argv
    sys.exit(run_command(argv, raw_log_path, audit, {
        "target_host": host_meta["hostname"],
        "target_port": host_meta["port"],
        "remote_user": host_meta["user"],
        "source_ip": os.getenv("SSH_CONNECTION", "").split(" ")[0] if os.getenv("SSH_CONNECTION") else None,
    }))
