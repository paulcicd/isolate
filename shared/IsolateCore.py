#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import socket
import re

try:
    import geoip2.database
except ImportError:
    geoip2 = None

sys.dont_write_bytecode = True

# Common snippets and funcs for use in other scripts (tiny lib)

__version__ = '0.2.0'


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
    return True


class IsolateGeoIP(object):

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.ASN_DB = os.getenv('ISOLATE_GEOIP_ASN', '/opt/auth/shared/geoip/GeoLite2-ASN.mmdb')
        self.asn = self
        self.reader = None
        if geoip2 is not None and os.path.exists(self.ASN_DB):
            self.reader = geoip2.database.Reader(self.ASN_DB)

    def name_by_addr(self, address):
        if self.reader is None:
            return None
        try:
            response = self.reader.asn(address)
            return response.autonomous_system_organization
        except Exception:
            return None


class IsolateStorage(object):
    pass


class IsolateCore(object):
    pass
