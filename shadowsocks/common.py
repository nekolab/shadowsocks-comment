#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# absolute import is a future feature opt in python 2.5 and default in 3.0, import this to disable relative import
# division is a future feature opt in python 2.2 and default in 3.0, import this to change division operator behavior
#   from integer division to float division
# print function is a future feature opt in python 2.6 and default in 3.0, import this can change print to print()
# with statement is a future feature opt in python 2.5 and default in 2.6, import this can enable "with" statement
from __future__ import absolute_import, division, print_function, \
    with_statement

import socket   # Python socket library.  Docs can be found at https://docs.python.org/2/library/socket.html
import struct   # Python struct library.  Docs can be fount at https://docs.python.org/2/library/struct.html
import logging  # Python logging library. Docs can be found at https://docs.python.org/2/library/logging.html


# A native ord function wrapper which can accept not only one-length string
# as syntax but also number. When syntax is number, it will be returned directly.
def compat_ord(s):
    if type(s) == int:
        return s
    return _ord(s)


# In python 3, chr() accepts number from 0x0 to 0x10FFFF and return an UNICODE string, keeping with it's
# "Unicode strings are default" policy, which equivalent to unichr() in python 2, but chr() in Python 2
# only accept syntax from 0x0 to 0xFF and return a BYTE string. To simulate chr()'s behavior in python 2
# on python 3. We should compare bytes to str first, on Python 2 they are same, on Python 3 bytes is not str,
# then we can use bytes([d]) to simulate old chr().
def compat_chr(d):
    if bytes == str:    # True when Python 2
        return _chr(d)
    return bytes([d])


# Map built-in ord and chr to _ord and _chr and then shadow built-in ord and chr to above modded version.
_ord = ord
_chr = chr
ord = compat_ord
chr = compat_chr


# convert str to bytes in Python 3
def to_bytes(s):
    if bytes != str:            # True when Python 3
        if type(s) == str:      # When s is string, use s.encode() convert it to bytes
            return s.encode('utf-8')
    return s


# convert bytes to str in Python 3
def to_str(s):                  # Inverse version of to_bytes()
    if bytes != str:            # True when Python 3
        if type(s) == bytes:    # When s is bytes, use s.decode() convert it to string
            return s.decode('utf-8')
    return s


# Convert a packed binary version IP address to its family-specific string format
# Since this function has only native support on Unix system, shadowsocks implement it by itself
def inet_ntop(family, ipstr):
    if family == socket.AF_INET:                    # IPv4
        return to_bytes(socket.inet_ntoa(ipstr))    # Return a packed version of ipstr in bytes by using native inet_ntoa which could be found on all platform
    elif family == socket.AF_INET6:                 # IPv6
        import re
        v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j))).lstrip('0')   # Convert i, j to ascii code then convert them to fixed length hex string and left strip 0
                          for i, j in zip(ipstr[::2], ipstr[1::2]))     # Function zip convert "1234" to [('1','2'),('3','4')]
        v6addr = re.sub('::+', '::', v6addr, count=1)                   # If ':::' in v6addr, use '::' replace it
        return to_bytes(v6addr)                                         # return v6addr in bytes on Python 3


# Convert an IP address from its family-specific string format to a packed binary version
# Since this function has only native support on Unix system, shadowsocks implement this by itself
def inet_pton(family, addr):
    addr = to_str(addr)                 # Convert possible bytes to string in Python 3
    if family == socket.AF_INET:        # IPv4
        return socket.inet_aton(addr)   # Use native inet_aton method to convert
    elif family == socket.AF_INET6:     # IPv6
        if '.' in addr:  # a v4 addr    # A IPv4-mapped IPv6 addresses like ::ffff:192.168.1.1
            v4addr = addr[addr.rindex(':') + 1:]    # Get v4addr from last ':' in address to end like 192.168.1.1
            v4addr = socket.inet_aton(v4addr)       # Convert v4addr to packed version by using native method like '\xc0\xa8\x01\x01'
            v4addr = map(lambda x: ('%02X' % ord(x)), v4addr)   # Convert each character to hex ascii number list like ['C0','A8','01','01']
            v4addr.insert(2, ':')                               # Insert ':' before 3rd item in list ['C0','A8',':','01','01']
            newaddr = addr[:addr.rindex(':') + 1] + ''.join(v4addr)     # Append ipv4 address to IPv6 prefix like ::ffff:C0A8:0101
            return inet_pton(family, newaddr)                   # Use this method recalculate again
        dbyts = [0] * 8  # 8 groups                             # [0, 0, 0, 0, 0, 0, 0, 0]
        grps = addr.split(':')                                  # Split address by using ':' as delimiter
        for i, v in enumerate(grps):                # i is index and v is content
            if v:                                   # if v is not ''. Since '::' in IPv6 address, v maybe ''
                dbyts[i] = int(v, 16)               # Convert v to number because v is hexadecimal string
            else:
                for j, w in enumerate(grps[::-1]):  # Reverse calculate direction when meet '::' in address
                    if w:
                        dbyts[7 - j] = int(w, 16)   # Calculate hexadecimal string w to number
                    else:                           # Reach the '::'
                        break
                break
        return b''.join((chr(i // 256) + chr(i % 256)) for i in dbyts) # Example: Convert dbyts element like 65535 to '\xff\xff' then join them
    else:
        raise RuntimeError("What family?")


# Try to find the ip address family
def is_ip(address):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            if type(address) != str:
                address = address.decode('utf8')
            inet_pton(family, address)
            return family
        except (TypeError, ValueError, OSError, IOError):
            pass
    return False


def patch_socket():
    if not hasattr(socket, 'inet_pton'):    # Other than Unix-like system, Python doesn't support native inet_pton, so use self implemented version
        socket.inet_pton = inet_pton

    if not hasattr(socket, 'inet_ntop'):    # Other than Unix-like system, Python doesn't support native inet_ntop, so use self implemented version
        socket.inet_ntop = inet_ntop


patch_socket()  # Let's rock~


# You can find these definition in RFC1928 page 7
ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3


# Pack IPv4/IPv6/Host address to binary version and add type specific prefix
# If address is IPv4 address, like '192.168.1.1', will be packed to b'\x01\xc0\xa8\x01\x01' (Type prefix \x01 added)
# If address is IPv6 address, like '::ffff:c0a8:0101', will be packed to '\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xc0\xa8\x01\x01' (Type prefix \x04 added)
# If address is Host address, like 'www.google.com', will be packed to '\x03\x0ewww.google.com' (Type prefix \x03 and additional length prefix added)
def pack_addr(address):
    address_str = to_str(address)
    for family in (socket.AF_INET, socket.AF_INET6):        # Use a loop to determine family is IPv4 or IPv6 or host
        try:
            r = socket.inet_pton(family, address_str)
            if family == socket.AF_INET6:
                return b'\x04' + r
            else:
                return b'\x01' + r
        except (TypeError, ValueError, OSError, IOError):
            pass
    if len(address) > 255:                                  # If address type is host, limit host length in 256 bytes
        address = address[:255]  # TODO
    return b'\x03' + chr(len(address)) + address


# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   | (header format)
# +------+----------+----------+----------+
# Parse IPv4/IPv6/Host header in packet to a tuple (for shadowsocks package and a part of socks5 package).
# Returns (address type, destination address in form of bytes, destination port and header length)
def parse_header(data):
    addrtype = ord(data[0])                                 # Convert first byte from binary to number address type
    dest_addr = None
    dest_port = None
    header_length = 0
    if addrtype == ADDRTYPE_IPV4:                           # If address is IPv4 address
        if len(data) >= 7:                                  # (Type byte(1) + IP bytes(4) + Port bytes(2)) = 7
            dest_addr = socket.inet_ntoa(data[1:5])         # Convert 4 bytes from binary to readable ip address
            dest_port = struct.unpack('>H', data[5:7])[0]   # Convert 2 bytes from big endian unsigned short in C (represent as python string) to python int
            header_length = 7                               # Set header length to 7
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_HOST:                         # If address is host address
        if len(data) > 2:                                   # Confirm data has at least address byte and address length byte
            addrlen = ord(data[1])                          # Convert second byte from binary to number (First byte is address length)
            if len(data) >= 2 + addrlen:                    # Data length should greater than 2 (type byte and len byte) + address length
                dest_addr = data[2:2 + addrlen]             # Clip address by using calculated address length (Bypass first two bytes)
                dest_port = struct.unpack('>H', data[2 + addrlen:4 +    # Convert 2 bytes to python int
                                          addrlen])[0]                  # Since unpack returns a tuple so use [0] to get port number
                header_length = 4 + addrlen                 # 4 (type byte(1) + address len byte(1) + port bytes(2)) + address length
            else:
                logging.warn('header is too short')
        else:
            logging.warn('header is too short')
    elif addrtype == ADDRTYPE_IPV6:                         # If address is IPv6 address
        if len(data) >= 19:                                 # Confirm data has more than (type byte(1) + ip bytes(16) + port bytes(2)) = 19
            dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])   # Convert 16 bytes from binary to readable ip address
            dest_port = struct.unpack('>H', data[17:19])[0]             # Convert  2 bytes to python int
            header_length = 19                              # Set header length to 19
        else:
            logging.warn('header is too short')
    else:
        logging.warn('unsupported addrtype %d, maybe wrong password' %
                     addrtype)
    if dest_addr is None:
        return None
    return addrtype, to_bytes(dest_addr), dest_port, header_length


class IPNetwork(object):                                                # Class IPNetwork is used to process CIDR match
    ADDRLENGTH = {socket.AF_INET: 32, socket.AF_INET6: 128, False: 0}

    def __init__(self, addrs):
        self._network_list_v4 = []
        self._network_list_v6 = []
        if type(addrs) == str:
            addrs = addrs.split(',')
        list(map(self.add_network, addrs))

    def add_network(self, addr):
        if addr is "":
            return
        block = addr.split('/')
        addr_family = is_ip(block[0])
        addr_len = IPNetwork.ADDRLENGTH[addr_family]                            # IPv4 -> 32, IPv6 -> 128
        if addr_family is socket.AF_INET:                                       # If it's a IPv4 address
            ip, = struct.unpack("!I", socket.inet_aton(block[0]))               # Unpack IP address to a 32 bit number
        elif addr_family is socket.AF_INET6:                                    # or it's a IPv6 address
            hi, lo = struct.unpack("!QQ", inet_pton(addr_family, block[0]))     # Unpack IP address to two 64 bit number
            ip = (hi << 64) | lo                                                # Combine these to one 128 bit number
        else:
            raise Exception("Not a valid CIDR notation: %s" % addr)
        if len(block) is 1:                                                     # If no prefix size provided
            prefix_size = 0
            while (ip & 1) == 0 and ip is not 0:                                # Loop to check how many continuous 0
                ip >>= 1                                                        # on the right of IP Number, get network
                prefix_size += 1                                                # range and prefix size
            logging.warn("You did't specify CIDR routing prefix size for %s, "
                         "implicit treated as %s/%d" % (addr, addr, addr_len))
        elif block[1].isdigit() and int(block[1]) <= addr_len:                  # If prefix size is provided
            prefix_size = addr_len - int(block[1])                              # Calculate by using length minus it
            ip >>= prefix_size                                                  # and get network range
        else:
            raise Exception("Not a valid CIDR notation: %s" % addr)
        if addr_family is socket.AF_INET:                                       # Append (range, prefix_size) to
            self._network_list_v4.append((ip, prefix_size))                     # specified list
        else:
            self._network_list_v6.append((ip, prefix_size))

    def __contains__(self, addr):                                               # Override operator 'in'
        addr_family = is_ip(addr)
        if addr_family is socket.AF_INET:
            ip, = struct.unpack("!I", socket.inet_aton(addr))                   # Convert given ip address to number
            return any(map(lambda n_ps: n_ps[0] == ip >> n_ps[1],               # if any tuple in list matches
                           self._network_list_v4))                              # range = ip >> prefix_size
        elif addr_family is socket.AF_INET6:                                    # return True
            hi, lo = struct.unpack("!QQ", inet_pton(addr_family, addr))
            ip = (hi << 64) | lo
            return any(map(lambda n_ps: n_ps[0] == ip >> n_ps[1],
                           self._network_list_v6))
        else:
            return False


# Some tests
def test_inet_conv():
    ipv4 = b'8.8.4.4'
    b = inet_pton(socket.AF_INET, ipv4)
    assert inet_ntop(socket.AF_INET, b) == ipv4
    ipv6 = b'2404:6800:4005:805::1011'
    b = inet_pton(socket.AF_INET6, ipv6)
    assert inet_ntop(socket.AF_INET6, b) == ipv6


def test_parse_header():
    assert parse_header(b'\x03\x0ewww.google.com\x00\x50') == \
        (3, b'www.google.com', 80, 18)
    assert parse_header(b'\x01\x08\x08\x08\x08\x00\x35') == \
        (1, b'8.8.8.8', 53, 7)
    assert parse_header((b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00'
                         b'\x00\x10\x11\x00\x50')) == \
        (4, b'2404:6800:4005:805::1011', 80, 19)


def test_pack_header():
    assert pack_addr(b'8.8.8.8') == b'\x01\x08\x08\x08\x08'
    assert pack_addr(b'2404:6800:4005:805::1011') == \
        b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00\x00\x10\x11'
    assert pack_addr(b'www.google.com') == b'\x03\x0ewww.google.com'


def test_ip_network():
    ip_network = IPNetwork('127.0.0.0/24,::ff:1/112,::1,192.168.1.1,192.0.2.0')
    assert '127.0.0.1' in ip_network
    assert '127.0.1.1' not in ip_network
    assert ':ff:ffff' in ip_network
    assert '::ffff:1' not in ip_network
    assert '::1' in ip_network
    assert '::2' not in ip_network
    assert '192.168.1.1' in ip_network
    assert '192.168.1.2' not in ip_network
    assert '192.0.2.1' in ip_network
    assert '192.0.3.1' in ip_network  # 192.0.2.0 is treated as 192.0.2.0/23
    assert 'www.google.com' not in ip_network


if __name__ == '__main__':
    test_inet_conv()
    test_parse_header()
    test_pack_header()
    test_ip_network()
