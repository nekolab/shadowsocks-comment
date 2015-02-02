#!/usr/bin/env python
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


# Commented in common.py
from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import os
import socket
import struct
import re
import logging

from shadowsocks import common, lru_cache, eventloop


CACHE_SWEEP_INTERVAL = 30

# A regexp match string not start from or end with '-', contains letter less than 63 A-Z and -. No case sensitive.
VALID_HOSTNAME = re.compile(br"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

# Patch socket (Add self-implemented stocket.inet_ntop() and socket.inet_pton() for non UNIX like system).
common.patch_socket()

# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

# These constants are defined in RFC1035.
# Full types and classes list could be found in section 3.2.2 to 3.2.5 on RFC 1035.
QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_NS = 2
QCLASS_IN = 1


# Build dns request/response address by using ordinary address.
def build_address(address):
    address = address.strip(b'.')   # Remove '.' on both side of address.
    labels = address.split(b'.')    # Split address by using '.' as separator.
    results = []
    for label in labels:            # Iterate each level in address.
        l = len(label)              # Get length of this level in domain.
        if l > 63:                  # If length is longer than 63 (max length in standard).
            return None
        results.append(common.chr(l))   # Append length in form of bytes to results.
        results.append(label)           # Append this level to results.
    results.append(b'\0')               # Append end marker to results.
    return b''.join(results)            # Join them by using byte empty string ''.


# Build dns request
# Question section format in RFC 1035
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                     QNAME                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QCLASS                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#
def build_request(address, qtype):
    # ! is big endian, H is unsigned short and B is unsigned char.
    # In header, request id is a 16 bit identifier, so use unsigned short to represent it.
    #
    # Then is QR, Opcode, AA, TC and RC in 8 bits.
    # QR is 'Query' is '0' in bit in DNS request case,
    # Opcode is 'a standard query' is '0000' in bit form,
    # AA (Authoritative Answer) is not used in query so set as '0' in bit,
    # TC (TrunCation) is set to '0' in bit. It can be set to '1' when request pack's length
    # is greater than permitted on the transmission channel (512 bytes in UDP) and has been truncated,
    # RD (Recursion Desired) is set to '1' to direct the name server to pursue the query recursively.
    # So second unsigned char bit sequence is '0 0000 0 0 1' so third syntax of struct.pack() is 1.
    #
    # Then is RA, Z and RCODE in next 8 bits.
    # RA (Recursion Available) costs 1 bit indicates whether the server support recursion query or not.
    # This filed is meaningful in response but useless in query, so set it to '0'
    # Z costs 3 bit and is reserved for future use, so it MUST be zero in all queries and responses.
    # RCODE is a 4 bit field indicates response status. There are 5 types of RCODE in RFC 1035, here
    # we use 0 which means 'No error condition' since this is a query.
    # So third unsigned char bit sequence is '0 000 0000' so fourth syntax of struct.pack() is 0.
    #
    # Next four unsigned 16 bit integer fields is QDCOUNT, ANCOUNT, NSCOUNT and ARCOUNT.
    # QDCOUNT specifying the number of entries in the question section.
    # In this case just includes one question in a request, so set this field to 1.
    # ANCOUNT specifying the number of resource records in the answer section.
    # Since this is a request packet, no answer in this packet so set this field to 0.
    # NSCOUNT specifying the number of name server resource records in the authority records section.
    # Since this is a request packet, no answer in this packet so set this field to 0.
    # ARCOUNT specifying the number of resource records in the additional records section, set to 0 in this case.
    request_id = os.urandom(2)								# Generate random request id
    header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
    addr = build_address(address)    # Convert ordinary address to dns request style address format.
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)     # qtype (16 bit) indicates query type (A, AAAA, CNAME etc.).
                                                            # QCLASS_IN (16 bit) means query on the Internet.
    return request_id + header + addr + qtype_qclass        # Join them to build a DNS request packet.


# Resolve RDATA by giving TYPE, data, length and offset
def parse_ip(addrtype, data, length, offset):
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype in [QTYPE_CNAME, QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


# Resolve name from NAME struct
def parse_name(data, offset):
    p = offset
    labels = []
    l = common.ord(data[p])     # Read first byte to get first part of domain name's length.
    while l > 0:
        if (l & (128 + 64)) == (128 + 64):  # According to RFC, name stores like (length)(name)(length)(name)(...)\x00,
            # if length's first two bit is '11' indicates it's a pointer, pointer use two bytes different with one byte
            # length, that's also the reason why any part of domain cannot be longer than 63 bytes.
            # 128 + 64 = 192 in bit form is '1100 0000', logic add l and 192 can judge whether it's a pointer or not.
            pointer = struct.unpack('!H', data[p:p + 2])[0]     # Unpack next two bytes to get compress pointer value.
            pointer &= 0x3FFF                       # Logic and '0011 1111' to pointer again to remove '11' prefix.
            r = parse_name(data, pointer)           # Recursive invoke parse name to get compressed domain name.
            labels.append(r[1])                     # Append decompressed domain name to labels.
            p += 2                                  # Move to the byte next to the pointer.
            # pointer is the end                    # See RFC 1035 4.1.4. Message compression for more schema detail.
            return p - offset, b'.'.join(labels)    # Return a tuple contains name length and domain name
        else:
            labels.append(data[p + 1:p + 1 + l])    # Domain name sequence, push (name) into labels.
            p += 1 + l                              # Move pointer to next (length) pointer.
        l = common.ord(data[p])                     # Use pointer to get next (length).
    return p - offset + 1, b'.'.join(labels)        # Return a tuple contains name length and domain name


# rfc1035
# this is answer record, question record see line 103
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
def parse_record(data, offset, question=False):
    nlen, name = parse_name(data, offset)       # Parse name's length and content
    if not question:                            # Only answer contains TTL and RDLength
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]     # big-endian ushort TYPE, ushort CLASS, int TTL and
        )                                                       # ushort RDLENGTH, 2 + 2 + 4 + 2 = 10
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)   # Parse IP from data
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)   # Return a tuple contains record length and content
    else:                                       # Just a question
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]        # big-endian ushort TYPE and ushort CLASS, 2 + 2 = 4
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)


# Header contains a lot of data, see line 118 for more information
def parse_header(data):
    if len(data) >= 12:
        header = struct.unpack('!HBBHHHH', data[:12])
        res_id = header[0]
        res_qr = header[1] & 128        # 128 = 0b10000000 Get the first bit of first byte.
        res_tc = header[1] & 2          # 2   = 0b00000010
        res_ra = header[2] & 128
        res_rcode = header[2] & 15      # 15  = 0b00001111
        # assert res_tc == 0            # Assert message is not truncated.
        # assert res_rcode in [0, 3]    # 0 is No error condition, 3 is Name Error.
        res_qdcount = header[3]         # Get question count.
        res_ancount = header[4]         # Get answer count.
        res_nscount = header[5]         # Get authority records count.
        res_arcount = header[6]         # Get additional records count.
        return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
                res_ancount, res_nscount, res_arcount)
    return None


# Parse response to an object
def parse_response(data):
    try:
        if len(data) >= 12:
            header = parse_header(data)
            if not header:
                return None
            res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
                res_ancount, res_nscount, res_arcount = header

            qds = []
            ans = []
            offset = 12
            for i in range(0, res_qdcount):
                l, r = parse_record(data, offset, True)
                offset += l
                if r:
                    qds.append(r)
            for i in range(0, res_ancount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ans.append(r)
            for i in range(0, res_nscount):
                l, r = parse_record(data, offset)
                offset += l
            for i in range(0, res_arcount):
                l, r = parse_record(data, offset)
                offset += l
            response = DNSResponse()
            if qds:
                response.hostname = qds[0][0]
            for an in qds:
                response.questions.append((an[1], an[2], an[3]))
            for an in ans:
                response.answers.append((an[1], an[2], an[3]))
            return response
    except Exception as e:
        import traceback
        traceback.print_exc()
        logging.error(e)
        return None


# If all part of hostname (split by dot) match the regexp VALID_HOSTNAME, return True.
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


# DNS response object.
class DNSResponse(object):
    def __init__(self):
        self.hostname = None
        self.questions = []  # each: (addr, type, class)
        self.answers = []  # each: (addr, type, class)

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


STATUS_IPV4 = 0
STATUS_IPV6 = 1


class DNSResolver(object):

    def __init__(self):
        self._loop = None
        self._hosts = {}                                # Item parse from /etc/hosts
        self._hostname_status = {}                      # Dict <str hostname, int (STATUS_IPV4|STATUS_IPV6)>
        self._hostname_to_cb = {}                       # Dict <str hostname, list<function callback>>
        self._cb_to_hostname = {}                       # Dict <function callback, str hostname>
        self._cache = lru_cache.LRUCache(timeout=300)   # Cache
        self._last_time = time.time()
        self._sock = None                               # UDP Socket
        self._servers = None                            # nameserver list
        self._parse_resolv()
        self._parse_hosts()
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    # Parse nameserver in /etc/resolv.conf to self._servers
    # If no nameserver in /etc/resolv.conf, use ['8.8.4.4', '8.8.8.8'] instead
    def _parse_resolv(self):
        self._servers = []
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                content = f.readlines()
                for line in content:
                    line = line.strip()
                    if line:
                        if line.startswith(b'nameserver'):
                            parts = line.split()
                            if len(parts) >= 2:
                                server = parts[1]
                                if common.is_ip(server) == socket.AF_INET:
                                    if type(server) != str:
                                        server = server.decode('utf8')
                                    self._servers.append(server)
        except IOError:
            pass
        if not self._servers:
            self._servers = ['8.8.4.4', '8.8.8.8']

    # Parse all items in hosts (both windows and unix) to self._hosts
    # If no item in hosts, use {'localhost': '127.0.0.1'} fill self._hosts
    def _parse_hosts(self):
        etc_path = '/etc/hosts'
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if common.is_ip(ip):
                            for i in range(1, len(parts)):
                                hostname = parts[i]
                                if hostname:
                                    self._hosts[hostname] = ip
        except IOError:
            self._hosts['localhost'] = '127.0.0.1'

    # Add dns resolver to event loop
    def add_to_loop(self, loop, ref=False):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,       # UDP Socket
                                   socket.SOL_UDP)
        self._sock.setblocking(False)                                       # Non-blocking mode
        loop.add(self._sock, eventloop.POLL_IN)                             # Add socket to loop
        loop.add_handler(self.handle_events, ref=ref)                     	# Add self.handle_events to loop handler

    def _call_callback(self, hostname, ip, error=None):
        callbacks = self._hostname_to_cb.get(hostname, [])              # Get callback list by hostname, default to []
        for callback in callbacks:                                      # Traverse all callbacks
            if callback in self._cb_to_hostname:             			# If callback in callback -> hostname map
                del self._cb_to_hostname[callback]                      # delete it
            if ip or error:
                callback((hostname, ip), error)                         # call callback with hostname, ip and error
            else:                                                       # If no ip and no error
                callback((hostname, None),                              # call callback with hostname, None(IP)
                         Exception('unknown hostname %s' % hostname))   # and an exception about unknown hostname
        if hostname in self._hostname_to_cb:                 			# If hostname in hostname -> callback map
            del self._hostname_to_cb[hostname]                          # delete it
        if hostname in self._hostname_status:                           # If hostname in hostname -> status map
            del self._hostname_status[hostname]                         # delete it

    def _handle_data(self, data):
        response = parse_response(data)                                 # Parse data received from socket to response
        if response and response.hostname:
            hostname = response.hostname
            ip = None
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0]                                      # If response contains an answer, use it
                    break                                               # and stop find process
            if not ip and self._hostname_status.get(hostname, STATUS_IPV6) \
                    == STATUS_IPV4:                                     # If no IP queried on IPV4 query
                self._hostname_status[hostname] = STATUS_IPV6           # assuming it should be an AAAA query
                self._send_req(hostname, QTYPE_AAAA)                    # and query again
            else:
                if ip:
                    self._cache[hostname] = ip                          # Put query result to cache
                    self._call_callback(hostname, ip)                   # Call callback with hostname and ip
                elif self._hostname_status.get(hostname, None) == STATUS_IPV6:  # It is a IPv6 query and no IP queried
                    for question in response.questions:                 # Check if question is a IPv6 request
                        if question[1] == QTYPE_AAAA:                   # Under specific circumstances, _hostname_status
                                                                        # has been changed to STATUS_IPV6 but some
                                                                        # IPV4 query just returned, to prevent these
                                                                        # condition, we should check it's a IPV6 query
                            self._call_callback(hostname, None)         # End query and call callback will None result
                            break

    # Handle events returned by event loop
    def handle_events(self, events):
        for sock, fd, event in events:
            if sock != self._sock:                                              # Not my socket
                continue                                                        # pass to next event
            if event & eventloop.POLL_ERR:                                      # Socket error
                logging.error('dns socket err')
                self._loop.remove(self._sock)                                   # Remove socket from event loop
                self._sock.close()                                              # and close socket
                # TODO when dns server is IPv6
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,   # Recreate a UDP socket
                                           socket.SOL_UDP)
                self._sock.setblocking(False)                                   # set it to non-blocking
                self._loop.add(self._sock, eventloop.POLL_IN)                   # and add it back to event loop
            else:
                data, addr = sock.recvfrom(1024)                                # Receive data from socket
                if addr[0] not in self._servers:                                # if received packet from other server
                    logging.warn('received a packet other than our dns')
                    break                                                       # Break the handle process
                self._handle_data(data)                                         # Handle response
            break
        now = time.time()                                                       # What time is it now?
        if now - self._last_time > CACHE_SWEEP_INTERVAL:                        # If it's too old to keep in cache
            self._cache.sweep()                                                 # sweep it from cache
            self._last_time = now                                               # Set last sweep time to now

    # Remove callback from dns resolver
    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)                   # Check if callback has corresponding hostname
        if hostname:
            del self._cb_to_hostname[callback]                          # Delete callback -> hostname map
            arr = self._hostname_to_cb.get(hostname, None)              # Get callback list by using hostname
            if arr:
                arr.remove(callback)                                    # Remove callback from callback list
                if not arr:                                             # If callback list is empty after remove
                    del self._hostname_to_cb[hostname]                  # Delete the hostname -> empty list map
                    if hostname in self._hostname_status:               # If self._hostname_status contains hostname
                        del self._hostname_status[hostname]             # remove it

    # Send query request
    def _send_req(self, hostname, qtype):
        req = build_request(hostname, qtype)                    # Build request
        for server in self._servers:                            # Send request to each server in self._servers
            logging.debug('resolving %s with type %d using server %s',
                          hostname, qtype, server)
            self._sock.sendto(req, (server, 53))

    # Resolve hostname
    def resolve(self, hostname, callback):
        if type(hostname) != bytes:                             # Compatible with Python 3
            hostname = hostname.encode('utf8')                  # Convert to bytes
        if not hostname:                                        # Raise exception if hostname is empty
            callback(None, Exception('empty hostname'))
        elif common.is_ip(hostname):                            # Directly return if hostname is IP address
            callback((hostname, hostname), None)
        elif hostname in self._hosts:                           # Directly return if hostname in /etc/hosts
            logging.debug('hit hosts: %s', hostname)
            ip = self._hosts[hostname]
            callback((hostname, ip), None)
        elif hostname in self._cache:                           # Directly return if hostname hit cache
            logging.debug('hit cache: %s', hostname)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        else:                                                   # Send query to server
            if not is_valid_hostname(hostname):                 # Raise exception if hostname is not valid
                callback(None, Exception('invalid hostname: %s' % hostname))
                return
            arr = self._hostname_to_cb.get(hostname, None)      # Try to get callback list from map by hostname
            if not arr:                                         # If no hostname as key in map 'self._hostname_to_cb'
                self._hostname_status[hostname] = STATUS_IPV4   # IPv4 request
                self._send_req(hostname, QTYPE_A)               # Send query request now
                self._hostname_to_cb[hostname] = [callback]     # Add hostname -> callback mapping
                self._cb_to_hostname[callback] = hostname       # Add callback -> hostname mapping
            else:                                               # If hostname and callback list exist
                                                                # (Seems means request has been sent once or more)
                arr.append(callback)                            # Append this callback to callback list
                # TODO send again only if waited too long
                self._send_req(hostname, QTYPE_A)               # Send query request again

    # Close socket
    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None                                   # Release memory?


def test():
    dns_resolver = DNSResolver()
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop, ref=True)

    global counter
    counter = 0

    def make_callback():
        global counter

        def callback(result, error):
            global counter
            # TODO: what can we assert?
            print(result, error)
            counter += 1
            if counter == 9:
                loop.remove_handler(dns_resolver.handle_events)
                dns_resolver.close()
        a_callback = callback
        return a_callback

    assert(make_callback() != make_callback())

    dns_resolver.resolve(b'google.com', make_callback())
    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('example.com', make_callback())
    dns_resolver.resolve('ipv6.google.com', make_callback())
    dns_resolver.resolve('www.facebook.com', make_callback())
    dns_resolver.resolve('ns2.google.com', make_callback())
    dns_resolver.resolve('invalid.@!#$%^&$@.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())

    loop.run()


if __name__ == '__main__':
    test()
