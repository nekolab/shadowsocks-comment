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

# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import socket
import logging
import struct
import errno
import random

from shadowsocks import encrypt, eventloop, lru_cache, common
from shadowsocks.common import parse_header, pack_addr


BUF_SIZE = 65536                                                            # Bytes can be read at once


def client_key(a, b, c, d):                                                 # Convert connect tuple to key
    return '%s:%s:%s:%s' % (a, b, c, d)


class UDPRelay(object):
    def __init__(self, config, dns_resolver, is_local):
        self._config = config
        if is_local:                                                        # For local
            self._listen_addr = config['local_address']                     # listen local address
            self._listen_port = config['local_port']                        # on local port
            self._remote_addr = config['server']                            # set remote address to server address
            self._remote_port = config['server_port']                       # and remote port to server port
        else:                                                               # For remote
            self._listen_addr = config['server']                            # listen server address
            self._listen_port = config['server_port']                       # on server port
            self._remote_addr = None                                        # No remote for server since it needn't
            self._remote_port = None                                        # so dose remote port
        self._dns_resolver = dns_resolver                                   # set dns resolver
        self._password = config['password']                                 # load password
        self._method = config['method']                                     # set encryption method
        self._timeout = config['timeout']                                   # set connection timeout
        self._is_local = is_local                                           # is local here?
        self._cache = lru_cache.LRUCache(timeout=config['timeout'],         # Seems use LRUCache to hold and reuse link
                                         close_callback=self._close_client)
        self._client_fd_to_server_addr = \
            lru_cache.LRUCache(timeout=config['timeout'])                   # Client file description to server address?
                                                                            # Q: I think actually is fd to client info.
        self._eventloop = None
        self._closed = False
        self._last_time = time.time()
        self._sockets = set()                                               # Set of out link (c->s or s->web) sockets
        if 'forbidden_ip' in config:
            self._forbidden_iplist = config['forbidden_ip']                 # load forbidden ip list if it exists
        else:
            self._forbidden_iplist = None

        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,     # Get address info needed to create
                                   socket.SOCK_DGRAM, socket.SOL_UDP)           # a connection socket
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]                       # Use first element of addrs
        server_socket = socket.socket(af, socktype, proto)                  # Use family, socktype, proto create socket
        server_socket.bind((self._listen_addr, self._listen_port))          # Bind socket to specific address and port
        server_socket.setblocking(False)                                    # Non-blocking socket
        self._server_socket = server_socket                                 # _server_socket is listening socket

    def _get_a_server(self):                                                # Get/Choice a server and port from config
        server = self._config['server']
        server_port = self._config['server_port']                           # Maybe a list
        if type(server_port) == list:
            server_port = random.choice(server_port)
        logging.debug('chosen server: %s:%d', server, server_port)
        # TODO support multiple server IP
        return server, server_port

    def _close_client(self, client):
        if hasattr(client, 'close'):
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            client.close()
        else:
            # just an address
            pass

    # Handle server for both client and server.
    # On local, server maintains the connection from user to local shadowsocks
    #   user -> socks5 protocol -> shadowsocks local server -> shadowsocks protocol -> encrypted data -> remote
    # On remote, server maintains the connection from local shadowsocks to remote shadowsocks
    #   local -> encrypted data -> shadowsocks remote server -> shadowsocks protocol -> network
    def _handle_server(self):
        server = self._server_socket
        data, r_addr = server.recvfrom(BUF_SIZE)                            # Receive buffer size length content
        if not data:
            logging.debug('UDP handle_server: data is empty')
        if self._is_local:                                                  # On local client, server socket listen
            frag = common.ord(data[2])                                      # socks5 format request data from client
            if frag != 0:                                                   # data[2] FRAG means Current fragment number
                logging.warn('drop a message since frag is not 0')          # According to RFC1928, page 7, implement
                return                                                      # fragmentation is optional. If not impl,
            else:                                                           # must drop any datagram which frag isn't 0.
                data = data[3:]                                             # data without RSV and FRAG (ss format)
        else:                                                               # In server, socket listen link from client
            data = encrypt.encrypt_all(self._password, self._method, 0, data)
            # decrypt data
            if not data:
                logging.debug('UDP handle_server: data is empty after decrypt')
                return
        header_result = parse_header(data)                                  # Parse socks5 request header
        if header_result is None:
            return
        addrtype, dest_addr, dest_port, header_length = header_result

        if self._is_local:                                                  # If here is local client
            server_addr, server_port = self._get_a_server()                 # Get a server form config to connect
        else:                                                               # else if here is remote server
            server_addr, server_port = dest_addr, dest_port                 # Use socks destination to connect

        key = client_key(r_addr[0], r_addr[1], dest_addr, dest_port)        # Use sender&dest's (addr,port) generate key
        client = self._cache.get(key, None)                                 # Check if this connect is in cache
        if not client:                                                      # If socket not in cache (for reuse?)
            # TODO async getaddrinfo
            addrs = socket.getaddrinfo(server_addr, server_port, 0,         # get address info for connect use
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if addrs:
                af, socktype, proto, canonname, sa = addrs[0]
                if self._forbidden_iplist:
                    if common.to_str(sa[0]) in self._forbidden_iplist:      # sa[0] is a resolved address in ip format
                        logging.debug('IP %s is in forbidden list, drop' %
                                      common.to_str(sa[0]))
                        # drop
                        return
                client = socket.socket(af, socktype, proto)                 # create a connection
                client.setblocking(False)                                   # Non-blocking mode
                self._cache[key] = client                                   # use connect tuple as key to cache socket
                self._client_fd_to_server_addr[client.fileno()] = r_addr    # cache relay socket fd -> incoming addrinfo
            else:
                # drop
                return
            self._sockets.add(client.fileno())                              # Add connection fd to _sockets
            self._eventloop.add(client, eventloop.POLL_IN)                  # Add connection to event loop

        if self._is_local:                                                  # If here is local client
            data = encrypt.encrypt_all(self._password, self._method, 1, data)   # encrypt client -> server data
            if not data:
                return
        else:                                                               # or here is remote server
            data = data[header_length:]                                     # remove socks5 header, restore DATA
        if not data:
            return
        try:
            client.sendto(data, (server_addr, server_port))                 # Send data to remote or network
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            # EAGAIN: Try again
            # EINPROGRESS: Operation now in progress
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                logging.error(e)

    # Handle client for both client and server.
    # On local, client maintains the connection from local shadowsocks to remote shadowsocks
    #   remote -> encrypted data -> shadowsocks local client -> shadowsocks protocol -> socks5 protocol -> user
    # On remote, client maintains the connection from network to remote shadowsocks
    #   network -> shadowsocks remote client -> shadowsocks protocol -> encrypted data -> local
    def _handle_client(self, sock):
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return
        if not self._is_local:                                              # If here is remote client
            addrlen = len(r_addr[0])                                        # domain name length?
            if addrlen > 255:
                # drop
                return
            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data   # >H is big-endian unsigned short
            response = encrypt.encrypt_all(self._password, self._method, 1,     # encrypt data will be send to local
                                           data)
            if not response:
                return
        else:                                                               # If here is local client
            data = encrypt.encrypt_all(self._password, self._method, 0,     # decrypt data received from remote
                                       data)
            if not data:
                return
            header_result = parse_header(data)                              # parse shadowsocks header
            if header_result is None:                                       # Not a valid data
                return
            # addrtype, dest_addr, dest_port, header_length = header_result
            response = b'\x00\x00\x00' + data       # Add RSV(00) and FRAG(0) to header, convert shadowsocks to socks5
        client_addr = self._client_fd_to_server_addr.get(sock.fileno())     # find client address
        if client_addr:
            self._server_socket.sendto(response, client_addr)               # Send response to local or user
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def add_to_loop(self, loop):                                            # Add listing socket to event loop
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop
        loop.add_handler(self._handle_events)

        server_socket = self._server_socket
        self._eventloop.add(server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR)

    def _handle_events(self, events):
        for sock, fd, event in events:
            if sock == self._server_socket:                                 # Incoming link to listening socket
                if event & eventloop.POLL_ERR:
                    logging.error('UDP server_socket err')
                self._handle_server()                                       # So should handle by server
            elif sock and (fd in self._sockets):                            # It's a client socket
                if event & eventloop.POLL_ERR:
                    logging.error('UDP client_socket err')
                self._handle_client(sock)                                   # So should handle by client
        now = time.time()
        if now - self._last_time > 3:                                       # If time past 3 seconds to last sweep
            self._cache.sweep()                                             # Do some sweep, if socket is swept
            self._client_fd_to_server_addr.sweep()                          # connection will be closed
            self._last_time = now
        if self._closed:
            self._server_socket.close()                                     # Close listening socket
            for sock in self._sockets:                                      # Close each client socket
                sock.close()
            self._eventloop.remove_handler(self._handle_events)             # remove handler from event loop

    def close(self, next_tick=False):
        self._closed = True
        if not next_tick:
            self._server_socket.close()
