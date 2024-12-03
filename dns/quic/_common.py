import copy
import functools
import socket
import struct
import time
from typing import Any, Optional
import aioquic.quic.configuration
import aioquic.quic.connection
import dns.inet
QUIC_MAX_DATAGRAM = 2048
MAX_SESSION_TICKETS = 8
SESSIONS_TO_DELETE = MAX_SESSION_TICKETS // 4

class UnexpectedEOF(Exception):
    pass

class Buffer:

    def __init__(self):
        self._buffer = b''
        self._seen_end = False

class BaseQuicStream:

    def __init__(self, connection, stream_id):
        self._connection = connection
        self._stream_id = stream_id
        self._buffer = Buffer()
        self._expecting = 0

class BaseQuicConnection:

    def __init__(self, connection, address, port, source=None, source_port=0, manager=None):
        self._done = False
        self._connection = connection
        self._address = address
        self._port = port
        self._closed = False
        self._manager = manager
        self._streams = {}
        self._af = dns.inet.af_for_address(address)
        self._peer = dns.inet.low_level_address_tuple((address, port))
        if source is None and source_port != 0:
            if self._af == socket.AF_INET:
                source = '0.0.0.0'
            elif self._af == socket.AF_INET6:
                source = '::'
            else:
                raise NotImplementedError
        if source:
            self._source = (source, source_port)
        else:
            self._source = None

class AsyncQuicConnection(BaseQuicConnection):
    pass

class BaseQuicManager:

    def __init__(self, conf, verify_mode, connection_factory, server_name=None):
        self._connections = {}
        self._connection_factory = connection_factory
        self._session_tickets = {}
        if conf is None:
            verify_path = None
            if isinstance(verify_mode, str):
                verify_path = verify_mode
                verify_mode = True
            conf = aioquic.quic.configuration.QuicConfiguration(alpn_protocols=['doq', 'doq-i03'], verify_mode=verify_mode, server_name=server_name)
            if verify_path is not None:
                conf.load_verify_locations(verify_path)
        self._conf = conf

class AsyncQuicManager(BaseQuicManager):
    pass
