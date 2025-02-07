#!/usr/bin/python3
#
# for best performance run with nogil using pyenv
#
# extendable implementation of SOCKS5 protocol
# 
# notes on SOCKS5:
#
# ref https://datatracker.ietf.org/doc/html/rfc1928
# https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
# 
# 
# handshake format (run curl --socks5 127.0.0.1:1010 foo.com and 
#                  rlwrap nc -nlvp 1010 | xxd to see)
#
# +----+----------+----------+
# |VER | NMETHODS | METHODS  |
# +----+----------+----------+
# | 1  |    1     | 1 to 255 |
# +----+----------+----------+
#
# handshake response format
# +----+--------+
# |VER | METHOD |
# +----+--------+
# | 1  |   1    |
# +----+--------+
#
# request format
# +----+-----+-------+------+----------+----------+
# |VER | CMD |  RSV  | ATYP | BND.ADDR | BND.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+
#
# response format
# +----+-----+-------+------+----------+----------+
# |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+
# 
# note:
#
# VER will always be 0x05
# RSV will always be 0x00.

from socketStreams import *
from debugIO import *

import random
from colorama import Fore
import threading
import argparse
import os
import socket
import json
import yaml
import sys

# we have to use tlslite to
# wrap sockets when forging
# handshakes, since we need
# to peek the sni-hostname
# and it's impossible to 
# rewind() the ssl socket
# after the initial "client hello"
# has been sent, which we can
# do with tlslite.

from tlslite import TLSConnection
from tlslite import SessionCache
from fractalTLS import *

if __name__ == "__main__":
    help_msg = """
Fractal is an extendable framework for defining custom behaviour for a SOCKS5
interface. You can use Fractal to script, manage, manipulate, forward, and chain
SOCKS5 connections, or as a standalone server. While the focus is on the tcp/udp 
level, a basic http interface is provided. 

fractal can function as a standalone SOCKS5 proxy, or simply present as a 
SOCKS5, or even extended SOCKS5 interface.

For more information on the SOCKS5 protocol see the following:
    https://datatracker.ietf.org/doc/html/rfc1928
    https://www.iana.org/assignments/socks-methods/socks-methods.xhtml

USAGE:

    fractal.py [-h]
    fractal.py [-c CONF_FILE.yml/json] [-s script.py] 
    fractal.py [-b/B address:port/INTERFACE] [-p PORT] [-m METHODS] 
               [-s script.py]

    NOTE: for any argument where multiple values can be supplied provide
    such values as a comma seperated list (ex: 1,2,3,4...).

    -c (--config):          path of configuration file. JSON and YAML
                            supported.

    -h (--help):            display this help message.

    -b (--bind-addr):       address to bind to (ex: 127.0.0.1:8080)
    
    -B (--bind-interface):  network interface to bind to (ex: wlan0)
    
    -p (--port):            port to listen on.

    -m (--methods):         list of SOCKS5 accepted authentication methods
                            should be listed by hex code (ex 0x01,0x02,0x6...)

    -C (--commands):        list of supported SOCKS5 commands.

    -a (--address-types):   list of accepted address types. all are enabled by
                            default.

    -s (--scripts):         path of (python) script(s) containing user defined 
                            behaviour for provided methods and commands. scripts
                            alter server functionality per user specification.
                            note that running scripts on top of each other is
                            possible (there are no technical limitations) each
                            will overwrite variables defined in the last. Could
                            this lead to unintended consuqueces? Certainly!
                            
                            see installation path for example scripts.

    -P (--pool):            a (json/yaml) file containing acceptable proxy
                            connections that the application can connect to.
                            TODO: specify format for pool

    -T (--capturetls):      forge certificates to upstream tls clients.

    -d (--debug):           enable verbose mode. 
"""

def IPV4FromBytes(BYTES): return str(BYTES[0]) + "."+ str(BYTES[1]) + "." + str(BYTES[2]) + "." + str(BYTES[3])

def IPV4ToBytes(addr): return(bytes([int(x) for x in addr.split(".")]))

def domainNameFromBytes(BYTES): return str(BYTES[1:], "ascii")

def domainNameToBytes(addr): return int.to_bytes(len(addr), 1) + bytes(addr, encoding='utf-8')

def IPV6FromBytes(BYTES):
    string = ""
    for byteIndex in range(8):
        string += hex(BYTES[byteIndex * 2])[2:].rjust(2,"0") + hex(BYTES[(byteIndex * 2) + 1])[2:].rjust(2,"0") + ":"
    return string[:-1]

def IPV6ToBytes(addr):
    BYTES = b''
    for part in addr.split(":"):
        BYTES += int(part, 16).to_bytes(2, "big")
    return BYTES
    
# for parsing arguments
def resolveHexArg (hexArr : str):
    if hexArr.lower() == "all": return [-1]
    return [int(index, 0) for index in hexArr.split(",")]

# to handle user specified support 
# and resolve implementation conflicts.
def resolveProxySupport (requestedFeatures, supportedFeatures):
    if requestedFeatures[0] == -1: return supportedFeatures

    for feature in requestedFeatures:
        if feature not in supportedFeatures: 
            DbgError("requested feature: " + hex(feature) + " unavailable")
            raise NotImplementedError

    for feature in supportedFeatures:
        if feature not in requestedFeatures: del supportedFeatures [feature]

    return supportedFeatures

# SOCKS5 protocol codes
class SOCKS5:

    def handShakeMsg(methods, ver=0x05):
        return bytes([ver, len(methods)] + methods)

    def udp_header(FRAG, ATYP, ADDR, PORT, DATA, RSV=0x00, byteOrder="big"):
        return bytes([RSV, RSV, FRAG, ATYP]) + ADDR + PORT.to_bytes(2, byteOrder) + DATA

    # command and reply assume ADDR has been correctly converted to bytes.
    # though PORT may be passed as an int. byteOrder only applies to PORT

    def command(CMD, ATYP, ADDR, PORT, ver=0x05, RSV=0x00, byteOrder="big"):
        return bytes([ver, CMD, RSV, ATYP]) + ADDR + PORT.to_bytes(2, byteOrder)
    
    # this method just puts the response together to be sent over
    # the connection. 

    def reply(REP, ATYP, ADDR, PORT, ver=0x05, RSV=0x00, byteOrder="big"): 
        return bytes([ver, REP, RSV, ATYP]) + ADDR + PORT.to_bytes(2, byteOrder)

    class METHODS:

        NOAUTH = 0x00
        GSSAPI = 0x01
        USERNAME_PASSWORD = 0x02
        CHAP = 0x03 # Challenge-Handshake Authentication Protocol
        CRAM = 0x05 # Challenge-Response Authentication Method
        SSL = 0x06
        NDS = 0x07
        MAF = 0x08 # Multi-Authentication Framework
        JPB = 0x09 # JSON Parameter Block"
        NOACCEPT = 0xFF

    class COMMANDS:
        
        CONNECT = 0x01
        BIND = 0x02
        UDP_ASSOCIATE = 0x03

    class ADDRESS_TYPES:
        
        IPV4 = 0x01
        DOMAINNAME = 0x03
        IPV6 = 0x04 

        LENGTHS = {
            IPV4:4,
            DOMAINNAME:None,
            IPV6:16
        }

    class REPLIES:
        
        SUCCEEDED = 0x00
        SOCKS_SERVERFAIL = 0x01
        RULESET_ERROR = 0x02
        NETWORK_UNREACHABLE = 0x03
        HOST_UNREACHABLE = 0x04
        CONNECTION_REFUSED = 0x05
        TTL_EXPIRED = 0x06
        COMMAND_UNSUPPORTED = 0x07
        ADDRESS_TYPE_UNSUPPORTED = 0x08

    VER = 0x05
    RSV = 0x00


class SOCKS5_DEBUG:

    METHODS = {
     0x00: "NO AUTHENTICATION REQUIRED", 
     0x01: "GSSAPI",
     0x02: "USERNAME/PASSWORD",
     # methods 0x03-0x7f are IANA reserved
     0x03: "Challenge-Handshake Authentication Protocol",
     0x05: "Challenge-Response Authentication Method",
     0x06: "Secure Socket Layer",
     0x07: "NDS Authentication",
     0x08: "Multi-Authentication Framework",
     0x09: "JSON Parameter Block",
     # methods 0x80-0xFE are reserved
     # for private use.
     0xFF: "NO ACCEPTABLE METHODS"
    }
    
    COMMANDS = {
     0x01: "CONNECT",
     0x02: "BIND",
     0x03: "UDP ASSOCIATE"
    }
    
    ADDRESS_TYPES = {
     0x01: "IP V4",
     0x03: "DOMAINNAME",
     0x04: "IP V6"
    }
    
    REPLIES = {
     0x00: "succeeded",
     0x01: "general SOCKS server failure",
     0x02: "connection not allowed in ruleset",
     0x03: "network unreachable",
     0x04: "host unreachable",
     0x05: "connection refused",
     0x06: "TTL expired",
     0x07: "command not supported",
     0x08: "address type not supported",
     # 0x09 to 0xff unassigned
    }
    
    VER = 0x05
    RSV = 0x00
    
# base socket wrapper
# that the server can
# use to manage binding
# sockets.

# sockets with blank bind
# addresses are "symbolic"
# and return true when compared
# with a preexisting socket
# with combatible settings.

class bindSocket:

    DEBUG = False

    connections = []

    FAMILY = socket.AF_INET
    TYPE = socket.SOCK_STREAM
    PROTO = 0
    FILENO = None 
    BIND_ADDR = None
    BIND_INTERFACE = None

    SOCK = None

    def __init__(self, bindInterface, bindAddr=None, family=None, type_=None, proto=None, fileNo=None, debug=False):
        
        self.DEBUG = debug

        if fileNo: self.FILENO = fileNo
        if proto: self.PROTO = proto
        if family: self.FAMILY = family
        if type_: self.TYPE = type_

        if bindInterface:
            if bindInterface.lower() == "any":
                self.BIND_INTERFACE = socket.INADDR_ANY 
                if bindAddr:
                    bindAddr[0] = ''

        if bindAddr: self.BIND_ADDR = bindAddr

    def createSock(self):

        self.SOCK = socket.socket(self.FAMILY, self.TYPE, self.PROTO, self.FILENO)
        
        if self.BIND_INTERFACE:
            self.SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.BIND_INTERFACE)

        self.BIND_ADDR = tuple(self.BIND_ADDR)
        self.SOCK.bind(self.BIND_ADDR)
        self.SOCK.listen()

    def __eq__(self, other):
        
        if not self.BIND_ADDR or not other.BIND_ADDR:
            return self.FAMILY == other.FAMILY and self.TYPE == other.TYPE

        return self.FAMILY == other.FAMILY and self.TYPE == other.TYPE and self.BIND_ADDR == other.BIND_ADDR


    def __contains__(self, key): return key in self.connections

    def isEmpty(self): return bool(self.connections)

    # TODO ensure that the packets are properly
    # authenticated per pre-specified handshake
    # rules.

    # addr is the address of the server that
    # will be connecting.

    def bind(self, server, addr): 

        if self.DEBUG: DbgOut("waiting to establish tunnel")
        cmd_conn = server.getConnection(addr)

        # this SHOULD be correct
        # and it avoids network
        # interface issues.

        bindAddr = (cmd_conn.getsockname()[0], self.SOCK.getsockname()[1])
        # print("BIND ADDR:", bindAddr)

        # pass tunnling info to the client

        cmd_conn.send(SOCKS5.reply(SOCKS5.REPLIES.SUCCEEDED, 
                                    address.ATYP, 
                                    address.toBytes(bindAddr[0]),
                                    bindAddr[1]
                                   )
                      )

        if self.DEBUG: DbgOut("waiting to establish tunnel")

        while True:
            conn, inc_addr = self.SOCK.accept()
            if inc_addr[0] == addr:
                self.connections += str(inc_addr)
                return conn
            conn.close()


streamName = {True:"upstream", False:"downstream"}

class Socks5Tunnel:

    DEBUG = False

    # the address the server binds to
    # and the address the server presents
    # to the client can be seperate

    # whatever code handles the command should
    # actually make the tunnel, and provides
    # the client-exposed socket
    #
    # the code that handles address resolution
    # creates the server side socket and passes
    # it to the command
    #
    # this class only handles the abstracted
    # connection objects.

    # a client may initiate a connection to
    # the server with a CONNECT command
    # and if the server endpoint needs
    # to initiate a secondary connection
    # to the client 

    # diagram:
    #  ____________       _______________________       ____________________
    # | client     |     |  server               |     | remote host        |
    # | port xxxxx |<--->| port 1080 (cmd port)  |---->| REMOTE SERVER_ADDR |
    # |____________|     | |-> SERVER_SOCK_ADDR  |<--->| REMOTE_BIND_ADDR   |
    #                    |_______________________|     |____________________|

    client_addr = (None, None)

    DEBUG = False
    server = None

    hooks = None
    CLIENT_CONNECTION = None
    SERVER_CONNECTION = None

    UPSTREAM   = True
    DOWNSTREAM = False
    EITHER     = None

    throughput = 524288

    def __init__(self, server, server_con, client_con, streamStr=None, debug=False):

        self.server = server
        self.TLSStream = False
        if debug: self.DEBUG = True
        self.SERVER_CONNECTION = server_con
        self.CLIENT_CONNECTION = client_con 

        self.hooks = server.intercepts
        if not streamStr:
            try: self.streamStr = str(client_con.getpeername()) + "->" + str(server_con.getpeername())
            except: pass

        else: self.streamStr = streamStr

    def forward(self, stream):
        
        upstream   = self.CLIENT_CONNECTION
        downstream = self.SERVER_CONNECTION
      
        if stream == self.DOWNSTREAM:
           
            downstream = self.CLIENT_CONNECTION
            upstream   = self.SERVER_CONNECTION
       
        # handshake capture may
        # have given us bytes
        # to read.

        data = b''
        if isinstance(upstream, SocketStream):
            data = upstream.read()
        
        while True:
    
            try:
                if self.hooks: 
                    # don't actually run hooks until we have data
                    if not data:
                        upstream.recv(self.throughput)
                        upstream.rewind()

                    if upstream.data:
                        for hookDirection, hook in self.hooks:        
                            if not hookDirection or hookDirection == stream:
                                data = hook(self, upstream, stream)
                                if data: break
                    
                        if not data:
                            data = upstream.read()
                            upstream.flush()

                else:
                    if not data:
                        data = upstream.recv(self.throughput)
                        if isinstance(upstream, SocketStream):
                            upstream.flush()

            except ConnectionResetError: 
                data = None

            if not data:
                if self.DEBUG:
                    DbgError(streamName[stream] + " tunnel closed")
                return None
            
            # print(downstream.getpeername(), data[0:2000], len(data))
            try:
                downstream.send(data)
                # print("sent")

            except Exception as e:
                return None
            
            data = b''

    def run(self):

        # we need buffered streams unless
        # we are acting as a transparent
        # stream.

        if self.hooks or self.server.tlsCapture:
            self.SERVER_CONNECTION = SocketStream(self.SERVER_CONNECTION, self.throughput)
            self.CLIENT_CONNECTION = SocketStream(self.CLIENT_CONNECTION, self.throughput)


        upstreamConnection = threading.Thread(target=self.forward, args=[self.UPSTREAM])
        downstreamConnection = threading.Thread(target=self.forward, args=[self.DOWNSTREAM])

        # we need to do this before tunneling 
        # it will not work as a standard hook

        if self.server.tlsCapture:
            if not self.server.tlsHook: captureHandshake(self)
            else: self.server.tlsHook(self)

        upstreamConnection.start()
        downstreamConnection.start()

        return bool(upstreamConnection.join()) & bool(downstreamConnection.join())


def resolveIPV4(self, client_addr, DST_ADDR, DST_PORT, udp):

    sock_type = socket.SOCK_STREAM

    if udp:
        sock_type = socket.SOCK_DGRAM

    sock = socket.socket(socket.AF_INET, sock_type)
    BIND_ADDR = (IPV4FromBytes(DST_ADDR), int.from_bytes(DST_PORT))
    return (BIND_ADDR, sock)

def resolveIPV6(self, client_addr, DST_ADDR, DST_PORT, udp):
    
    sock_type = socket.SOCK_STREAM

    if udp: sock_type = socket.SOCK_DGRAM

    sock = socket.socket(socket.AF_INET6, sock_type, 0)
    BIND_ADDR = (IPV6FromBytes(DST_ADDR), int.from_bytes(DST_PORT), 0, 0)
    return (BIND_ADDR, sock)

def resolveDomainName(self, client_addr, DST_ADDR, DST_PORT, udp):

    sock_type = socket.SOCK_STREAM
    if udp: sock_type = socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, sock_type)
    BIND_ADDR = (domainNameFromBytes(DST_ADDR), int.from_bytes(DST_PORT))
    return (BIND_ADDR, sock)


# wrapper interface for address types
# when passing one to the server you
# could just define your own object
# to replace this one.

# so it can function as a formal or
# informal interface

# also bypasses the bullshit where
# you can't define a method referencing
# "self" outside of a class

class AddressInfo:

    family = None

    addressLength = None
    DEBUG = False

    ATYP = None

    def resolve (self, client_addr, DST_ADDR, DST_PORT, udp): return self.functions["resolve"](self, client_addr, DST_ADDR, DST_PORT, udp)
    def toBytes (self, addr): return self.functions["toBytes"](addr)
    def fromBytes (self, addrBytes): return self.functions["fromBytes"](addrBytes)
    def createSock (self, addr): return self.functions["createSock"](addr)

    def __init__(self, atyp, addrlen, resolveFunc, fromBytesFunc, toBytesFunc, family, debug=False):
        self.functions = {}
        self.addressLength = addrlen
        self.functions["resolve"] = resolveFunc
        self.functions["toBytes"] = toBytesFunc
        self.functions["fromBytes"] = fromBytesFunc
        self.DEBUG = debug
        self.ATYP = atyp
        self.family = family

# must handle address resolution and return a
# tunnel

def connect(self, addr, ATYP, dest_addr, dest_port):

    remote_addr, sock = self.resolveAddress(addr, ATYP, dest_addr, dest_port)
    cmd_conn = self.getConnection(addr)

    streamStr = addr + "->" + str(remote_addr)
    DbgOut(Fore.BLUE + streamStr + Fore.WHITE)

    # sock.connect(remote_addr)
    try: sock.connect(remote_addr)     

    except OSError:
        DbgError("could not connect to  " + str(remote_addr))
        return self.closeConnection(addr, error=SOCKS5.REPLIES.HOST_UNREACHABLE)

    if self.DEBUG:
        DbgSuccess("connected to remote host")
        DbgOut("establishing tunnel")

    bindAddr = sock.getsockname()
    cmd_conn.send(SOCKS5.reply(SOCKS5.REPLIES.SUCCEEDED, 
                               ATYP, 
                               self.addressInfo[ATYP].toBytes(bindAddr[0]),
                               bindAddr[1]
                              )    
                 )  

    tunnel = Socks5Tunnel(self, sock, cmd_conn)
    tunnel.run()

    return self.closeConnection(addr)


def bind(self, addr, ATYP, dest_addr, dest_port):

    remote_addr, _ = self.resolveAddress(addr, ATYP, dest_addr, dest_port)
    cmd_conn = self.getConnection(addr)
    
    DbgOut(addr + "::" + str(remote_addr)) 
    server_conn = self.bind_socket(addr, ATYP, remote_addr[0])
    tunnel = Socks5Tunnel(self, server_conn, cmd_conn)
    tunnel.run()

    return self.closeConnection(addr)


def udp_associate(self, addr, ATYP, dest_addr, dest_port): pass

# return authenticated connection 

noauth = lambda self, addr : True

IPV4 = AddressInfo(SOCKS5.ADDRESS_TYPES.IPV4,
                  SOCKS5.ADDRESS_TYPES.LENGTHS[SOCKS5.ADDRESS_TYPES.IPV4],
                  resolveIPV4,
                  IPV4FromBytes,
                  IPV4ToBytes,
                  socket.AF_INET,
                  debug=True)

IPV6 = AddressInfo(SOCKS5.ADDRESS_TYPES.IPV6,
                  SOCKS5.ADDRESS_TYPES.LENGTHS[SOCKS5.ADDRESS_TYPES.IPV6],
                  resolveIPV6,
                  IPV6FromBytes,
                  IPV6ToBytes,
                  socket.AF_INET6,
                  debug=True)

DOMAINNAME = AddressInfo(SOCKS5.ADDRESS_TYPES.DOMAINNAME,
                        SOCKS5.ADDRESS_TYPES.LENGTHS[SOCKS5.ADDRESS_TYPES.DOMAINNAME],
                        resolveDomainName,
                        domainNameFromBytes,
                        domainNameToBytes,
                        socket.AF_INET,
                        debug=True)

# alternative way of invoking the program
# this is so the --script flag can reflectively
# create another instance from the command line.

def getArgs():

    # it does this by dumping a python dict as a string
    # and well...

    args = sys.argv[1].replace("'", '"')
    args = args.replace("True","true")
    args = args.replace("False", "false")
    return json.loads(args)

def sslAuth(self, addr):
    
    if True: # try:
        
        cmd_con = self.getConnection(addr)
        cmd_con = self.sslContext.serverWrap(cmd_con) 
        self.client_connections[addr]["connection"] = cmd_con
        return True
    
    # except Exception as e:
    #    return False

class Socks5Server:

    VER = SOCKS5.VER

    DEBUG = False
    
    client_connections = {}
    _bind_ports = list(range(50000, 60000))
    
    # the actual syscall args and
    # bind info.
    
    # while the protocol specifies that
    # servers can only listen on TCP
    # addresses, there is nothing 
    # stoping you from implementing
    # this

    class socketInfo:
        FAMILY = socket.AF_INET
        TYPE = socket.SOCK_STREAM
        PROTO = 0
        FILENO = None
        BIND_ADDR = (None, None)
        BIND_INTERFACE = None
   
    # sockets will be requested by being
    # placed into the queue and placed
    # back into server_sockets.

    # the server will handle authentication
    # and encapsulation of new
    # connections and then pass connection back
    # to the command API or default method.

    server_sockets = []

    # for use in the bind command

    def bind_socket(self, addr, ATYP, remoteAddr):

        socketInfo = bindSocket(self.socketInfo.BIND_INTERFACE, debug=self.DEBUG)
        cmd_con = self.getConnection(addr)
        found = False

        # if the server already has a useable
        # socket use that, otherwise create one.

        for sock in self.server_sockets:
            if addr not in sock and socketInfo == sock:
                found = True
                break

        if not found:
            socketInfo.BIND_ADDR = (self.socketInfo.BIND_ADDR[0], random.choice(self._bind_ports))
            sock = socketInfo
            sock.createSock()
            self.server_sockets.append(sock)

        # authenticate the incoming connection

        serverAddr = sock.SOCK.getsockname()

        cmd_conn.send(SOCKS5.reply(SOCKS5.REPLIES.SUCCEEDED,
                            ATYP,
                            self.addressInfo[ATYP].toBytes(serverAddr[0]),
                            serverAddr[1]
                            )
                     )

        return sock.bind(self, remoteAddr, addr)

    # events are essentially the servers signal system
    # each one should corespond with a function... arguments
    # are subject to the event in question. 

    # the server defines some of it's own events in the
    # init function, however the user can add more.

    events = {}


    # "method" as in "authentication method"

    method_functions = {SOCKS5.METHODS.NOAUTH:noauth,
                        SOCKS5.METHODS.SSL:sslAuth
                        }
    
    command_functions = {
            SOCKS5.COMMANDS.CONNECT:connect,
            SOCKS5.COMMANDS.BIND:bind
            }

    addressInfo = {
            SOCKS5.ADDRESS_TYPES.IPV4:IPV4,
            SOCKS5.ADDRESS_TYPES.IPV6:IPV6,
            SOCKS5.ADDRESS_TYPES.DOMAINNAME:DOMAINNAME
            }


    intercepts = []
    
    # the programmer can pass a collection of SOCKS5 peers
    # to the server with this variable.

    pool = None

    # these methods expose the "API" that allows the
    # programmer to modify 

    def registerIntercept(self, direction=None):
        def wrap(cmd):
            self.intercepts += [(direction, cmd)]
            return cmd
        return wrap 

    def registerHandshakeIntercept(self):
        def wrap(cmd):
            self.tlsHook = cmd
            return cmd
        return wrap

    def registerMethod(self, CODE) -> None:          
        def wrap(methodInfo):
            self.method_functions[CODE] = methodInfo
            return cmd
        return wrap

    def registerCommand(self, CODE) -> None:        
        def wrap(cmd):
            self.command_functions[CODE] = cmd
            return cmd
        return wrap 

    def registerAddressType(self, addrInfo):
        def wrap(cmd):
            self.addressInfo[addrInfo.ATYP] = addrInfo
            return cmd
        return wrap
    
    def registerEvent(self, EVENT) -> None:
        def wrap(eventHook):
            self.events[EVENT] = eventHook
            return eventHook
        return wrap

    def setConnectionStatus(self, addr, status): 
        self.client_connections[addr]["status"] = status    
        event = self.client_connections[addr]["status"]

        if event in self.events:        
            if self.DEBUG: DbgTip("triggered event: " + event)
            self.events[event](self, addr)
            
        else: DbgError("no handler defined for event")

        return None

    getConnectionStatus = lambda self, addr: self.client_connections[addr]["status"]

    def __init__(self, cmdArgs):        
        
        if(cmdArgs["capturetls"]): 
            self.tlsCapture = True
            with open("certs/tmp/ca.key", "rb") as key: 
                self.key = key.read() 
        
            self.ca = loadCertFile("certs/tmp/ca-cert.pem")
            self.tlsHook = None

        else: self.tlsCapture = False
            
        self.events["connected"] = Socks5Server.dispatchClientHandshake
        self.events["disconnected"] = Socks5Server.closeConnection
        self.events["needauth"] = Socks5Server.authenticateClient
        self.events["await-command"] = Socks5Server.commandLoop

        self.DEBUG = cmdArgs["debug"]

        if self.DEBUG: DbgOut("loading proxy configuration")

        bindingInterface = False

        if cmdArgs["bind_interface"].lower() == "any":
            self.socketInfo.BIND_INTERFACE = socket.INADDR_ANY
            bindingInterface = True

        elif cmdArgs["bind_interface"]:
            self.socketInfo.BIND_INTERFACE = cmdArgs["bind_interface"]
            bindingInterface = True

        if bindingInterface: self.socketInfo.BIND_ADDR = ("", int(cmdArgs["port"]))

        else: 
            self.socketInfo.BIND_ADDR = list(cmdArgs["bind_addr"].split(":"))
            self.socketInfo.BIND_ADDR[1] = int(self.socketInfo.BIND_ADDR[1])
            self.socketInfo.BIND_ADDR = list(self.socketInfo.BIND_ADDR)

        if self.DEBUG: DbgSuccess("loaded address configuration")

        try:
            DbgOut("checking auth methods") 
            # self.method_functions = resolveProxySupport(resolveHexArg(cmdArgs["methods"]), self.method_functions)
            DbgSuccess("success")
        
            DbgOut("checking commands")
            self.command_functions = resolveProxySupport(resolveHexArg(cmdArgs["commands"]), self.command_functions)
            DbgSuccess("success")
        
            DbgOut("checking address types")
            self.addressType_functions = resolveProxySupport(resolveHexArg(cmdArgs["address_types"]), self.addressType_functions)
            DbgSuccess("success")

        except: DbgError("one or more requested features have not been implemented")

        # any endpoints that the server needs
        # passed at runtime can be assigned here.`

        if cmdArgs["pool"]: self.pool = loadPool(cmdArgs["pool"])

    def resolveAddress(self, client_addr, ATYP, DST_ADDR, DST_PORT, udp=False):
        return self.addressInfo[ATYP].resolve(client_addr, DST_ADDR, DST_PORT, udp)

    # the server can explicitly terminate a connection
    # or request termination with this method. 

    # status "disconnected" calls this method
    # by default.

    # the error value is for server side errors that
    # must be relayed to the client. Though 
    # this argument is not needed for client errors
    # the server may then close the connection 
    # silently.

    def closeConnection(self, addr, addressType=None, error=None):
        
        # if the client disconnects you can close the server with no response
        # if the client sends a bad command or a host is unreachable
        # you can just specify a blank bind address.

        # if a open bind address has an error the server must specify
        # which to the command connection.
        
        if addr in self.client_connections: cmd_conn = self.getConnection(addr)
        else: return None

        if not error: cmd_conn.close()

        else:
            cmd_conn.send(SOCKS5.reply(error, SOCKS5.ADDRESS_TYPES.IPV4, b"\x00\x00\x00\x00", 0))
            cmd_conn.close()

        # if this hangs there is something seriously
        # wrong because if there is a need to close
        # the connection the thread should have returned
        
        if addr not in self.client_connections: return None

        try:
            if self.client_connections[addr]["thread"].is_alive():
                self.client_connections[addr]["thread"].join()
        
        except RuntimeError: pass

        if addr in self.client_connections: del self.client_connections[addr]
        return None
        
    # handling handshakes is deterministic
    # based on other aspects of the protocol
    # so it's handled statically here.

    getConnection = lambda self, addr: self.client_connections[addr]["connection"]

    getAuthMethod = lambda self, addr: self.client_connections[addr]["auth"]

    def dispatchClientHandshake (self, addr):
        
        conn = self.getConnection(addr)
        msg = conn.recv(257) # max a client can pass
        
        if msg: 
            if self.DEBUG:
                DbgSuccess("received handshake message " + Fore.CYAN + fmtHex(msg) + Fore.WHITE)
                DbgOut("client version: " + hex(msg[0]))
                DbgOut("client authentication method: " + hex(msg[1]))

        else: DbgError("did not reveieve auth information from client")

        if not msg:
            DbgError("client did not send handshake information")
            return self.setConnectionStatus(addr, "disconnected")

        if msg[0] != self.VER: 
            DbgError("version not supported by server")
            return self.closeConnection(addr)
        
        resp = [self.VER]
        METHOD_COUNT = msg[1]

        if METHOD_COUNT != len(msg[2:]):
            DbgError("malformed handshake request")
            return self.closeConnection(addr)

        if self.DEBUG:
            for METHOD_INDEX in range(METHOD_COUNT):
                clientMethod = msg[2 + METHOD_INDEX]
                try: DbgOut(hex(clientMethod) + ": " + SOCKS5_DEBUG.METHODS[clientMethod])
                except KeyError: DbgError(hex(clientMethod) + ": (unknown)")

        for METHOD_INDEX in range(METHOD_COUNT):
            
            clientMethod = msg[2 + METHOD_INDEX]
            if clientMethod in self.method_functions:
                resp += [clientMethod]
                self.client_connections[addr]["auth"] = clientMethod
                break

        if len(resp) == 1: 
            resp += [SOCKS5.METHODS.NOACCEPT]
            conn.send(bytes(resp))
            return self.closeConnection(addr)

        conn.send(bytes(resp))
        return self.setConnectionStatus(addr, "needauth")

    def commandLoop(self, addr):

        conn = self.getConnection(addr)
        clientMethod = self.getAuthMethod(addr)

        while True:
            try:
                msg = conn.recv(4096)
            except OSError:
                return self.closeConnection(addr)

            if msg:

                if self.DEBUG:
                    DbgOut(addr + " received command: " + Fore.CYAN + fmtHex(msg) + Fore.WHITE)

                try:
                    VER = msg[0]
                    if VER != self.VER:
                        DbgError("ERROR: client requested bad protocol version")
                        if self.DEBUG: DbgOut(addr + ":" + hex(VER))
                        return self.closeConnection(addr)
                    
                    if msg[2] != SOCKS5.RSV: 
                        DbgError(addr + ": ERROR malformed client request (RSV!=0)")
                        return self.closeConnection(addr, error=SOCKS5.REPLIES.RULESET_ERROR)

                    cmd = msg[1]

                    if cmd not in self.command_functions:
                        DbgError(addr + ": ERROR client requested unsupported command: " + Fore.CYAN + hex(cmd) + Fore.WHITE)
                        
                       if self.DEBUG:
                            if cmd in SOCKS5_DEBUG.COMMANDS:
                                DbgOut(addr + ": " + hex(cmd) + " " + SOCKS5_DEBUG.COMMANDS[cmd])
                            else: DbgError(addr + ": (unknown)")

                        return self.closeConnection(addr, error=SOCKS5.REPLIES.COMMAND_UNSUPPORTED)
                    
                    # address resolution part

                    ATYP = msg[3]

                    if self.DEBUG: DbgOut("address type: " + hex(ATYP))

                    if ATYP not in self.addressInfo:
                        DbgError(addr + ": client requested unsupported address type: ")
                        if ATYP in SOCKS5_DEBUG.ADDRESS_TYPES:
                            DbgError(SOCKS5_DEBUG.ADDRESS_TYPES[ATYP])
                        else: DbgError("(unknown address type)")

                        return self.closeConnection(addr, error=SOCKS5.REPLIES.ADDRESS_TYPE_UNSUPPORTED)

                    else: 
                        dest_port = msg[-2:]
                        ADDR_LEN = self.addressInfo[ATYP].addressLength
                        if ADDR_LEN == None: 
                            dest_addr = msg[4:5 + msg[4]] # to account for length octet

                        else: dest_addr = msg[4:4+ADDR_LEN]

                        if self.DEBUG:
                            DbgOut("DST.ADDR: " + fmtHex(dest_addr))
                            DbgOut("DST.PORT: " + fmtHex(dest_port))

                        remote_addr = self.resolveAddress(addr, ATYP, dest_addr, dest_port)[0]
                        # DbgOut(addr + "->" + str(remote_addr))

                        self.command_functions[cmd](self, addr, ATYP, dest_addr, dest_port)

                except IndexError:
                    DbgOut(addr + ": error parsing command")
                    return self.closeConnection(addr)

            else:
                DbgError("did not recieve command information from: " + addr)
                return self.closeConnection(addr)

    def authenticateClient(self, addr):
        clientMethod = self.getAuthMethod(addr)
        if clientMethod in self.method_functions:
            
            if self.DEBUG: DbgOut("authenticating client " + addr)
            if self.method_functions[clientMethod](self, addr):
                if self.DEBUG: DbgOut("client " + addr + " authenticated") 
                return self.setConnectionStatus(addr, "await-command")
        
            else:
                DbgError("client: " + addr + " failed to authenticate")
                self.closeConnection(addr)

        # THIS SHOULD NOT HAPPEN
        
        else: 
            DbgError("client method not supported, but passed negotiation... something is wrong.")
            raise NotImplementedError 

    # create the socket and run main tcp event loop
    def run (self): 
        
        # setup
        try:
            if self.DEBUG:
                DbgOut("starting server on: " + str(self.socketInfo.BIND_ADDR))
                DbgOut("creating socket")
                print("family=" + str(self.socketInfo.FAMILY))
                print("type=" + str(self.socketInfo.TYPE))
                print("proto=" + str(self.socketInfo.PROTO))
                print("fileno=" + str(self.socketInfo.FILENO))

            self.SOCK = socket.socket(self.socketInfo.FAMILY,
                                      self.socketInfo.TYPE,
                                      self.socketInfo.PROTO,
                                      self.socketInfo.FILENO)
       
            # self.SOCK.setblocking(False)

            if self.DEBUG: 
                DbgSuccess("created socket")
                DbgOut("binding socket: " + str(self.socketInfo.BIND_ADDR))
            
            if self.socketInfo.BIND_INTERFACE != None:
                DbgOut("binding to interface: " + str(self.socketInfo.BIND_INTERFACE))
                self.SOCK.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.socketInfo.BIND_INTERFACE)

            # bind_addr now becomes immutable
            self.socketInfo.BIND_ADDR = tuple(self.socketInfo.BIND_ADDR)
            self.SOCK.bind(self.socketInfo.BIND_ADDR)
            
            if(self.DEBUG): DbgSuccess("bound socket")
            
            self.SOCK.listen()
            if(self.DEBUG): DbgSuccess("server listening")

        except: 
            DbgError("failed to start server on:" + str(self.socketInfo.BIND_ADDR))
            return None
 
        # the main event loop
        try:
            while True:    
                conn, addr = self.SOCK.accept()

                addr = str(addr)

                if self.DEBUG:
                    DbgOut("connection from: " + addr + " on: " + str(self.socketInfo.BIND_ADDR))

                # this thread will immediatly dispatch new connections. by
                # manually invoking the first event.

                self.client_connections[addr] = {
                        "thread": threading.Thread(target=self.events["connected"], args=[self, addr]),
                        "connection": conn,
                        "status": "connected",
                        "tunnels": {},
                        "auth": SOCKS5.METHODS.NOACCEPT} # set as this value until
                                                         # handshake determined

                # print("STARTING THREAD")

                self.client_connections[addr]["thread"].start()

        except: DbgError("FATAL: a crash occured in the server main loop")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-c", "--conf", default="", type=str)
    parser.add_argument("-b", "--bind-addr", default='127.0.0.1:1080', type=str)
    parser.add_argument("-B", "--bind-interface", default='any', type=str)
    parser.add_argument("-m", "--methods", default="0x00", type=str)
    parser.add_argument("-p", "--port", default="1080", type=str)
    parser.add_argument("-C", "--commands", default="ALL", type=str)
    parser.add_argument("-n", "--no-default", action="store_false")
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-P", "--pool", default="", type=str)
    parser.add_argument("-s", "--script", default="", type=str)
    parser.add_argument("-a", "--address-types", default="0x01,0x03,0x04", type=str)
    parser.add_argument("-T", "--capturetls", action="store_true")

    args = parser.parse_args()

    if args.help: 
        print(help_msg)
        sys.exit()
    
    if args.conf:
        pass # parse yaml or json

    if args.script: sys.exit(os.system(os.path.abspath(args.script) + ' "' + str(vars(args)) + '"'))

    if True:  server = Socks5Server(vars(args))

    else: # except:
        DbgError("server creation failed")

    if args.script:
        sys.exit(os.system(os.path.abspath(args.script) + ' "' + str(vars(args)) + '"'))
    
    try: server.run(s thread will immediatly dispatch new connections. by
                    1193                 # manually invoking the first event.
                    )
    except KeyboardInterrupt: sys.exit()
