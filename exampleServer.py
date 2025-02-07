#!/usr/bin/python

import fractal
from httpIntercept import *
from chain import * 

args = fractal.getArgs()
server = fractal.Socks5Server(args)

Servers = [("127.0.0.1", 5050), ("127.0.0.1", 6060), ("127.0.0.1", 7070)]
Servers = [Socks5Peer(addr) for addr in Servers]

@server.registerIntercept(direction=Socks5Tunnel.UPSTREAM)
@httpRequest
def requestInfo(self, request):
    DbgSuccess("http request details")
    print(request.command)          # "GET"
    print(request.path)             # "/who/ken/trust.html"
    print(request.request_version)  # "HTTP/1.1"
    print(request.headers)
    print(request.body)
    print(request.toBytes())
    return request.toBytes()

@server.registerIntercept(direction=Socks5Tunnel.DOWNSTREAM)
@httpResponse
def responseInfo(self, response):
    DbgSuccess("http response details")
    print(response.version)
    print(response.status)
    print(response.reason)
    print(response.headers)
    print(response.body)
    return response.toBytes()

@server.registerCommand(SOCKS5.COMMANDS.CONNECT)
def connect(self, addr, ATYP, dest_addr, dest_port):

    cmd_conn = self.getConnection(addr)
    tunnel = chain(self,
                    cmd_conn,
                    (ATYP, dest_addr, dest_port),
                    Servers,
                    SOCKS5.COMMANDS.CONNECT,
                    shuffle=True,
                    cut=2
                   )

    tunnel.run()
    return self.closeConnection(addr)

server.run()

