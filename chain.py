#!/usr/bin/python3

from debugIO import *
from colorama import Fore
from fractal import Socks5Tunnel
from fractal import SOCKS5
import fractal
import random
import socket

if __name__ == "__main__":
    args = fractal.getArgs()
    server = fractal.Socks5Server(args)


class Socks5Peer:
    
    # information to connect and
    # information to authenticate

    ATYP=None
    remoteAddr=None
    authFunc=None
    authObj=None # whatever information needed
                 # to authenticate the server

    def __init__(self, remoteAddr, ATYP=SOCKS5.ADDRESS_TYPES.IPV4, authFunc=None, authObj=None):
        self.ATYP=ATYP
        self.remoteAddr=remoteAddr
        self.authFunc=authFunc
        self.authObj=authObj

    def auth(self, conn): 

        if not self.authFunc:  
            conn.send(bytes([0x05, 0x01, 0x00]))
            data = conn.recv(2)
            # print(fmtHex(data))
            if data[0] == 0x05 and data[1] == 0x00:
                return conn 
            
            return False

        else: return self.authFunc(self, conn, authObj)

# some random public proxy servers I found
# Servers = [("98.162.25.7", 31653), ("184.178.172.23", 4145), ("192.252.220.89", 4145)]

# test with independant fractal instances

Servers = [("127.0.0.1", 5050), ("127.0.0.1", 6060), ("127.0.0.1", 7070)]
Servers = [Socks5Peer(addr) for addr in Servers]

def chain(self, cmd_con, bindInfo, serverPool, cmd, shuffle=False, cut=None):

    ATYP, dest_addr, dest_port = bindInfo 
    servers = serverPool.copy()

    if shuffle: random.shuffle(servers)
    if cut: servers = servers[0:cut]

    serverChain = [str(server.remoteAddr) + "->" for server in servers]
    serverChain = "".join(serverChain)
    
    hostAddr = str(cmd_con.getpeername())
    peerAddr = "('" + self.addressInfo[ATYP].fromBytes(dest_addr) + "', " + str(int.from_bytes(dest_port, "big")) + ")"
    DbgOut(hostAddr + "->" + Fore.CYAN + serverChain + Fore.WHITE + peerAddr)
    serverChain = hostAddr + "->" + serverChain + peerAddr 

    server = servers.pop(0)

    # the client/server must
    # connect to the first
    # proxy manually

    sock = socket.socket(self.addressInfo[server.ATYP].family, socket.SOCK_STREAM)
    
    try: sock.connect(server.remoteAddr)
    except Exception as e:
        DbgError("could not form chain")
        return self.closeConnection(addr, error=SOCKS5.REPLIES.HOST_UNREACHABLE)

    sock = server.auth(sock)
    if not sock: 
        DbgError("could not form chain")
        self.closeConnection(addr, error=SOCKS5.REPLIES.HOST_UNREACHABLE)
        return None

    chainCmd = SOCKS5.COMMANDS.CONNECT
    while servers:

        server = servers.pop(0)

        PEER_ATYP = server.ATYP
        ADDR = self.addressInfo[PEER_ATYP].toBytes(server.remoteAddr[0])
        PORT = server.remoteAddr[1]
        sock.send(SOCKS5.command(chainCmd, PEER_ATYP, ADDR, PORT))
        data = sock.recv(4096)

        if data[0] != SOCKS5.VER or data[1] != SOCKS5.REPLIES.SUCCEEDED:
            DbgError("unable to complete chain")
            self.closeConnection(addr, error=SOCKS5.REPLIES.HOST_UNREACHABLE)
            return None

        sock = server.auth(sock)
        if not sock: self.closeConnection(addr, error=SOCKS5.REPLIES.HOST_UNREACHABLE)

    sock.send(SOCKS5.command(cmd, ATYP, dest_addr, int.from_bytes(dest_port, "big")))
    data = sock.recv(4096)
    bindPort = int.from_bytes(data[-2:], "big")
    bindAddr = data[4:-2]

    cmd_con.send(SOCKS5.reply(SOCKS5.REPLIES.SUCCEEDED,
                               ATYP,
                               bindAddr,
                               bindPort
                              )   
                 ) 

    tunnel = Socks5Tunnel(self, sock, cmd_con, streamStr=serverChain)
    return tunnel


# example code.
         
if __name__ == "__main__":

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

    @server.registerCommand(SOCKS5.COMMANDS.BIND)
    def bind(self, addr, ATYP, dest_addr, dest_port):
        print("hook")
        return fractal.bind(self, addr, ATYP, dest_addr, dest_port)

    #@server.registerCommand(fractal.SOCKS5.COMMANDS.UDP_ASSOCIATE)

    server.run()
