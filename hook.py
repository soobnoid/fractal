#!/usr/bin/python3

import fractal

args = fractal.getArgs()

server = fractal.Socks5Server(args)

@server.registerCommand(fractal.SOCKS5.COMMANDS.CONNECT)
def connect(self, addr, ATYP, dest_addr, dest_port):
    print("hook")
    return fractal.connect(self, addr, ATYP, dest_addr, dest_port)

@server.registerCommand(fractal.SOCKS5.COMMANDS.BIND)
def bind(self, addr, ATYP, dest_addr, dest_port):
    print("hook")
    return fractal.bind(self, addr, ATYP, dest_addr, dest_port)

server.run()
