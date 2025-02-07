#!/usr/bin/python3
#
# port scan
# usage ./proxyheader.py [-m METHODS] -a ip:port

import argparse
from fractal import SOCKS5
from fractal import SOCKS5_DEBUG
from fractal import resolveHexArg
from debugIO import *
import socket
import sys

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("-m", "--methods", default="", type=str) 
    parser.add_argument("-a", "--address", default="", type=str)

    args = parser.parse_args()

    if args.methods: methods = resolveHexArg(args.methods)
    else: methods = list(range(255))  

    bindAddr=args.address.split(":")
    bindAddr[1] = int(bindAddr[1])
    bindAddr = tuple(bindAddr)

    while methods:

        try: 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(bindAddr)
        except:
            DbgError("cannot connect to addr")
            sys.exit()

        sock.send(SOCKS5.handShakeMsg(methods))
        data = sock.recv(2)

        if data[0] != 0x05: 
            DbgError("not SOCKS5 server")
            sys.exit()

        method = data[1]

        if method == 0xff: 
            DbgError("no more acceptable methods")
            sys.exit()

        else:

            methods.remove(method)
            
            if method in SOCKS5_DEBUG.METHODS:
                DbgOut(hex(method) + ":" + SOCKS5_DEBUG.METHODS[method])

            else: DbgError(hex(method) + ":(unknown)")
            sock.close() 
