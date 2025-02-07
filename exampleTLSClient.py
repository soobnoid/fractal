#!/usr/bin/python3

import socket
import time
from fractal import SOCKS5
from fractal import domainNameToBytes 
from fractal import SocketStream # to test
                                 # TLS/SSL compatability

from debugIO import *

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from tlslite import HandshakeSettings
from tlslite import TLSConnection
from tlslite import parsePEMKey
from tlslite import x509 as tlsliteX509
from tlslite.x509certchain import X509CertChain
from tlslite.checker import Checker as certChecker

from fractalTLS import *

req_body = b'GET / HTTP/1.1\r\nHost: foo.com\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n\r\n\r\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 1080))
s = SocketStream(s)
s.send(SOCKS5.handShakeMsg([SOCKS5.METHODS.SSL]))

msg = s.recv(2)
print(msg)

if msg[0] != SOCKS5.VER and msg[1] != SOCKS5.METHODS.SSL:
    DbgOut("server does not support SSL/TLS authentication, closing...")
    s.close()

else:
    

    clientCertChain = loadCertChain(loadCertFile("certs/testClient.crt"))
    clientCertKey   = loadKeyFile("certs/testClient.key")
    caCert          = loadCertChain(loadCertFile("certs/fractal.crt"))

    handshakeSettings = HandshakeSettings()
    tlsConnection = TLSConnection(s)
        
    # validator = certChecker([caCert.getFingerprint()])

    tlsConnection.handshakeClientCert(clientCertChain,
                                      clientCertKey,
                                      settings=handshakeSettings 
                                     )
   
    serverCertBytes = bytes(tlsConnection.session.serverCertChain.x509List[0].writeBytes())
    server_cert = x509.load_der_x509_certificate(serverCertBytes, default_backend())

    tlsConnection.send(SOCKS5.command(SOCKS5.COMMANDS.CONNECT,
                          SOCKS5.ADDRESS_TYPES.DOMAINNAME,
                          domainNameToBytes("foo.com"),
                          80           
                         )
           )
   
    msg = tlsConnection.recv(4096)
    if msg[1] != 0x00: DbgError("connection failed")
    else: tlsConnection.send(req_body)
    start_time = time.time()
    print(tlsConnection.recv(8192))

    end_time = time.time()

    # Calculate the elapsed time
    elapsed_time = end_time - start_time

    print(f"Elapsed time: {elapsed_time:.6f} seconds")

