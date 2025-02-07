import datetime

from functools import wraps

from socketStreams import ShadowSocket
from debugIO import *

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from tlslite import TLSConnection
from tlslite import parsePEMKey
from tlslite import x509 as tlsliteX509
from tlslite import SessionCache
from tlslite import HandshakeSettings
from tlslite.utils.codec import Parser
from tlslite.messages import ClientHello
from tlslite.x509certchain import X509CertChain

from tlslite.extensions import *

getServerCert = lambda sock : bytes(sock.sock.session.serverCertChain.x509List[0].writeBytes())
getCert       = lambda cert : bytes(cert.writeBytes())
parseCert     = lambda cert : x509.load_der_x509_certificate(cert)
loadCert      = lambda certStr : tlsliteX509.X509().parse(certStr)
loadCertChain = lambda cert : X509CertChain([cert]) if type(cert) != list else X509CertChain(cert)
loadKey       = lambda keyStr : parsePEMKey(keyStr, private=True)
loadAlpn      = lambda alpn: list(map(lambda x: bytes(x), alpn.protocol_names))

def loadKeyFile(fpath):
    with open(fpath, "r") as f:
        return loadKey(f.read())

def loadCertFile(fpath):
    with open(fpath, "r") as f:
        return loadCert(f.read())

def getTLSExt(clientHello, extension):
    for ext in clientHello.extensions:
        if isinstance(ext, extension):
            return ext

# informal interface for tlsintercept
# to return so the server can
# execute a mitm. Also aleviates 
# issues with SSL/TLS backends. 

# I know OOP concepts may come
# as a challenge to the average
# python developer, but I can't
# think of a better way to do it.

class TLSContext:

    # "_" functions are not included in the interface.

    def __init__(self, ca, privateKey, reqCert=False):
        self.ca = ca
        self.sessionCache = SessionCache()
        self.privateKey = privateKey
        self.reqCert = reqCert

    def _wrap(self, sock):
        sock.sock = ShadowSocket(sock.sock, data=sock.read())
        sock.sock = TLSConnection(sock.sock)
        sock.flush()

    def serverWrap(self, sock):
        self._wrap(sock)
        certChain = loadCertChain([loadCert(forgeX509Certificate(self.cert, getCert(self.ca), self.privateKey)), self.ca])
        sock.sock.handshakeServer(certChain=certChain,
                                  privateKey=loadKey(str(self.privateKey, "ascii")),
                                  reqCert=self.reqCert,
                                  alpn = self.alpn
                                 )
        return sock

    def clientWrap(self, sock, clientHello):
        
        # print(clientHello.extensions)
        # print(sock.getpeername())
        self.alpn = loadAlpn(getTLSExt(clientHello, ALPNExtension))
        hostname = str(clientHello.server_name, "ascii")

        self._wrap(sock)
        sock.sock.handshakeClientCert(serverName=hostname, alpn=self.alpn)
        self.cert = getServerCert(sock)
        return sock

def getSan(cert): 
    san_extension = None
    for extension in cert.extensions:
        if isinstance(extension.value, x509.SubjectAlternativeName):
            san_extension = extension.value
            break
    
    return san_extension

# create signed ssl cert.

def forgeX509Certificate(Cert, Ca, Key, password=None):

    ca   = parseCert(Ca) 
    cert = parseCert(Cert)

    # get private key
    key = serialization.load_pem_private_key(Key, 
                                             password=password, 
                                             backend=default_backend()
                                            )
    
    commonName = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

    san = getSan(cert)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, commonName)])

    issuer = ca.subject
    serialNumber = x509.random_serial_number()

    cert = x509.CertificateBuilder()
    cert = cert.subject_name(subject)
    cert = cert.issuer_name(issuer)
    cert = cert.public_key(ca.public_key())
    cert = cert.serial_number(serialNumber)
    cert = cert.not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    cert = cert.not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    cert = cert.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    cert = cert.add_extension(san, critical=False)
    cert = cert.sign(key, hashes.SHA256())

    return str(cert.public_bytes(serialization.Encoding.PEM), "ascii")

CLIENT_HELLO = 0x01
CONTENT_TYPE_HANDSHAKE = 0x16

def captureHandshake(tunnel, hook=None):
    
    # sanity check

    if tunnel.TLSStream: 
        return None

    # steps for TLS mitm
    # 1: figure out if packet is a "client hello"
    #
    # 2: 
    #    2.1: parse first 6 bytes to get tls info
    #    2.2: pass the rest to the tlslite ClientHello
    #         parser.
    #
    # 3: get sni-hostname.
    #
    # 4: use sni-hostname to spoof client handshake
    #    to server.
    #
    # 5: get server certificate SAN and common 
    #    name.
    #
    # 6: forge cert with values gathered
    #    from steps 4-5.
    #
    # 7: do_handshake with client as server.
    #
    # 8: break TLS
    #
    # 9: adjust the tunnel streams as needed
    #
    # for this to work we obviously need a valid sslContext for
    # the client and (if we have client certs) the server.

    # also according to wireshark the handshake type
    # is part of the handshake protocol, but we are
    # reading it here because that's how tlslite does
    # it.

    recordLayer = tunnel.CLIENT_CONNECTION.recv(6)
    
    # not a tls handshake
    if len(recordLayer) != 6: 
        tunnel.CLIENT_CONNECTION.rewind()
        # DbgOut("not tls ")
        return None

    isHello = recordLayer[0] == CONTENT_TYPE_HANDSHAKE and recordLayer[5] == CLIENT_HELLO
    if isHello:
        try:
            handshakeLen = int.from_bytes(recordLayer[3:5], "big") 
            handshake = tunnel.CLIENT_CONNECTION.recv(handshakeLen - 1)
            
            p = Parser(bytearray(handshake))
            clientHello = ClientHello()
            clientHello.parse(p)
 
        except Exception as e:
            DbgError("error parsing client hello")
            tunnel.CLIENT_CONNECTION.rewind()
            return None
       
        commonName = str(clientHello.server_name, "ascii")
        
        try:
            if not hook:
                ca = tunnel.server.ca
                privKey = tunnel.server.key
                context = TLSContext(ca, privKey)

                # "client" and "server" are inverted
                # since we need to impersonate the opposite
                # from our respective sockets.

                tunnel.SERVER_CONNECTION = context.clientWrap(tunnel.SERVER_CONNECTION, clientHello)

                tunnel.CLIENT_CONNECTION.rewind()
                tunnel.CLIENT_CONNECTION = context.serverWrap(tunnel.CLIENT_CONNECTION)

                DbgOut(Fore.MAGENTA + "forged server handshake to " + Fore.GREEN + commonName + Fore.WHITE)
                tunnel.TLSStream = True
                return None
            
            else:
                hook(tunnel, clientHello)
                tunnel.TLSStream = True


        except Exception as e:
            DbgError("error forging handshake to " + commonName)
            return None
    
    tunnel.CLIENT_CONNECTION.rewind()
    return None 

def tlsIntercept(func):
    @wraps(func)
    def wrapper(tunnel):
        captureHandshake(tunnel, hook=func) 
    return wrapper
