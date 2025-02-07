#!/usr/bin/python3

# see:
# https://stackoverflow.com/questions/4685217/parse-raw-http-headers

import fractal
from fractal import Socks5Tunnel
from debugIO import *

from colorama import Fore
from functools import wraps

from io import BytesIO
from http.server import BaseHTTPRequestHandler
from http.client import HTTPResponse as BaseHTTPResponseHandler # my fucking namespace

CRLF = b"\r\n"

def generateHTTPEntity(HTTPObject):
    data = b''
    contentLen = False

    for key, value in HTTPObject.headers.items():
        # see RFC 2616 sec 19.4.6
        if key.lower() != "transfer-encoding":
            data += f"{key}: {value}".encode() + CRLF

        if key.lower() == "content-length": contentLen = True

    data += CRLF

    # if present add request body
    if HTTPObject.body: data += HTTPObject.body
    if not contentLen: data += CRLF * 2

    return data


# fixing the python standard library

class HTTPRequest (BaseHTTPRequestHandler):
    
    def __init__(self, requestText):
        self.rfile = BytesIO(requestText)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
        
        self.body = self.rfile.read().rstrip(CRLF * 2) 
        # this is a dummy stream that ends at the message
        # boundary, so this call doesn't block the socket.

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

    # not gonna bother supporting trailers
    def toBytes(self):
        # generate byline 
        data = self.command.encode() + b' '
        data += self.path.encode() + b' ' 
        data += self.request_version.encode() + CRLF

        # add entity
        data += generateHTTPEntity(self)
        return data

# for whatever dumb reason the implementation of HTTPResponse
# and BaseHTTPRequestHandler are totally different, despite
# being the equivalent "parser" class for their respective 
# HTTP entities.

# this also means that the HTTPResponse object gets
# a "debuglevel" and HTTPRequest does not. 
# and meanwhile requests return internal error codes
# and responses throw exceptions... 

# also they represent HTTP protocol versions
# differently (hence versionMap)

versionMap = {10:"HTTP/1.0", 11:"HTTP/1.1"}

# ¯\_(ツ)_/¯

_UNKNOWN = 'UNKNOWN'

class HTTPResponse (BaseHTTPResponseHandler):

    # in spite of their differing implementaion
    # the boilerplate for both just boils down
    # to abstracting the bounded http bytes
    # as a file.

    def __init__(self, responseText, debuglevel=0):
        self.fp = BytesIO(responseText)
        self._method = None
        self.debuglevel = debuglevel

        self.headers = self.msg = None

        # (copy pasted from the original constructor)
        # from the Status-Line of the response
        self.version = _UNKNOWN # HTTP-Version
        self.status = _UNKNOWN  # Status-Code
        self.reason = _UNKNOWN  # Reason-Phrase

        self.chunked = _UNKNOWN         # is "chunked" being used?
        self.chunk_left = _UNKNOWN      # bytes left to read in current chunk
        self.length = _UNKNOWN          # number of bytes left in response
        self.will_close = _UNKNOWN      # conn will close at end of response
        # (end copy paste) 

        self.begin()
        self.body = self.fp.read().rstrip(CRLF * 2) 
        self.version = versionMap[self.version]

    def toBytes(self):
        data = self.version.encode() + b' '
        data += str(self.status).encode() + b' '
        data += self.reason.encode() + CRLF
        data += generateHTTPEntity(self)
        data += CRLF
        return data


def parseHTTPMessage(stream, messageType):
    try:
        data = stream.read()
        headerDelim = data.index(CRLF * 2)
        headers = data[:headerDelim].lower()
        parsed = False

        if b'content-length' in headers:
                    
            # offset by 15 to account for token
            # seperator
            
            # print("shug")

            index = headers.index(b"content-length")
            contentLen = headers[index + 15:] + CRLF
            index = contentLen.index(CRLF)
            contentLen = int(contentLen[:index])

            headerSize = len(headers)
            packetSize = headerSize + contentLen + 4

            if len(data) < packetSize:
                data += stream.recv(packetSize - len(data)) # get remaining bytes.

            parsed = True

        while not parsed and not data.endswith(CRLF * 2):
            data += stream.recv(stream.chunkSize)

        # parse chunked messages with body
        # starting in seperate packet.

        # if b'transfer-encoding' in headers:
        #    print("chunked")
        #    if len(data) == headerDelim + 4:
        #        while True:
        #            data += stream.recv(stream.chunkSize)
        #            if data.endswith(CRLF * 2): break
        #            print(data)
 
        # print("requestData", data)

        if messageType.lower() == "request":
            # DbgOut("parsing request")
            message = HTTPRequest(data)
            if message.error_code:
                DbgError("http protocol error")
                # DbgOut(request.error_message)
                stream.rewind()
                return None

        elif messageType.lower() == "response":
            # DbgOut("parsing response")
            try: message = HTTPResponse(data)
            except Exception as e:
                DbgError("http protocol error")
                # DbgOut(e.__class__.__name__)
                stream.rewind()
                return None
    
    except ConnectionResetError as e: 
        DbgOut("connection closed")
        raise e
    
    except Exception as e:
        # DbgError("http parser error, message is likely not HTTP")
        # print(data)
        stream.rewind()
        return None

    stream.flush()
    return message


# wrap to deserialize http entities
# and modify/read by hook.

def httpRequest(func): 
    @wraps(func)
    def wrapper(self, stream, direction):
        request = parseHTTPMessage(stream, "request")
        if request:
            # DbgOut(Fore.BLUE + self.streamStr + Fore.RED + " [" + fractal.streamName[direction] + "] " + Fore.WHITE + "intercepted http request")
            return func(self, direction, request)
        
        return None
    return wrapper

def httpResponse(func): 
    @wraps(func)
    def wrapper(self, stream, direction):
        response = parseHTTPMessage(stream, "response")
        if response:
            # DbgOut(Fore.BLUE + self.streamStr + Fore.MAGENTA + " [" + fractal.streamName[direction] + "] " + Fore.WHITE + "intercepted http response")
            return func(self, direction, response)
    
        return None
    return wrapper


if __name__ == "__main__":
    
    args = fractal.getArgs()
    server = fractal.Socks5Server(args)

    @server.registerIntercept(direction=Socks5Tunnel.UPSTREAM)
    @httpRequest
    def requestInfo(self, direction, request):    
        # DbgSuccess("http request details")
        DbgOut(Fore.BLUE + self.streamStr + Fore.RED + " [" + fractal.streamName[direction] + "] " + Fore.WHITE + 'intercepted http request\n    -> ' + request.command + ' ' + request.request_version + ' ' + request.path)
        # print(request.path)
        # print(request.request_version)
        # print(request.headers)
        # print(request.body)
        # print(request.toBytes())
        return request.toBytes()

    @server.registerIntercept(direction=Socks5Tunnel.DOWNSTREAM)
    @httpResponse
    def responseInfo(self, direction, response):
        # DbgSuccess("http response details")
        DbgOut(Fore.BLUE + self.streamStr + Fore.MAGENTA + " [" + fractal.streamName[direction] + "] " + Fore.WHITE + 'intercepted http response\n    <- ' + response.version + ' ' + str(response.status) + ' ' + response.reason)
        # print(response.status)
        # print(response.reason)
        # print(response.headers)
        # print(response.body)
        # print(response.toBytes())
        return response.toBytes()

    server.run()
