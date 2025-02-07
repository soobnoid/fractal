#!/usr/bin/python3

# arbitrary python objects to
# make socket I/O suck less.

class WrappedSocket:

    sock = None

    def __init__(self, sock):
        self.sock = sock

    def recv(self, ammount):
        return self.sock.recv(ammount)

    def send(self, msg):
        return self.sock.send(msg)

    def sendall(self, buf):
        return self.sock.sendall(buf)

    def close(self, *args, **kwargs):
        return self.sock.close(*args, **kwargs)

    def getsockname(self):
        return self.sock.getsockname()

    def getpeername(self):
        return self.sock.getpeername()

    def settimeout(self, value):
        return self.sock.settimeout(value)

    def gettimeout(self):
        return self.sock.gettimeout()

    def setsockopt(self, level, optname, value):
        return self._sock.setsockopt(level, optname, value)

    def shutdown(self, how):
        return self._sock.shutdown(how)


class SocketStream (WrappedSocket):

    chunkSize = None

    sock = None
    data = b''

    index = 0

    def __init__(self, sock, throughput=524288):
        self.sock = sock
        self.chunkSize = throughput

    def read(self, ammount=None):
        ammount = len(self.data) - self.index if not ammount else ammount
        ret = self.data[self.index:self.index + ammount]
        self.index += ammount
        return ret

    def recv(self, ammount):
        try:
            if self.index + ammount > len(self.data):
                self.data += self.sock.recv(self.chunkSize)
            res = self.data[self.index:self.index + ammount]
            self.index += ammount
            # print(res)
            return res
        except Exception as e:
            return b''

    def rewind(self): self.index = 0

    def flush(self):
        self.data = b''
        self.index = 0

# unbuffered socket
# that can also have
# arbitrary data prepended

class ShadowSocket (WrappedSocket):

    data = b''

    def __init__(self, sock, data=b''):
        self.sock = sock
        self.data = data

    def recv(self, ammount):
        if not self.data: 
            return self.sock.recv(ammount)
        
        # if the tlslite-ng devs can't
        # be bothered to recv the right
        # ammount neither can this class.

        else:
            ret = self.data[:ammount]
            self.data = self.data[ammount:]
            return ret

        # keeping this code comented
        # since it works with the tlslite-ng 
        # version on pip

        # else:
        #    res = self.data + self.sock.recv(ammount - len(self.data))
        #    self.data = b''
        #    return res
