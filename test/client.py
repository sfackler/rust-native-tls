import socket
import ssl
import sys

s = ssl.wrap_socket(socket.socket(socket.AF_INET),
                    ca_certs="root-ca.pem",
                    cert_reqs=ssl.CERT_REQUIRED)
s.connect(("localhost", int(sys.argv[1])))

s.sendall("hello")
buf = s.recv(1024)
if buf != "world":
    raise Exception("Saw {0}".format(buf))
