import socket
import ssl
import sys

ctx = ssl.create_default_context(cafile = "root-ca.pem")
s = ctx.wrap_socket(socket.socket(socket.AF_INET),
                    server_hostname = "foobar.com")
s.connect(("localhost", int(sys.argv[1])))

s.sendall("hello")
buf = s.recv(1024)
if buf != "world":
    raise Exception("Saw {0}".format(buf))
