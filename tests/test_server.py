# Echo server program
import socket
import sys

HOST = None			   # Symbolic name meaning all available interfaces
PORT = 50007			  # Arbitrary non-privileged port
s=socket.socket()
s.bind(("localhost",PORT))
s.listen(1)
"""
#TEST-CODE
import threading,runpy
threading.Thread(target=lambda: runpy.run_path("./client.py",run_name="__main__")).start()
"""

print "waiting for request..."
conn, addr = s.accept()
print "got connection from: "+str(addr)
while 1:
	print "waiting for data..."
	data = conn.recv(1024)
	print "got data: "+str(data)
	if not data:
		print "data empty, closing..."
		break
	print "sending..."
	conn.send(data.upper())
	print "sent."
conn.close()
print "closed."

raise Exception, "End"
