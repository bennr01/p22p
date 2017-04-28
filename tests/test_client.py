"""socket test"""
import socket,sys

if __name__=="__main__":
    host=sys.argv[1]
    port=int(sys.argv[2])
    msg=sys.argv[3]
    print "connecting..."
    s=socket.socket()
    s.connect((host,port))
    print "connected."
    print "sending..."
    s.send(msg)
    print "sent."
    print "receiving..."
    data=s.recv(2014)
    print "received: ",data
    print "sending empty string..."
    s.send("")
    print "closing connection..."
    s.close()
