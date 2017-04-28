"""A ping test"""
import sys

from p22p import client, common
from twisted.internet import reactor, task
from twisted.python.util import println
from twisted.python import log
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol


log.startLogging(sys.stdout)


def gotProtocol(p):
    print "connected"
    loop = task.LoopingCall((lambda p=p: p.ping_server().addBoth(println)))
    print "starting loop"
    loop.start(interval=1)


point = TCP4ClientEndpoint(reactor, "localhost", common.DEFAULT_PORT)
d = connectProtocol(point, client.P22PClientProtocol())
d.addCallback(gotProtocol)

print "starting reactor..."
reactor.run()
print "\nreactor stopped."
