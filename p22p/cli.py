"""P22P v0.4 command-line interface"""
import sys, argparse, os, anydbm

from twisted.internet import reactor, endpoints, defer, task

import p22p.common, p22p.server, p22p.client


def conndef(s):
    """utility function. converts a string to a dictionary containing connection data"""
    if s.count("-") != 2:
        raise ValueError(s)
    p, l, r = s.split("-")
    p, l, r = int(p), int(l), int(r)
    return {"pid": p, "from_port": l, "to_port": r}

def portlist(s):
    """utility function. converts a string to a list of ports"""
    while s.endswith(","):
        s = s[:-1]
    return [int(v) for v in s.split(",")]


@defer.inlineCallbacks
def client_connect_success(c, ns, cert=None):
    """called when the client connected"""
    if ns.verbose:
        print "Connected to server."
    yield c.wait_ready()
    if ns.ping:
        if ns.pinginterval is None:
            do_server_ping(c)
        else:
            loop = task.LoopingCall(lambda c=c: do_server_ping(c))
            loop.start(interval=ns.pinginterval)
    if ns.action == "create":
        try:
            cid = yield c.create_group(name=ns.group, password=ns.password, sco=ns.sco, cert=cert, compression=ns.comp)
        except p22p.common.JoinFailed as e:
            print "Could not create Group. Reason: {m}.".format(m=e.message)
            c.disconnect()
            reactor.stop()
        else:
            if ns.verbose:
                print "Group created. CID is: {c}.".format(c=cid)
    elif ns.action == "join":
        try:
            cid = yield c.join_group(name=ns.group, password=ns.password, cert=cert)
        except p22p.common.JoinFailed as e:
            print "Could not join Group. Reason: {m}.".format(m=e.message)
            c.disconnect()
            reactor.stop()
        else:
            if ns.verbose:
                print "Group joined. CID is: {c}. Relaying connections.".format(c=cid)
            for cd in ns.connections:
                c.relay_port_to(**cd)
            if ns.verbose:
                print "All connections are now being relayed."
    elif ns.action == "reserve":
        try:
            cert = yield c.reserve_group(name=ns.group, sco=ns.sco)
        except p22p.common.ReservationFailed as e:
            print "Could not reserve Group. Reason: {m}.".format(m=e.message)
            reactor.stop()
        else:
            cf = ("cert.json" if ns.cert is None else ns.cert)
            with open(cf, "w") as outf:
                outf.write(cert)
            print "Group reserved."
            c.disconnect()
            reactor.stop()
    elif ns.action == "extend":
        try:
            cert = yield c.extend_reservation(cert)
        except p22p.common.ReservationFailed as e:
            print "Could not extend reservation. Reason: {m}.".format(m=e.message)
            c.disconnect()
            reactor.stop()
        else:
            cf = ("cert.json" if ns.cert is None else ns.cert)
            with open(cf, "w") as outf:
                outf.write(cert)
            print "Group reserved."
            c.disconnect()
            reactor.stop()


def client_connect_fail(e):
    """called when the client could not connect"""
    print "Error: Cant connect to server! Failure: {e}".format(e=e)
    reactor.stop()


@defer.inlineCallbacks
def do_server_ping(c):
    """pings the server"""
    p = yield c.ping_server()
    print "Ping to server is {p}ms".format(p=p*1000)


def cli(argv=None):
    """processes some command line arguments"""
    if argv is None:
        argv = sys.argv
    if ("--help" in argv) or (len(argv) <= 1):
        if ("--help" not in argv) or (argv.index("--help") < 2):
            # show basic help
            print_basic_help(e=argv[0])
            return
        else:
            # otherwise, let --help be handled by the other functions
            pass
    if True:
        subcmd = argv.pop(1)
        argv = argv[1:]
        if subcmd.lower() == "gui":
            from p22p import client_gui
            client_gui.main()
            return
        elif subcmd.lower() == "server":
            import p22p.server
            parser = argparse.ArgumentParser(description="P22P Server")
            parser.add_argument("-d", "--dir", action="store", help="Directory to store reservation data in", default=os.getcwd(), dest="dir")
            parser.add_argument("-p", "--port", action="store", type=int, help="Port to listen on", default=p22p.common.DEFAULT_PORT, dest="port")
            parser.add_argument("-i", "--interface", action="store", help="Interface to listen on", default="0.0.0.0", dest="interface")
            parser.add_argument("-b", "--backlog", action="store", type=int, help="backlog for listening socket", default=3, dest="backlog")
            parser.add_argument("-q", "--quiet", action="store_false", dest="verbose", help="Do not print anything")
            parser.add_argument("--prefix", action="store", dest="prefix", help="prefix for reserved groups.", default="#")
            parser.add_argument("-l", "--lifetime", action="store", type=int, dest="lifetime", help="lifetime for reservations", default=p22p.server.DEFAULT_RESERVATION_LIFETIME)
            parser.add_argument("-n", "--noclear", action="store_false", dest="clear", help="Do not auto-remove old reservations from database")
            ns = parser.parse_args(argv)
            if ns.verbose:
                from twisted.python import log
                log.startLogging(sys.stdout)
            d = os.path.abspath(ns.dir)
            if not os.path.exists(d):
                os.makedirs(d)
            sp = os.path.join(d, "secret.bin")
            secret = p22p.server.load_secret(sp)
            db = anydbm.open(os.path.join(d, "reservations.dbm"), "c")
            f = p22p.server.P22PServerFactory(db=db, secret=secret, reserved_prefix=ns.prefix, reservation_lifetime=ns.lifetime, autoclear=ns.clear)
            reactor.listenTCP(port=ns.port, interface=ns.interface, factory=f, backlog=ns.backlog)
            reactor.run()
        elif subcmd.lower() == "client":
            import p22p.client
            parser = argparse.ArgumentParser(description="P22P Client")
            parser.add_argument("action", action="store", help="what to do", choices=("create", "join", "reserve", "extend"))
            parser.add_argument("group", action="store", help="name of group")
            parser.add_argument("password", action="store", help="password for the group")
            parser.add_argument("-s", "--server", action="store", help="which server to connect to", dest="host", default=p22p.common.DEFAULT_SERVER)
            parser.add_argument("-p", "--port", action="store", type=int, help="Port to listen on", default=p22p.common.DEFAULT_PORT, dest="port")
            parser.add_argument("-e", "--endpoint", action="store", help="twisted endpoint string to connect to", default=None, dest="ep")
            parser.add_argument("-q", "--quiet", action="store_false", dest="verbose", help="Do not print anything")
            parser.add_argument("-c", "--cert", action="store", dest="cert", help="certificate/key for group", default=None)
            parser.add_argument("-P", "--ping", action="store_true", dest="ping", help="ping the server")
            parser.add_argument("-i", "--interval", action="store", type=float, dest="pinginterval", help="time between pings (default: only ping once)", default=None)
            parser.add_argument("-S","--sco", action="store_true", dest="sco", help="when creating a group, restrict connections to the server")
            parser.add_argument("-C", "--compression", action="store", dest="comp", type=int, help="compression level to use", default=p22p.common.DEFAULT_COMPRESSION_LEVEL)
            parser.add_argument("-w", "--whitelist", action="store", dest="whitelist", help="comma-seperated list of ports to restrict connections from other clients to", type=portlist, default=None)
            parser.add_argument("connections", action="store", nargs="*", help="connections to open once joined (PID-LOCAL-TARGET)", type=conndef)
            ns = parser.parse_args(argv)
            if ns.verbose:
                from twisted.python import log
                log.startLogging(sys.stdout)
            if (ns.cert is not None) and (not os.path.exists(ns.cert)):
                if ns.action != "reserve":
                    print "Error: Certfile not found!"
                    sys.exit(1)
            if ns.cert:
                if ns.action != "reserve":
                    with open(ns.cert, "r") as fin:
                        cert = fin.read()
                else:
                    cert = None
            else:
                if ns.action == "extend":
                    print "Please specify a cert to extend."
                    sys.exit(1)
                cert = None
            if ns.ep:
                ep = endpoints.clientFromString(parser.ep)
            else:
                ep = endpoints.TCP4ClientEndpoint(reactor, ns.host, ns.port)
            p = p22p.client.P22PClientProtocol(whitelist=ns.whitelist)
            d = endpoints.connectProtocol(ep, p)
            d.addCallback(lambda c, ns=ns, cert=cert: client_connect_success(c, ns, cert=cert))
            d.addErrback(client_connect_fail)
            reactor.run()
        else:
            print "Unknown subcommand. Use '{e} --help' to view a list of available subcommands.".format(e=argv[0])
            sys.exit(1)


def print_basic_help(e):
    """prints basic help"""
    print "P22P v{v}".format(v=p22p.common.VERSION)
    print "Subcommands (Usage: {e} subcommand [args [args ...]]):".format(e=e)
    print "gui"
    print "server"
    print "client"


if __name__ == "__main__":
    cli(sys.argv)
