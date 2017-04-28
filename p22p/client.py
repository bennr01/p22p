"""P22P v0.4 client"""
import json
import hashlib
import zlib
import random
import time
import struct

from twisted.protocols.basic import IntNStringReceiver
from twisted.internet import defer, reactor, endpoints, protocol

from p22p import common


# ===== Constants =====

STATE_QUIT = 0
STATE_VERSION = 1
STATE_MAIN = 2


# ===== utility functions =====

def hash_password(password):
    """hashes the password"""
    return hashlib.sha256(password).hexdigest()


# ===== Protocol =====

class P22PClientProtocol(IntNStringReceiver):
    """The client protocol for p22p"""
    structFormat = common.LENGTH_FORMAT
    prefixLength = common.LENGTH_FORMAT_LENGTH

    debug = False

    def __init__(self, whitelist=None):
        self.pswd = None
        self.cid = None
        self.whitelist = whitelist  # A whitelist indicating which ports are allowed to connect to. If None, all are allowed.
        self.state = STATE_VERSION
        self.compression = common.DEFAULT_COMPRESSION_LEVEL
        self.pings = {}  # ping_id -> (start, deferred)
        self.chid2p = {}  # (pid, from_port) ->  proto
        self.chid2d = {}  # (pid, from_port) -> deferred
        self.port2relay = {}  # port -> factory
        self.join_d = None
        self.reserve_d = None
        self.handshake_d = defer.Deferred()

    def wait_ready(self):
        """waits until the handshake is finished. returns None if the handshake is finished or a deferred which will be called with self once the handshake is finished."""
        return self.handshake_d

    def connectionMade(self):
        """called when the connection was establish"""
        self.send_version()

    def send_version(self):
        """sends the clients version to the server"""
        self.sendString(common.VERSION)

    def prepare_outgoing_data(self, data):
        """prepares the data for sending by compressing and encrypting it"""
        assert isinstance(data, str)
        assert self.pswd is not None
        if self.debug:
            print "sending data: ", repr(data)
        if self.compression > 0:
            data = zlib.compress(data, self.compression)
        if self.debug:
            print "sending compressed data: ", repr(data)
        data = common.encrypt(data, self.pswd)
        return data

    def prepare_received_data(self, data):
        """prepares received data for handling by decrypting and decompressing it"""
        assert isinstance(data, str)
        assert self.pswd is not None
        data = common.decrypt(data, self.pswd)
        if self.debug:
            print "got compressed data: ", repr(data)
        if self.compression > 0:
            data = zlib.decompress(data)
        if self.debug:
            print "got data: ", repr(data)
        return data

    def stringReceived(self, data):
        """called when a string was received"""
        if self.debug:
            print "got data: ", repr(data)
            
        if len(data) == 0:
            pass
        else:
            if self.state == STATE_QUIT:
                pass
            elif self.state == STATE_VERSION:
                if data == "\x01":
                    self.state = STATE_MAIN
                    t, self.handshake_d = self.handshake_d, None
                    t.callback(self)
                else:
                    self.state = STATE_QUIT
                    self.force_disconnect()
                    self.handshake_d.errback(common.ConnectionError("Version mismatch!"))
                    
            elif self.state == STATE_MAIN:
                idb, payload = data[0], data[1:]
                if idb == common.ID_SERVER_COMMAND:
                    data = json.loads(payload)
                    action = data.get("action", None)
                    if action == "PONG":
                        pingid = data.get("ping_id", "<None>")
                        if pingid in self.pings:
                            start, d = self.pings[pingid]
                            del self.pings[pingid]
                            t = time.time() - start
                            d.callback(t)
                    elif action == "SET_CID":
                        cid = data.get("cid", self.cid)
                        self.cid = cid
                    elif action == "DISCONNECT":
                        self.disconnect()
                    elif action == "JOINED":
                        self.cid = data.get("cid", 0)
                        self.compression = data.get("compression", common.DEFAULT_COMPRESSION_LEVEL)
                        if self.join_d is not None:
                            d, self.join_d = self.join_d, None
                            d.callback(self.cid)
                        else:
                            pass
                    elif action == "JOIN_FAIL" or action == "CREATE_FAIL":
                        errmsg = data.get("reason", "Reason unknown")
                        if self.join_d is not None:
                            d, self.join_d = self.join_d, None
                            d.errback(common.JoinFailed(errmsg))
                    elif (action == "RESERVE_SUCCESS") or (action == "EXTEND_SUCCESS"):
                        c = data.get("cert", None)
                        if self.reserve_d is not None:
                            d, self.reserve_d = self.reserve_d, None
                            d.callback(c)
                    elif (action == "RESERVE_FAIL") or (action == "EXTEND_FAIL"):
                        errmsg = data.get("reason", "Unknown Reason")
                        if self.reserve_d is not None:
                            d, self.reserve_d = self.reserve_d, None
                            d.errback(common.ReservationFailed(errmsg))
                    else:
                        if self.debug:
                            print "got unknown server command: ", action
                            
                else:
                    piddata, payload = payload[:common.CID_FORMAT_LENGTH], self.prepare_received_data(payload[common.CID_FORMAT_LENGTH:])
                    pid = struct.unpack(common.BYTEORDER + common.CID_FORMAT, piddata)[0]
                    if idb == common.ID_CLIENT_COMMAND:
                            info = json.loads(payload)
                            action = info.get("action", None)
                            if action == "RELAY":
                                to_port = info.get("to_port", None)
                                from_port = info.get("from_port", None)
                                if (to_port is None) or (from_port is None):
                                    return
                                if self.whitelist is not None:
                                    if to_port not in self.whitelist:
                                        self.send_client_command_to_peer(pid, {"action": "CONNECT_FAILED", "port": from_port})
                                        return
                                chid = (pid, from_port)
                                p = RelayConnectProtocol(self, chid, pid=pid, port=from_port)
                                self.chid2p[chid] = p
                                ep = endpoints.TCP4ClientEndpoint(reactor, host="localhost", port=to_port, timeout=5)
                                d = endpoints.connectProtocol(ep, p)
                                d.addCallback(p.notify_connect_success)
                                d.addErrback(p.notify_connect_failed)
                            elif action == "CONNECT_FAILED":
                                port = info.get("port", None)
                                chid = (self.cid, port)
                                p = self.chid2p.get(chid, None)
                                if p is not None:
                                    p.disconnect()
                                d = self.chid2d.get(chid, None)
                                if d is not None:
                                    del self.chid2d[chid]
                                    d.errback(common.ConnectionError("Peer could not connect!"))
                            elif action == "CONNECT_SUCCESS":
                                if self.debug:
                                    print "connected"
                                port = info.get("port", None)
                                chid = (self.cid, port)
                                p = self.chid2p.get(chid, None)
                                if p is not None:
                                    p.did_connect()
                                d = self.chid2d.get(chid, None)
                                if d is not None:
                                    del self.chid2d[chid]
                                    d.callback(p)
                            elif action == "CONNECTION_CLOSE":
                                port = info.get("port", None)
                                chid = (self.cid, port)
                                p = self.chid2p.get(chid, None)
                                if p is not None:
                                    p.disconnect()
                            else:
                                if self.debug:
                                    print "Got unknown command for a peer: ", action
                            
                            
                    elif idb in (common.ID_DATA_FROM_HOST, common.ID_DATA_FROM_CLIENT):
                        if self.debug:
                            print "got data for relaying..."
                        portdata, data = payload[:common.PORT_LENGTH], payload[common.PORT_LENGTH:]
                        port =  struct.unpack(common.BYTEORDER + common.PORT_FORMAT, portdata)[0]
                        if idb == common.ID_DATA_FROM_CLIENT:
                            chid = (pid, port)
                            if self.debug:
                                print "data is from client."
                        else:
                            chid = (self.cid, port)
                            if self.debug:
                                print "data is from host"
                        if chid not in self.chid2p:
                            if self.debug:
                                print "Received data for unknown channel"
                                print "Channel: ", chid
                                print "Channels: ", self.chid2p.keys()
                        else:
                            proto = self.chid2p[chid]
                            proto.send_data(data)
                    else:
                        if self.debug:
                            print "got data with unknown id byte: ", repr(idb)

    def send_server_command(self, data):
        """sends a command to the server"""
        assert isinstance(data, dict)
        if self.debug:
            print "sending server command: ", data
        dumped = json.dumps(data)
        msg = common.ID_SERVER_COMMAND + dumped
        self.sendString(msg)

    def send_client_command_to_peer(self, pid, data):
        """sends a command to a peer"""
        assert isinstance(pid, (int, long))
        assert isinstance(data, dict)
        if self.debug:
            print "sending command to peer: ", data
        dumped = json.dumps(data)
        msg = common.ID_CLIENT_COMMAND + struct.pack(common.BYTEORDER + common.CID_FORMAT, pid) + self.prepare_outgoing_data(dumped)
        self.sendString(msg)

    def send_data_to_peer(self, pid, chid, data):
        """sends data to the peer"""
        if self.debug:
            print "sending {n} bytes to peer...".format(n=len(data))
        port = chid[1]
        portdata = struct.pack(common.BYTEORDER + common.PORT_FORMAT, port)
        piddata = struct.pack(common.BYTEORDER + common.CID_FORMAT, pid)
        if pid == chid[0]:
            # target relays its connection to here, this is the host
            idb = common.ID_DATA_FROM_HOST
        else:
            # relaying peer is not this client
            idb = common.ID_DATA_FROM_CLIENT
        msg = idb + piddata + self.prepare_outgoing_data(portdata + data)
        self.sendString(msg)

    def ping_server(self):
        """pings the server. returns a deferred which will fire with the ping"""
        if self.debug:
            print "pinging server..."
        ping_id = self.new_ping_id()
        d = defer.Deferred()
        start = time.time()
        self.pings[ping_id] = (start, d)
        self.send_server_command({"action": "PING", "ping_id": ping_id})
        return d.addTimeout(10, reactor)

    def new_ping_id(self):
        """returns a UID for a ping"""
        while True:
            pid = str(random.randint(1, 9999999))
            if pid not in self.pings:
                return pid

    def send_open_command(self, chid, pid, from_port, to_port):
        """tells another client to open the port"""
        assert isinstance(pid, (int, long))
        assert isinstance(from_port, (int, long))
        assert isinstance(to_port, (int, long))
        d = defer.Deferred()
        self.chid2d[chid] =  d
        self.send_client_command_to_peer(pid, {"action": "RELAY", "from_port": from_port, "to_port": to_port})
        return d

    def force_disconnect(self):
        """disconnects from the server without sending a message to the server"""
        self.state = STATE_QUIT
        self.stop_all_relays()
        self.close_connections(send_message=False)
        self.transport.loseConnection()
        self.cid = None

    def disconnect(self):
        """disconnect from the server"""
        if self.state == STATE_MAIN:
            self.state = STATE_QUIT
            self.send_server_command({"action": "QUIT"})
            self.stop_all_relays()
            self.close_connections(send_message=True)
        self.transport.loseConnection()
        self.cid = None

    def close_connections(self, send_message=True):
        """closes all connections. If send_message, notify the peers."""
        chids = self.chid2p.keys()
        for chid in chids:
            if chid not in self.chid2p:
                continue
            self.close_channel(chid, send_message=send_message)

    def create_group(self, name, password, sco=False, cert=None, compression=common.DEFAULT_COMPRESSION_LEVEL):
        """
Creates a group and joins it. Returns a deferred which will be called with the CID or errbacked with the error message.
If sco, only connections between the creator of the group and other clients are allowed,
meaning that connections between other clients is prohibited.
If cert is given, it should be a string representing a key for a group reservation.
"""
        if self.join_d is not None:
            raise common.UsageError("Allready creating or joing a group!")
        self.pswd = password
        pswd_hash = hash_password(password)
        d = defer.Deferred()
        self.join_d = d
        self.send_server_command({"action": "CREATE", "name": name, "password": pswd_hash, "sco": sco, "cert": cert, "compression": compression})
        return d

    def join_group(self, name, password, cert=None):
        """
Joins a group. Returns a deferred which will be called with the CID or errbacked with the error message.
If cert is given, it should be a string representing a key for a group reservation, in which case you will get the CID 0.
"""
        if self.join_d is not None:
            raise common.UsageError("Allready creating or joing a group!")
        self.pswd = password
        pswd_hash = hash_password(password)
        d = defer.Deferred()
        self.join_d = d
        self.send_server_command({"action": "JOIN", "name": name, "password": pswd_hash})
        return d

    def leave_group(self):
        """leaves the current group."""
        if self.cid is None:
            raise common.UsageError("Not in a group!")
        self.cid = None
        if self.join_d is not None:
            self.join_d.cancel()
            self.join_d = None
        self.stop_all_relays()
        self.close_connections(send_message=True)
        self.send_server_command({"action": "LEAVE"})

    def reserve_group(self, name, sco=True):
        """reserves a group"""
        assert isinstance(name, str)
        if self.state != STATE_MAIN:
            return defer.fail(common.UsageError("Not connected / Handshake did not yet finished!"))
        if self.reserve_d is not None:
            return defer.fail(common.UsageError("Already reserving / extending!"))
        d = defer.Deferred()
        self.reserve_d = d
        self.send_server_command({"action": "RESERVE", "name": name, "sco": sco})
        return d

    def extend_reservation(self, cert):
        """extends a reservation"""
        assert isinstance(cert, str)
        if self.state != STATE_MAIN:
            return defer.fail(common.UsageError("Not connected / Handshake did not yet finished!"))
        if self.reserve_d is not None:
            return defer.fail(common.UsageError("Already reserving / extending!"))
        d = defer.Deferred()
        self.reserve_d = d
        self.send_server_command({"action": "EXTEND", "cert": cert})
        return d

    def get_relayed_ports(self):
        """return a list of ports on which relays are listening"""
        return self.port2relay.keys()

    def relay_port_to(self, from_port, pid, to_port):
        """listens on from_port and relays all incomming connections. Returns a deferred which fires with the result of the listening."""
        if self.cid is None:
            raise common.UsageError("Not in a group!")
        if pid == self.cid:
            raise common.UsageError("Can not relay data to self.")  # <-- realy, p22p v0.4 cant do this. both connections would share their chid, meaing on would be overwritten by the other.
        factory = RelayListenFactory(self, self.cid, pid, from_port, to_port)
        ep = endpoints.TCP4ServerEndpoint(reactor, port=from_port, backlog=50, interface="localhost")
        d = ep.listen(factory)
        d.addCallback(factory.did_bind)
        return d

    def get_relay(self, port):
        """returns the relay for port"""
        return self.port2relay.get(port, None)

    def stop_relaying(self, port):
        """stops relaying data from the port"""
        if port in self.port2relay:
            f = self.get_relay(port)
            f.stop()

    def stop_all_relays(self):
        """stops all relays"""
        for port in self.get_relayed_ports():
            self.stop_relaying(port)

    def get_chids(self):
        """returns a list of channel ids"""
        return self.chid2p.keys()

    def get_channel(self, chid):
        """returns the channel for chid or None"""
        return self.chid2p.get(chid, None)

    def close_channel(self, chid, send_message=True):
        """closes a channel"""
        p = self.get_channel(chid)
        if chid is not None:
            p.disconnect(send_message=send_message)

    def in_group(self):
        """returns True if the client has joined a group, False otherwise"""
        return (self.cid is not None)

    
class RelayConnectProtocol(protocol.Protocol):
    """Protocol used to connect to a server hosted on this client"""
    def __init__(self, root, chid, pid, port):
        assert isinstance(pid, (int, long))
        assert isinstance(port, (int, long))
        self.root = root
        self.chid = chid
        self.port = port
        self.pid = pid
        self.did_notify_connect = False
        self.did_send_connection_lost = False
        self.bytes_received = 0
        self.bytes_send = 0
        self.disconnect_d = defer.Deferred()
        self.status = "initiating"
        self.set_status("connecting...")

    def set_status(self, msg):
        """sets the status message"""
        if self.root.debug:
            print "setting status of '{chid}' to '{s}'".format(chid=self.chid, s=msg)
        self.status = msg

    def connectionMade(self):
        """called when the connection was established"""
        self.notify_connect_success()

    def did_connect(self):
        """called when the peer did successfully connect"""
        pass

    def notify_connect_success(self, p=None):
        """called when the connection was established."""
        self.set_status("connected.")
        if p is None:
            p = self
        if self.did_notify_connect:
            return
        self.did_notify_connect = True
        self.root.send_client_command_to_peer(self.pid, {"action": "CONNECT_SUCCESS", "port": self.port})

    def notify_connect_failed(self, f):
        """called when the connection failed"""
        if self.did_notify_connect:
            return
        self.did_notify_connect = True
        self.root.send_client_command_to_peer(self.pid, {"action": "CONNECT_FAIL", "port": self.port})
        self.remove_from_root()
        self.set_status("could not connect to local port")

    def remove_from_root(self):
        """unregister this protocol from the root object"""
        if self.chid in self.root.chid2p:
            del self.root.chid2p[self.chid]

    def dataReceived(self, data):
        """called when some data was received"""
        if self.root.debug:
            print "Got data on {chid} (len={l}): {d}".format(chid=self.chid, l=len(data), d=repr(data))
        self.bytes_received += len(data)
        self.root.send_data_to_peer(self.pid, self.chid, data)

    def send_data(self, data):
        """send data to the other side"""
        if self.root.debug:
            print "sending data to LOCAL (len={l}): {d}".format(l=len(data), d=repr(data))
        self.transport.write(data)
        self.bytes_send += len(data)

    def connectionLost(self, reason=None):
        """called when the connection was lost"""
        self.send_connection_lost()
        self.remove_from_root()
        self.set_status("connection lost")
        if not self.disconnect_d.called:
            self.disconnect_d.callback(self)

    def send_connection_lost(self):
        """sends a message to the peer indicating that this connection was lost"""
        if self.did_send_connection_lost:
            return
        self.did_send_connection_lost = True
        self.root.send_client_command_to_peer(self.pid, {"action": "CONNECTION_CLOSE", "port": self.port})

    def disconnect(self, send_message=True):
        """disconnects the protocol"""
        self.set_status("disconnecting...")
        self.transport.loseConnection()
        if send_message:
            self.send_connection_lost()
        self.remove_from_root()
        if not self.disconnect_d.called:
            self.disconnect_d.callback(self)

    def get_info(self):
        """returns a dict with useful stats about this protocol"""
        return {
            "received": self.bytes_received,
            "send": self.bytes_send,
            "chid": self.chid,
            "status": self.status,
            }

    def wait_disconnect(self):
        """returns a deferred which will be fired on disconnect"""
        return self.disconnect_d


class RelayListenProtocol(RelayConnectProtocol):
    """The protocol used to listen for connections and relay them"""
    def __init__(self, *args, **kwargs):
        RelayConnectProtocol.__init__(self, *args, **kwargs)
        self.buffer = []

    def notify_connect_success(self, p=None):
        # do nothing
        self.set_status("Waiting for peer...")

    def notify_connect_fail(self, f):
        # do nothing
        pass

    def did_connect(self, ignore=None):
        """called when the peer could connect."""
        self.set_status("connected. sending buffered data...")
        if self.buffer is not None:
            for msg in self.buffer:
                RelayConnectProtocol.dataReceived(self, msg)
            self.buffer = None
            self.set_status("connected.")

    def dataReceived(self, data):
        if self.buffer is not None:
            self.buffer.append(data)
        else:
            RelayConnectProtocol.dataReceived(self, data)


class RelayListenFactory(protocol.ServerFactory):
    """The factory used to create RelayListenProtocol"""
    def __init__(self, root, cid, pid, listen_port, target_port):
        assert isinstance(cid, (int, long))
        assert isinstance(pid, (int, long))
        assert isinstance(listen_port, (int, long))
        assert isinstance(target_port, (int, long))
        self.root = root
        self.cid = cid
        self.pid = pid
        self.listen_port = listen_port
        self.target_port = target_port
        self.lp = None
        self.total_connections = 0

    def buildProtocol(self, addr):
        """called to create a protocol"""
        port = addr.port
        chid = (self.cid, port)
        d = self.root.send_open_command(chid, self.pid, port, self.target_port)
        p = RelayListenProtocol(self.root, chid, self.pid, port)
        d.addCallback(p.did_connect)
        self.root.chid2p[chid] = p
        self.total_connections += 1
        return p

    def did_bind(self, lp):
        """called when the factory did bind."""
        self.lp = lp
        port = self.lp.getHost().port
        self.listen_port = (port if isinstance(port, int) else self.listen_port)
        self.root.port2relay[self.listen_port] = self

    def stop(self):
        """stops listening"""
        self.lp.stopListening()
        self.remove_from_root()

    def remove_from_root(self):
        """removes this factory from the root object"""
        if self.listen_port in self.root.port2relay:
            del self.root.port2relay[self.listen_port]

    def get_info(self):
        """returns a dictionary containing information and stats about this relay"""
        return {
            "local_port": self.listen_port,
            "remote_port": self.target_port,
            "pid": self.pid,
            "total_connections": self.total_connections,
            }
