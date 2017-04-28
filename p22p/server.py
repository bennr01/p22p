# -*- Coding: utf-8 -*-
"""P22P v0.4 server"""
import json
import hmac
import ast
import struct
import os
import hashlib
import time


from twisted.internet import task
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import IntNStringReceiver

from p22p import common

# ==== SERVER CONSTANTS =====

STATE_QUIT = 0
STATE_INIT = 1
STATE_MAIN = 2

DEFAULT_RESERVATION_LIFETIME = 60 * 60 * 24 * 31 * 3  # 3 months


# ===== Reservation system =====

def load_secret(path):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    else:
        length = 25 + ord(os.urandom(1))
        secret = os.urandom(length)
        with open(path, "wb") as f:
            f.write(secret)
        return secret


class ReservedGroupKey(object):
    """
    This class represents a signed key for restricting
    creation permissions for specific domains.
    """
    check_sign = ("name", "expires")
    
    def __init__(self, factory, info, secret):
        assert isinstance(info, dict)
        assert isinstance(secret, str)
        self.factory = factory
        self.info = info
        self.secret = secret
    
    def __getitem__(self, key):
        return self.info[key]
        
    def __nonzero__(self):
        return True

    @property
    def name(self):
        return self.info.get("name", None)
    
    @classmethod
    def load(cls, factory, data, secret):
        assert isinstance(data, (str, unicode))
        assert isinstance(secret, str)
        try:
            des = json.loads(data)
            des["name"] = str(des["name"])
            des["sign"] = str(des["sign"])
        except:
            return None
        ret = cls(factory, des, secret)
        if not ret.is_valid():
            return None
        return ret

    def save(self):
        return json.dumps(self.info)
    
    def is_valid(self):
        try:
            orgsign = self.info["sign"]
            tocheck = []
            for key in self.check_sign:
                tocheck.append(self.info[key])
            ser = json.dumps(tocheck)
            sign = hmac.new(self.secret, ser, hashlib.sha256).hexdigest()
            a = (sign == orgsign)
            b = (self.info["expires"] > time.time())
            return (a and b)
        except KeyError:
            return False

    @classmethod
    def new(cls, factory, name, lifetime, sco=True):
        assert isinstance(name, (str, unicode))
        assert isinstance(lifetime, (int, float, long))
        name = ReservedGroupKey.str_name(name)
        expires = time.time() + lifetime
        ser = json.dumps([name, expires])
        sign = hmac.new(factory.secret, ser, hashlib.sha256).hexdigest()
        cd = {"name": name, "sign": sign, "expires": expires, "sco": sco}
        factory.db[name] = str(expires)
        return cls(factory, cd, factory.secret)
    
    def extend_key(self, lifetime):
        assert isinstance(lifetime, (int, float, long))
        return self.new(self.factory, name=self.info["name"], lifetime=lifetime, sco=self.info["sco"])
    
    @classmethod
    def check_existence(cls, db, name):
        assert isinstance(name, (str, unicode))
        name = cls.str_name(name)
        i = (name in db)
        return i
    
    @staticmethod
    def is_available(db, name):
        assert isinstance(name, (str, unicode))
        name = ReservedGroupKey.str_name(name)
        if name not in db:
            return True
        exp = ast.literal_eval(db[name])
        ia = (exp < time.time())
        if ia:
            del db[name]
        return ia
    
    @staticmethod
    def clear_expired(db):
        t = time.time()
        for k in db:
            v = db.get(k, None)
            if v is None:
                continue
            if v < t:
                del db[k]

    @staticmethod
    def str_name(*args):
        """returns the name as a string"""
        assert len(args) in (1, 2)
        if len(args) == 1:
            s = args[0]
        else:
            s = args[1]
        if isinstance(s, str):
            return s
        elif isinstance(s, unicode):
            return s.encode("utf-8")
        else:
            raise ValueError("Expected str or unicode!")


# ===== Groups =====

class Group(object):
    """A Group manages the communication between clients"""
    def __init__(self, factory, name, pswd, sco=False, compression=common.DEFAULT_COMPRESSION_LEVEL):
        self.factory = factory
        self.name = name
        self.pswd = pswd
        self.sco = sco
        self.compression_level = compression
        self.destroying = False
        self.members = {}
        self.c2id = {}

    def new_cid(self):
        """returns a new client id or None"""
        if self.destroying:
            return None
        cids = self.members.keys()  # only check one time to improve perfomance
        for i in xrange(common.MAX_CIDS):
            if i not in cids:
                if not (self.sco and (i == 0)):
                    return i
        return None

    def join(self, client, pswd, cid=None):
        """
        check pswd and add client as member of this group if pswd match.
        return his new id if joined else False.
        """
        if pswd != self.pswd:
            return "Invalid password"
        if len(self.members.keys()) >= common.MAX_CIDS:
            # no ids left
            return "Group is full"
        if cid is None:
            cid = self.new_cid()
        if cid is None:
            return "Group is full"
        if cid in self.members:
            oc = self.members[cid]
            self.send_leave(cid)
            oc.kick()
        self.members[cid] = client
        self.c2id[client] = cid
        client.group = self
        return cid

    def leave(self, client):
        """remove client from group"""
        cid = self.c2id[client]
        self.send_leave(cid)
        del self.c2id[client]
        del self.members[cid]
        if len(self.members.keys()) <= 0 or (self.sco and cid == 0):
            # remove this group if no clients are connected
            # or if the creator left in sco-mode
            self.destroy()

    def destroy(self):
        """removes this group."""
        if self.destroying:
            return  # otherwise keyerror
        self.destroying = True
        self.pswd = None  # disable joining
        for c in self.c2id.keys():
            c.kick()  # kick from server
        del self.factory.groups[self.name]

    def send_leave(self, cid):
        """tells the members that this client left the group."""
        for client in self.c2id.keys():
            if self.c2id[client] == cid:
                continue
            client.send_leave_message(cid)

    def send_to(self, cid, pid, msg):
        """sends a message to client pid."""
        if pid not in self.members.keys():
            return
        if (cid != 0 and pid != 0) and self.sco:
            # disallow communication between clients in sco-mode
            return
        client = self.members[pid]
        client.send_message_to_client(cid, msg)


# ===== Protocol =====

class P22PServerProtocol(IntNStringReceiver):
    """The Protocol for the P22PServer"""
    structFormat = common.LENGTH_FORMAT
    prefixLength = common.LENGTH_FORMAT_LENGTH

    debug = False

    def __init__(self):
        self.cid = None
        self.group = None
        self.state = STATE_INIT
        self.did_reserve = False

    def stringReceived(self, msg):
        """called when a string was received"""
        assert isinstance(msg, str)
        
        if self.debug:
            print "got data: ", repr(msg)
        
        if len(msg) == 0:
            pass
        
        elif self.state == STATE_QUIT:
            # client did not disconnect, disconnecting him
            self.disconnect()

        if self.state == STATE_INIT:
            if msg != common.VERSION:
                self.sendString("\x00")
                self.state = STATE_QUIT
            else:
                self.sendString("\x01")
                self.state = STATE_MAIN

        elif self.state == STATE_MAIN:
            idb = msg[0]
            payload = msg[1:]
            if idb == common.ID_SERVER_COMMAND:
                try:
                    data = json.loads(payload)
                except:
                    # protocol violation
                    self.disconnect()
                self.handle_server_command(data)
            else:
                if self.group is None:
                    # protocol violation
                    self.disconnect()
                else:
                    self.handle_client_data(idb, payload)

        else:
            # protocol violation
            self.disconnect()

    def connectionLost(self, *args, **kwargs):
        """called when the connection to the client was lost."""
        self.state = STATE_QUIT
        if self.group is not None:
            self.leave_group()

    def handle_server_command(self, data):
        """handle a command received from the client"""
        action = data.get("action", None)
        if action is None:
            return
        if action == "QUIT":
            self.leave_group()
            self.disconnect()
        elif action == "LEAVE":
            self.leave_group()
        elif action == "JOIN":
            name = data.get("name", None)
            pswd = data.get("password", None)
            cert = data.get("cert", None)
            if name is None:
                self.disconnect()
            elif pswd is None:
                self.disconnect()
            self.join_group(name, pswd, cert)
        elif action == "CREATE":
            name = data.get("name", None)
            pswd = data.get("password", None)
            cert = data.get("cert", None)
            sco = data.get("sco", False)
            cpl = data.get("compression", common.DEFAULT_COMPRESSION_LEVEL)
            if name is None:
                self.disconnect()
            if pswd is None:
                self.disconnect()
            self.create_group(name=name, pswd=pswd, cert=cert, sco=sco, compression=cpl)
        elif action == "PING":
            ping_id = data.get("ping_id", "<None>")
            self.send_server_command({"action": "PONG", "ping_id": ping_id})
        elif action == "CID":
            self.send_cid()
        elif action == "RESERVE":
            name = data.get("name", None)
            sco = data.get("sco", True)
            if name is None:
                self.send_server_command({"action": "RESERVE_FAIL", "reason": "Invalid Request."})
            elif self.did_reserve:
                self.send_server_command({"action": "RESERVE_FAIL", "reason": "Already reserved a Group!"})
            else:
                k = self.factory.reserve_group(self, name, sco)
                if isinstance(k, str):
                    self.send_server_command({"action": "RESERVE_FAIL", "reason": k})
                else:
                    c = k.save()
                    self.send_server_command({"action": "RESERVE_SUCCESS", "cert": c})
                    self.did_reserve = True
        elif action == "EXTEND":
            cert = data.get("cert", None)
            if cert is None:
                self.send_server_command({"action": "EXTEND_FAIL", "reason": "Invalid Request"})
            else:
                k = self.factory.extend_reservation(self, cert)
                if isinstance(k, str):
                    self.send_server_command({"action": "EXTEND_FAIL", "reason": k})
                else:
                    c = k.save()
                    self.send_server_command({"action": "EXTEND_SUCCESS", "cert": c})
        else:
            # protocol violation
            self.disconnect()

    def handle_client_data(self, idb, payload):
        """handle data received from the client"""
        assert self.group is not None
        if len(payload) < common.CID_FORMAT_LENGTH:
            self.disconnect()
        ciddata, payload = payload[:common.CID_FORMAT_LENGTH], payload[common.CID_FORMAT_LENGTH:]
        cid = struct.unpack(common.BYTEORDER + common.CID_FORMAT, ciddata)[0]
        # msg = struct.pack(common.BYTEORDER + common.CID_FORMAT, self.cid) + payload
        self.group.send_to(self.cid, cid, idb + payload)

    def send_server_command(self, data):
        """sends a server command to the client"""
        assert isinstance(data, dict)
        dumped = json.dumps(data)
        self.sendString(common.ID_SERVER_COMMAND + dumped)

    def join_group(self, name, pswd, cert=None):
        """joins a group"""
        if self.group is not None:
            self.leave_group()
        cid = self.factory.join_group(self, name, pswd, cert=cert)
        if (cid is None) or (cid is False) or isinstance(cid, str):
            if not isinstance(cid, str):
                msg = "Unknown Error"
            else:
                msg = cid
            self.send_server_command({"action": "JOIN_FAIL", "reason": msg})
        else:
            self.cid = cid
            self.send_join_message()
            self.send_cid()

    def send_join_message(self):
        """sends the message indicating that the client joined the group."""
        self.send_server_command({"action": "JOINED", "cid": self.cid, "compression": self.group.compression_level, "sco": self.group.sco})
        
    def send_cid(self):
        """sends the client the id and notifies the client"""
        self.send_server_command({"action": "SET_CID", "cid": self.cid})

    def leave_group(self):
        """leaves the group"""
        if self.group is None:
            return
        self.group.leave(self)
        self.group = None

    def create_group(self, name, pswd, cert=None, sco=False, compression=common.DEFAULT_COMPRESSION_LEVEL):
        """creates a group."""
        assert isinstance(name, (str, unicode))
        assert isinstance(pswd, (str, unicode))
        assert isinstance(cert, (str, unicode)) or (cert is None)
        assert isinstance(compression, (int, long))
        if self.group is not None:
            self.leave_group()
        cid = self.factory.create_group(self, name, pswd, cert=cert, sco=sco, compression=compression)
        if (cid is None) or (cid is False) or isinstance(cid, str):
            if not isinstance(cid, str):
                msg = "Unknown Error"
            else:
                msg = cid
            self.send_server_command({"action": "CREATE_FAIL", "reason": msg})
        else:
            self.cid = cid
            self.send_join_message()
            self.send_cid()

    def send_leave_message(self, cid):
        """sends a message to the client indicating that a client disconnected"""
        self.send_server_command({"action": "LEAVE", "cid": cid})
        if cid == self.cid:
            self.kick()

    def send_message_to_client(self, pid, data):
        """sends data from a client to this client"""
        if self.state == STATE_QUIT:
            return
        msg = data[0] + struct.pack(common.BYTEORDER + common.CID_FORMAT, pid) + data[1:]
        self.sendString(msg)

    def disconnect(self):
        """disconnect the client"""
        if self.group is not None:
            self.leave_group()
        self.send_server_command({"action": "DISCONNECT"})
        self.transport.loseConnection()

    def kick(self):
        """kicks the client forom the server"""
        self.transport.loseConnection()


# ===== Factory =====

class P22PServerFactory(ServerFactory):
    """The Factory for the P22PServer"""
    protocol = P22PServerProtocol
    
    def __init__(self, db, secret, reserved_prefix="#", reservation_lifetime=DEFAULT_RESERVATION_LIFETIME, autoclear=False):
        assert isinstance(secret, str)
        assert isinstance(reserved_prefix, (str, unicode))
        assert isinstance(autoclear, (int, float, long)) or (autoclear is False) or (autoclear is None)
        self.db = db
        self.secret = secret
        self.reserved_prefix = reserved_prefix
        self.reservation_lifetime = reservation_lifetime
        self.autoclear = autoclear
        self.groups = {}

        if isinstance(autoclear, (int, long, float)):
            loop = task.LoopingCall(self.clear_expired)
            loop.start(self.autoclear)

    def clear_expired(self):
        """clears all expired keys from the database"""
        ReservedGroupKey.clear_expired(self.db)

    def join_group(self, client, name, pswd, cert=None):
        """join a group"""
        assert isinstance(name, (str, unicode))
        assert isinstance(cert, (str, unicode)) or (cert is None)
        assert isinstance(pswd, (str, unicode))
        if name not in self.groups:
            return "No such Group"
        if cert is not None:
            key = ReservedGroupKey.load(self, cert, self.secret)
            if key is None:
                return "Invalid key/cert"
            if not key.is_valid():
                return "Invalid key/cert"
            cid = 0
        else:
            cid = None
        group = self.groups[name]
        s = group.join(client, pswd, cid=cid)
        return s

    def create_group(self, client, name, pswd, cert=None, sco=False, compression=common.DEFAULT_COMPRESSION_LEVEL):
        """create a group"""
        assert isinstance(name, (str, unicode))
        assert isinstance(cert, (str, unicode)) or (cert is None)
        assert isinstance(pswd, (str, unicode))
        assert isinstance(compression, (int, long))
        if name.startswith(self.reserved_prefix) and (cert is None):
            return "Namespace is reserved for reserved Groups"
        if (name in self.groups) and (cert is None):
            if len(self.groups[name].members) > 0:
                return "Group already exists"
        if cert is not None:
            key = ReservedGroupKey.load(self, cert, self.secret)
            if key is None:
                return "Invalid key/cert"
            if not key.is_valid():
                return "Invalid key/cert"
            if key.name != name:
                return "Key/cert does not match groupname!"
        cid = 0
        if name in self.groups:
            group = self.groups[name]
            group.destroy()
        group = Group(self, name, pswd, sco=sco, compression=compression)
        self.groups[name] = group
        s = group.join(client, pswd, cid=cid)
        return s

    def reserve_group(self, client, name, sco=True):
        """reserves a Group"""
        if not ReservedGroupKey.is_available(self.db, name):
            return "Group already reserved."
        elif not name.startswith(self.reserved_prefix):
            return "Please use the Namespace for reserved Groups ( = names startig with '{p}').".format(p=self.reserved_prefix)
        else:
            k = ReservedGroupKey.new(self, name, lifetime=self.reservation_lifetime, sco=sco)
            return k

    def extend_reservation(self, client, cert):
        """extends a reservation"""
        key = ReservedGroupKey.load(self, cert, self.secret)
        if key is None:
            return "Invalid key/cert"
        if not key.is_valid():
            if ReservedGroupKey.is_available(self.db, key.name):
                pass
            else:
                return "Key is no longer valid and Group has already been reserved by someone else."
        key.extend_key(self.reservation_lifetime)
        return key
        
        

if __name__ == "__main__":
    import anydbm
    import sys
    from twisted.python import log
    log.startLogging(sys.stdout)
    from twisted.internet import reactor

    db = anydbm.open("p22p_keys.dbm", "c")
    secret = load_secret("p22p_secret.bin")
    
    factory = P22PServerFactory(db=db, secret=secret)
    reactor.listenTCP(port=common.DEFAULT_PORT, interface="0.0.0.0", factory=factory, backlog=3)
    
    reactor.run()
