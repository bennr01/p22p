# coding: utf-8
"""the P22P-Client. Also contains a single-file UI and a argument interface."""

import socket,select,struct,hashlib,base64,time,threading,cmd,sys,atexit,zlib,os,argparse
import autobahn.twisted.websocket as websocket
import twisted.internet
from twisted.internet import reactor
from twisted.internet.error import ReactorNotRunning
try:
	from twisted.internet import ssl
except:
	ssl=None

#constants
VERSION=0.3
PROTOCOLS=["P22P-WS-P"]
USER_AGENT="P22P/{v}".format(v=VERSION)
DEBUG=("-d" in sys.argv)
ISETO=0.02
RECV_BUFF=4096
COMPRESSION=7

ID_CTRL="\x01"
ID_PC="\x02"
ID_MSG="\x03"

DEFAULT_SERVER="ws://p22p-bennr01.rhcloud.com:8000"

if DEBUG:
	from twisted.python import log
	log.startLogging(sys.stdout)

#Exceptions
class CommunicationError(IOError):
	pass
class ConnectionError(IOError):
	pass
class UsageError(Exception):
	pass

#Encryption (uses CBC)

def _blockXOR(a,b):
	#return a xor b
	if len(a)!=len(b):
		raise ValueError("expected to strings with same length")
	res=[]
	for i in xrange(len(a)):
		res.append(chr(ord(a[i])^ord(b[i])))
	return "".join(res)
def encrypt(plain,key):
	"""encrypt using CBC."""
	blocklength=len(key)
	dl=len(plain)
	bc=dl/blocklength
	v=key
	i=0
	res=[]
	while i<bc:
		start=i*blocklength
		end=start+blocklength
		block=plain[start:end]
		v=_blockXOR(block,v)
		i+=1
		res.append(v)
	rm=dl%blocklength
	if rm>0:
		block=plain[-rm:]
		plain2=_blockXOR(block,v[0:rm])
		res.append(plain2)
	return "".join(res)
def decrypt(chipher,key):
	"""decrypts using CBC."""
	blocklength=len(key)
	dl=len(chipher)
	bc=dl/blocklength
	v=key
	i=0
	res=[]
	while i<bc:
		start=i*blocklength
		end=start+blocklength
		block=chipher[start:end]
		plain=_blockXOR(block,v)
		v=block
		i+=1
		res.append(plain)
	rm=dl%blocklength
	if rm>0:
		block=chipher[-rm:]
		plain=_blockXOR(block,v[0:rm])
		res.append(plain)
	return "".join(res)

#Communication

class P22PClientProtocol(websocket.WebSocketClientProtocol):
	"""The clientside Communication-Protocol"""
	def __init__(self,*args,**kwargs):
		nargs=tuple([self]+list(args))
		apply(websocket.WebSocketClientProtocol.__init__,nargs,kwargs)
		self.did_handshake=False
		self.cid=None
		self.joinstate=0#0=Not joining, 1=waiting, 2=Success, 3=Fail
		self.createstate=0#0=Not creating, 1=waiting, 2=Success, 3=Fail
		self.reservestate=0#0=Not reserving, 1=waiting, str=Success, 3=Fails
		self.extendstate=0#see above
		self.pingstates={}
		self.ai2s={}#map ai to s (ai=Adress info)
		self.ls={}#list of listening sockets
		self.s2ai={}#map sockets to ai
		self.s2i={}#map sockets to info
		self.whitelist=None
		self.AL=threading.Lock()
		reactor.callInThread(self.__loop)#use deffereds instead?
	def clientConnectionFailed(self,connector,reason):
		"""called when the connection failed."""
		if DEBUG:
			sys.stdout.write("Connection failed: reason: '{r}'.\n".format(r=reason))
		websocket.WebSocketClientProtocol.clientConnectionFailed(self,connector,reason)
		self.factory.root._connect_failed()
		#raise CommunicationError,"WS-Error during Connect: {r}!".format(r=reason)
	def onConnect(self,response):
		"""called when connection was established."""
		if DEBUG:
			sys.stdout.write("Connection established. Response: '{r}'.\n".format(r=response))
		self.factory.root.client=self#we need to tell the client-object that  this is the connection
	def onOpen(self):
		"""called when the connection was established and ws-handshake finished."""
		if DEBUG:
			sys.stdout.write("Initiating Handshake...\n")
		self.sendMessage(struct.pack("!d",VERSION),True)
	def onClose(self,wasclean,code,reason):
		"""called when an error occcures."""
		if DEBUG:
			sys.stdout.write("Connection closed.\n")
		if not wasclean:
			raise CommunicationError("WS-Error {n}: {r}!".format(n=code,r=reason))
		else:
			try: reactor.stop()
			except ReactorNotRunning:
				pass
	def onMessage(self,msg,isBinary):
		"""called when a message is received."""
		if DEBUG:
			sys.stdout.write("Got {t}binary Message: '{m}'.\n".format(m=msg,t="" if isBinary else "non"))
		if not isBinary:
			raise CommunicationError("Received non-binary Message: '{m}'!'".format(m=msg))
			return
		if not self.did_handshake:
			if len(msg)!=1:
				raise CommunicationError("Error during Handshake: Expected 1 Byte, got {n} Bytes!".format(n=len(msg)))
			if msg=="T":
				self.did_handshake=True
				return
			elif msg=="F":
				raise CommunicationError("Version Mismatch!")
			else:
				raise CommunicationError("Error during Handshake: Regeived Invalid Answer: '{a}'!".format(a=msg))
		idb=msg[0]
		payload=msg[1:]
		if idb==ID_CTRL:
			if payload.startswith("I:JOIN") and len(payload)==7:
				self.cid=ord(payload[-1])
				self.joinstate=2
			elif payload=="E:NOJOIN":
				self.joinstate=3
			elif payload.startswith("I:CREATE") and len(payload)==9:
				self.cid=ord(payload[-1])
				self.createstate=2
			elif payload=="E:NOCREATE":
				self.createstate=3
			elif payload.startswith("I:RESERVE"):
				self.reservestate=payload[9:]
			elif payload=="E:NORESERVE":
				self.reservestate=3
			elif payload.startswith("I:EXTEND"):
				self.extendstate=payload[8:]
			elif payload=="E:NOEXTEND":
				self.extendstate=3
			elif payload.startswith("LEAVE") and len(payload)==6:
				pid=ord(payload[-1])
				self.AL.acquire()
				for s in self.ls.keys():
					if self.ls[s]["peer"]==pid:
						self._close_s(s)
				for s in self.s2i.keys():
					i=self.s2i[s]
					if i["peer"]==pid:
						port=i["local"]
						self._close_s(s)
				self.AL.release()
		elif idb==ID_PC:
			sender,payload=ord(payload[0]),payload[1:]
			if payload=="PING":
				self.send_to(sender,ID_PC+"PINGANSW")
			elif payload=="PINGANSW":
				ct=time.time()
				if sender not in self.pingstates.keys():
					return
				else:
					st=self.pingstates[sender][1]
					res=ct-st
					self.pingstates[sender]=(True,res)
			elif payload.startswith("BRIDGE") and len(payload)==10:
				lp,pp=struct.unpack("!HH",payload[6:])
				ai=(sender,pp)
				if isinstance(self.whitelist,list) or isinstance(self.whitelist,tuple):
					if not lp in self.whitelist:
						self.__send_close(ai)
						return
				try:
					s=socket.socket()
					s.connect(("localhost",lp))
					self.AL.acquire()
					self.s2i[s]={"socket":s,"recv":0,"send":0,"peer":sender,"local":pp,"port":lp,"creator":sender}
					self.s2ai[s]=ai
					self.ai2s[ai]=s
					self.AL.release()
				except:
					self._close_s(s)
			elif payload.startswith("CLOSE") and len(payload)==8:
				c=ord(payload[5])
				lp=struct.unpack("!H",payload[6:])[0]
				ai=(c,lp)
				self.AL.acquire()
				try:
					s=self.ai2s[ai]
					self._close_s(s,send_close=False)
				except KeyError:
					pass
				self.AL.release()
		elif idb==ID_MSG:
			sender,creator,pi,payload=ord(payload[0]),ord(payload[1]),payload[2:4],payload[4:]
			lp=struct.unpack("!H",pi)[0]
			ai=(creator,lp)
			comp=decrypt(payload,self.__key)
			if COMPRESSION>0:
				tosend=zlib.decompress(comp)
			else: tosend=comp
			length=len(tosend)
			self.AL.acquire()
			try:
				s=self.ai2s[ai]
			except KeyError:
				self.AL.release()
				return
			self.s2i[s]["recv"]+=length
			self.AL.release()
			try:
				s.send(tosend)
			except:
				self.AL.acquire()
				self._close_s(s)
				self.AL.release()
		else:
			raise CommunicationError("Received Message with invalid ID '{i}'!".format(i=idb))
	def __loop(self):
		"""the internal socket event loop."""
		while True:
			self.AL.acquire()
			tr=self.ls.keys()+self.s2ai.keys()
			tw=[]
			tcx=tr
			self.AL.release()#other threads may modifiy this while we wait
			if len(tr+tw+tcx)==0:
				#acording to docs, three empty lists are platform dependant.
				#better not wait with empty lists.
				time.sleep(ISETO)#dont waste resources in a while-true-pass-loop
				continue
			ra,wa,xs=select.select(tr,tw,tcx,ISETO)#timeout so we can check for new sockets to read from
			self.AL.acquire()
			for s in xs:
				if s in ra:
					ra.remove(s)
					info=self.s2i[s]
				if s in wa:
					wa.remove(s)
				self._close_s(s)
			for s in ra:
				if s in self.ls.keys():
					#new connection
					c,a=s.accept()
					self.ls[s]["got"]+=1
					port=self.ls[s]["port"]
					lp=c.getsockname()[1]
					peer=self.ls[s]["peer"]
					ai=(self.cid,lp)
					self.ai2s[ai]=c
					self.s2ai[c]=ai
					self.s2i[c]={"ai":ai,"recv":0,"send":0,"local":lp,"creator":self.cid,"peer":peer,"socket":c,"port":port}
					self.send_to(peer,ID_PC+"BRIDGE"+struct.pack("!HH",port,lp))
				if s in self.s2ai.keys():
					ai=self.s2ai[s]
					data=s.recv(RECV_BUFF)
					self.s2i[s]["send"]+=len(data)
					info=self.s2i[s]
					if len(data)==0:
						self._close_s(s)
						continue
					pi=struct.pack("!H",ai[1])
					if COMPRESSION>0:
						comp=zlib.compress(data,COMPRESSION)
					else: comp=data
					tosend=encrypt(comp,self.__key)
					self.send_to(info["peer"],ID_MSG+chr(ai[0])+pi+tosend)
			for s in wa:
				pass
			self.AL.release()
	def __send_close(self,ai):
		"""tells peer that conn on port was closed."""
		peer=self.s2i[self.ai2s[ai]]["peer"]
		self.send_to(peer,ID_PC+"CLOSE"+chr(ai[0])+struct.pack("!H",ai[1]))
	def _close_s(self,s,send_close=True):
		"""closes a socket. Does not acquire intern lock."""
		try:
			if s in self.ls.keys():
				del self.ls[s]
			if s in self.s2ai.keys():
				ai=self.s2ai[s]
				if send_close:
					self.__send_close(ai)
				del self.s2ai[s]
				if ai in self.ai2s.keys():
					del self.ai2s[ai]
			if s in self.s2i.keys():
				del self.s2i[s]
		except:
			pass
		finally:
			try: s.close()
			except:
				pass
	def send_to(self,target,msg):
		"""sends a message to groupmember target"""
		if self.cid is None:
			raise UsageError("Not in a group!")
		idb,payload=msg[0],msg[1:]
		self.sendMessage(idb+chr(target)+payload,True)
	def disconnect(self):
		"""disconnects from the server."""
		if not self.did_handshake:
			raise UsageError("Not connected!")
		self.sendMessage(ID_CTRL+"DISCONNECT",True)
		self.cid=None
		self.did_handshake=False
		self.joinstate=0
		self.createstate=0
		self.sendClose()
	def create_group(self,name,pswd,key=None):
		"""creates and joins a group. returns True if it was created, otherwise False. key is optional and is a key for creating a group with a reserved name."""
		if not self.did_handshake:
			return False
		hpo=hashlib.sha256(pswd)
		hp=hpo.digest()
		tozip=[name,hp]
		if key is not None:
			tozip.append(key)
		tosend="\x00".join([base64.b64encode(e) for e in tozip])
		self.sendMessage(ID_CTRL+"CREATE"+tosend,True)
		self.createstate=1
		while self.createstate==1:
			pass
		if self.createstate==2:
			self.createstate=0
			self.__key=pswd
			return True
		else:
			self.createstate=0
			return False
	def join_group(self,name,pswd):
		"""joins a group"""
		hpo=hashlib.sha256(pswd)
		hp=hpo.digest()
		tosend="\x00".join([base64.b64encode(e) for e in (name,hp)])
		self.sendMessage(ID_CTRL+"JOIN"+tosend,True)
		self.joinstate=1
		while self.joinstate==1:
			pass
		if self.joinstate==2:
			self.joinstate=0
			self.__key=pswd
			return True
		else:
			self.joinstate=0
			return False
	def leave_group(self):
		"""leaves the current group."""
		self.sendMessage(ID_CTRL+"LEAVE",True)
		self.joinstate=0
		self.createstate=0
		self.__key=None
	def ping(self,target):
		"""pings the target group member."""
		if not self.did_handshake:
			raise UsageError("Not connected!")
		if self.cid is None:
			raise UsageError("Not in a Group!")
		self.pingstates[target]=(False,time.time())
		self.send_to(target,ID_PC+"PING")
		while not self.pingstates[target][0]:
			pass
		ret=self.pingstates[target][1]
		del self.pingstates[target]
		return ret
	def relay_port(self,pid,remote,local=0):
		"""relay port local to port remote on peer pid. A socket can connect to the local port and the communication will be relayed to remote.
		returns the port used localy"""
		if not self.did_handshake:
			raise UsageError("Not connected!")
		if self.cid is None:
			raise UsageError("Not in a Group!")
		s=socket.socket()
		try:
			s.bind(("localhost",local))
			port=s.getsockname()[1]
			s.listen(1)
			self.AL.acquire()
			self.ls[s]={"peer":pid,"port":remote,"got":0,"local":port}
			self.AL.release()
			return port
		except:
			if self.AL.locked():
				self.AL.release()
			s.close()
			raise
	def list_conns(self):
		"""
returns a list of the current relayed ports.
Each list element has the structure (type,from,localport,to,peerport,recv,send).
type: a string
from: 'LOCAL' or int
localport: int
to: 'LOCAL' or int
peerport: int
recv: int
send: int or None
"""
		res=[]
		self.AL.acquire()
		for ls in self.ls.keys():
			info=self.ls[ls]
			res.append(("Relay","LOCAL",info["local"],info["peer"],info["port"],info["got"],None))
		for s in self.s2i.keys():
			info=self.s2i[s]
			if info["creator"]==self.cid:
				fai="LOCAL"
				tai=info["peer"]
			else:
				fai=info["creator"]
				tai=info["peer"]
			res.append(("Conn",fai,info["local"],tai,info["port"],info["recv"],info["send"]))
		self.AL.release()
		return res
	def reserve_group(self,name,sco=True):
		"""reserves a froup and returns the key. if sco, only medsages between creator and clients are allowed."""
		if isinstance(self.reservestate,str):
			#already reserved, server wouldnt handle the request
			raise UsageError("Already reserved a Group!")
		elif not name.startswith("#"):
			raise UsageError("Reserved Groupnames need to start with a '#'!")
		tosend=name+("T" if sco else "F")
		self.reservestate=1
		self.sendMessage(ID_CTRL+"RESERVE"+tosend,True)
		while self.reservestate==1:
			pass
		if isinstance(self.reservestate,str):
			return self.reservestate
		else:
			self.reservestate=0
			return False
	def extend_reservation(self,key):
		"""extends the reservation for the group."""
		self.extendstate=1
		self.sendMessage(ID_CTRL+"EXTEND"+key,True)
		while self.extendstate==1:
			pass
		if isinstance(self.extendstate,str):
			ret=self.extendstate
			self.extendstate=0
			return ret
		else:
			self.extendstate=0
			return False
		

class P22PClientFactory(websocket.WebSocketClientFactory):
	"""The Factory for the P22P-Client"""
	def __init__(self,root,url):
		websocket.WebSocketClientFactory.__init__(self,url=url,protocols=PROTOCOLS,useragent=USER_AGENT,debug=DEBUG)
		self.protocol=P22PClientProtocol
		self.root=root

#Client object

class P22PClient(object):
	"""The P22P-Client."""
	def __init__(self,root,reactor=reactor):
		self.root=root
		self.factory=None
		self.client=None
		self.reactor=reactor#keep a reference if we ever change the reactor
	def connect(self,addr):
		"""connects to target server"""
		if self.client is not None:
			if self.client.did_handshake:
				raise UsageError("Already Connected!")
		try:
			self.factory=P22PClientFactory(self,addr)
			if self.factory.isSecure and (ssl is not None):
				context=ssl.ClientContextFactory()
			else:
				context=None
			#self.reactor.connectTCP(ip,port,self.factory,timeout=10)
			websocket.connectWS(self.factory,context,timeout=10)
			while self.client is None:
				#wait for self.client to be set
				pass
			if self.client is False:
				self.client=None
				raise ConnectionError("Cant connect to Server!")
			while not self.client.did_handshake:
				pass
		except:
			self.factory=None
			self.client=None
			raise
	def _connect_failed(self):
		"""called when the connection failed."""
		self.root.stdout.write("Error: Connection Failed!\n")
		self.client=False
	def disconnect(self):
		"""disconnects from server."""
		if self.client is None:
			raise UsageError("Not connected!")
		self.client.disconnect()
		self.client=None
		self.factory=None
	close=disconnect#alias for disconnect
	def create(self,name,pswd,key=None):
		"""Creates a Group."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.create_group(name,pswd,key)
	def join(self,name,pswd):
		"""Joins a Group."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.join_group(name,pswd)
	def leave(self):
		"""Leaves the Group."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.leave_group()
	def ping(self,target):
		"""pings target peer"""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.ping(target)
	def get_cid(self):
		"""returns the cid of this client."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.cid
	def relay(self,pid,remote,local=0):
		"""relays LOCAL to REMOTE@PID. Note that LOCAL is the port the local socket connects to and REMOTE the port where the server/host is running."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.relay_port(pid,remote,local)
	def list(self):
		"""returns a list of tuples each representing a connection or relay."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.list_conns()
	def reserve_group(self,name,sco):
		"""reserves a group (only owner of the key can create them) and returns the key on success. Otherwise returns False.
		if sco is True, only the creator of the group and the clients can communicate, otherwise clients can communicate with esch other."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.reserve_group(name,sco)
	def extend_reservation(self,key):
		"""extends a key for a reservation. key needs to be valid at this moment."""
		if self.client is None:
			raise UsageError("Not connected!")
		return self.client.extend_reservation(key)
	def set_whitelist(self,wl):
		"""sets the whitelist of ports. if wl is None, disable the whitelist."""
		if self.client is None:
			raise UsageError("Not connected!")
		if not (isinstance(wl,list) or isinstance(wl,tuple) or (wl is None)):
			raise ValueError("wl needs to be a list, tupler or None!")
		self.client.whitelist=wl

#Single-File User Interface

class P22PClientConsole(cmd.Cmd):
	"""A text-userinterface."""
	prompt="(p22p)"
	intro="p22p-Client v{v} For help, type 'help' or '?'.".format(v=VERSION)
	use_rawinput=True
	def __init__(self,reactor=reactor):
		cmd.Cmd.__init__(self)
		self.reactor=reactor
		self.client=P22PClient(self,reactor)
		self.ingroup=False
	def do_connect(self,cmd):
		"""connect [ADDRESS:PORT]: Connects to target server. If no address nor port are given, connect to default server."""
		if self.client.client is not None:
			self.stdout.write("Already connected!\n")
			return
		if cmd.count("://")>1:
			self.stdout.write("Invalid Argument!\n")
		if len(cmd)==0:
			target=DEFAULT_SERVER
		else:
			target=cmd
		try:
			self.stdout.write("Connecting to '{a}'...\n".format(a=target))
			self.client.connect(target)
			self.stdout.write("Connected.\n")
		except Exception,arg:
			self.stdout.write("Error: {e}\n".format(e=arg))
	def do_disconnect(self,cmd):
		"""disconnect: disconnects from server."""
		if self.client.client is None:
			self.stdout.write("Error: Not connected.\n")
			return
		self.client.disconnect()
		self.ingroup=False
	def do_create(self,cmd):
		"""create GROUP PSWD [KEYFILE]: creates and joins a group."""
		if self.ingroup:
			self.stdout.write("Error: Already in a Group!\n")
			return
		try:
			data=cmd.split(" ")
			if len(data)==2:
				name,pswd=data
				key=None
			elif len(data)==3:
				name,pswd,keypath=data
				if not os.path.isfile(keypath):
					self.stdout.write("Error: KEYPATH does not refer to a valid file!\n")
					return
				with open(keypath,"rb") as f:
					key=f.read()
			else:
				raise Exception("see except:")
		except:
			self.stdout.write("Error: Invalid Argument!\n")
			return
		s=self.client.create(name,pswd,key)
		if s:
			self.stdout.write("Group created and joined.\n")
			self.ingroup=True
			self.stdout.write("Your CID is {i}.\n".format(i=self.client.get_cid()))
		else:
			self.stdout.write("Error: Cant create Group!\n")
	def do_join(self,cmd):
		"""join GROUP PSWD: joins a group."""
		if self.ingroup:
			self.stdout.write("Error: Already in a Group!\n")
			return
		try:
			name,pswd=cmd.split(" ")
		except:
			self.stdout.write("Error: Invalid Argument!\n")
			return
		s=self.client.join(name,pswd)
		if s:
			self.stdout.write("Group joined.\n")
			self.ingroup=True
			self.stdout.write("Your CID is {i}.\n".format(i=self.client.get_cid()))
		else:
			self.stdout.write("Error: Cant join Group!\n")
	def do_leave(self,cmd):
		"""leave: leaves the group."""
		if not self.ingroup:
			self.stdout.write("Error: Not in a Group!\n")
			return
		self.client.leave()
		self.ingroup=False
	def do_ping(self,cmd):
		"""ping CID: pings groupmember with specified CID"""
		if not self.ingroup:
			self.stdout.write("Error: Not in a Group!\n")
			return
		try:
			cid=int(cmd)
		except:
			self.stdout.write("Error: Invalid Argument!\n")
			return
		self.stdout.write("Pinging...\n")
		ping=self.client.ping(cid)
		self.stdout.write("Ping to target is {p} seconds.\n".format(p=ping))
	def do_exit(self,cmd):
		"""exit: exits the program and disconnects if required."""
		if self.client.client is not None:
			self.client.disconnect()
		self.reactor.callFromThread(self.reactor.stop)
	do_close=do_EOF=do_exit
	def do_cid(self,cmd):
		"""cid: shows the CID of this client."""
		if self.client.client is None:
			self.stdout.write("Error: Not connected!\n")
			return
		cid=self.client.get_cid()
		if cid is None or not self.ingroup:
			self.stdout.write("Error: Not in a group!\n")
			return
		self.stdout.write("Your CID is {i}.\n".format(i=cid))
	do_CID=do_ID=do_id=do_get_id=do_cid
	def do_relay(self,cmd):
		"""relay PEER [LOCAL] REMOTE: relay connections to localhost:LOCAL to port REMOTE on PEER. if LOCAL is 0 or ommitted, a free port is used."""
		if self.client.client is None:
			self.stdout.write("Error: Not connected!\n")
			return
		if not self.ingroup:
			self.stdout.write("Error: Not in a group!\n")
			return
		sc=cmd.split(" ")
		try:
			peer=int(sc[0])
			if peer<0 or peer>255:
				raise Exception("See the except handler")
			if len(sc)==2:
				remote=int(sc[1])
				local=0
			elif len(sc)==3:
				local=int(sc[1])
				remote=int(sc[2])
			else:
				raise Exception("This will call the except handler.")
		except:
			self.stdout.write("Error: Invalid Argument or invalid number of arguments!\n")
			return
		p=self.client.relay(peer,remote,local)
		self.stdout.write("Now relaying port {l} to {r}.\n".format(l=p,r=remote))
	def do_list(self,cmd):
		"""shows all active connections and all relayed ports."""
		if self.client.client is None:
			self.stdout.write("Error: Not connected!\n")
			return
		if not self.ingroup:
			self.stdout.write("Error: Not in a group!\n")
			return
		stats=self.client.list()
		self.stdout.write("  Type   |From Pid |From Port| To Pid  | To Port |  Recv   |  Send   \n")
		self.stdout.write("---------+"*6+"---------\n")
		for l in stats:
			text=(("{:>9}|"*7)[:-1]).format(*l).replace("None","----")
			self.stdout.write(text+"\n")
		self.stdout.write("\n")
	def do_reserve(self,cmd):
		"""
reserve NAME CONNTYPE OUTFILE: reserves the groupname NAME and writes the key to KEYFILE.
CONNTYPE should be one either ALL (=everyone can connect to everyone) or SCO (=only connections to/from creator are allowed).
NAME needs to start with a '#'.
"""
		try:
			name,ct,of=cmd.split(" ")
			if not name.startswith("#"):
				raise Exception("see except:")
			if ct=="ALL": sco=False
			elif ct=="SCO": sco=True
			else:
				raise Exception("see except:")
		except:
			self.stdout.write("Error: Invalid Argument!\n")
			return
		key=self.client.reserve_group(name,sco)
		if not key:
			self.stdout.write("Error: cannot reserve Group!")
			return
		try:
			with open(of,"wb") as f: f.write(key)
		except:
			self.stdout.write("Error: Cant save Key!\nPlease write this lanually to {p}:\n{k}\n".format(p=of,k=key))
			return
		self.stdout.write("Group reserved.\n")
	def do_extend(self,cmd):
		"""extend KEYPATH: extends the reservation with the key in file KEYPATH."""
		kf=cmd
		if not os.path.isfile(kf):
			self.stdout.write("Error: Cannot find KEYFILE!\n")
			return
		try:
			with open(kf,"rb") as f: key=f.read()
			if len(key)==0:
				raise Exception("see except:")
		except:
			self.stdout.write("Error: Cannot read KEYFILE!\n")
			return
		nk=self.client.extend_reservation(key)
		if not nk:
			self.stdout.write("Error: Cannot extend key. Is key valid?\n")
			return
			try:
				with open(kp,"wb") as f: f.write(nk)
			except:
				self.stdout.write("Error: Cannot save new key! Please savt this to {p}:\n{k}\n".format(p=kp,k=nk))
				return
	def help_usage(self):
		"""shows a text how to use p22p."""
		helptext="""
USAGE
==========
1.) connect to server:
	When starting p22p, you dont automatically connect to a server.
	To do this, use the 'connect'-command.
	Without additional arguements, p22p will connect to {default}.
	If you want to connect to a other server, use the following syntax:
		connect PROTO://SERVER:PORT
	where PROTO is either 'ws' or 'wss'. 'wss' is a SSL/TLS connection, ws a insecure connection.
	Note that the communication between to clients is always CBC-encrypted (additionaly to other encryption methods.)
	The CBC-password will never be sent to the server.
	The Server only receives a hash of the password.

2.) join or create a Group
	p22p is using Group as Network-Namespaces.
	Each Groupmember has a unique CID. However, the CID is only unique in the Group and only unique during that clients connection.
	To create a new Group, use the 'create'-command:
		create NAME PASSWORD [KEYFILE]
	The server only receives a hash of the PASSWORD.
	Note that groupnames starting with a "#" are reserved (You cant create them except if you have the key).
	If you want to create a reserved group, pass the path to the keyfile.
	When creating a Group, you will automatically join that Group.
	
	To join a Group, use the 'join'-command:
		join NAME PSWD
	The Server only reveives a hash of the Password.

3.) relay a Port
	To relay a port from your Device to a target device, use the 'relay'-command:
		relay PEER [LOCAL] REMOTE
	If LOCAL is 0 or ommited, a free port is choosen.
	This Command will create a socket listening to Port LOCAL on your DEVICE.
	Once a connection is made to that Port, P22P will send a message to PEER, telling him to create a connection to Port REMOTE.
	All data sent trough this connection will be encrypted with the Group's Password.
	The Server only knows the hash of the password, meaning only Groupmembers know how to decrypt the Message.
	The Server knows who should receive this message and sends it to only that Client.

4.) Leaving a Group
	Once you are finished, you can leave the Group.
	This will close all connections to peers and free your CID.
	All Groupmembers will receive a message that you left the Group.
	to leave a Group, use thr 'leave'-command.

5.) Disconnecting
	If you want to disconnect from the Server, use the 'disconnect'-command.
	This will close all connections and also auto-leaves the Group (see 4.)

6.) Exiting
	To close this script, use the 'exit'-command.
	If required, the 'disconnect'-command is invoked.

7.) Additional commands
	To get a list of all aviable commands, use the 'help'-command.
	To get a description about a command, use the gollowing syntax:
		help COMMAND
	Here are some useful commands:
		ping PEER: pings the peer (not the Server.)
		list: shows a list of all connections and relayed ports. also shows some information.
		cid: shows your current CID.
""".format(default=DEFAULT_SERVER)
		self.stdout.write(helptext)

def _stop():
	"""stops the reactor."""
	try:
		reactor.callFromThread(reactor.stop)
	except ReactorNotRunning,arg:
		pass
		
if __name__=="__main__":
	atexit.register(_stop)
	reactor.addSystemEventTrigger("after","shutdown",sys.exit,(0,))
	if len(sys.argv)==1 or (len(sys.argv)==2 and ("-d" in sys.argv)):
		cmdo=P22PClientConsole(reactor)
		reactor.callInThread(cmdo.cmdloop)
		reactor.run()
	else:
		if "-d" in sys.argv: sys.argv.remove("-d")
		def _to_portlist(arg):
			try:
				peer,local,remote=arg.split(":")
				peer,local,remote=int(peer),int(local),int(remote)
				if peer>255 or peer<0 or local<0 or remote<0:
					raise Exception("see except:")
				return (peer,local,remote)
			except:
				raise argparse.ArgumentTypeError("Invalid format for portlist!")
		parser=argparse.ArgumentParser(description="Connect to the P22P-Network")
		parser.add_argument("-a",action="store",dest="address",default=DEFAULT_SERVER,help="address of server")
		parser.add_argument("command",action="store",help="What to do",choices=("create","join"))
		parser.add_argument("name",action="store",help="Name of Group")
		parser.add_argument("pswd",action="store",help="Password for Group")
		parser.add_argument("-k",action="store",dest="keyfile",help="Keyfile used for creating the Group")
		parser.add_argument("-n",action="store_false",dest="extend",help="do not extend keyfile")
		#parser.add_argument("-t",action="store",dest="type",help="Type of Network",choices=("ALL","SCO"))
		parser.add_argument("-p",action="store",dest="conns",help="ports to relay as PEER:LOCAL:REMOTE",nargs="+",type=_to_portlist,default=[],metavar="CONN")
		parser.add_argument("-w",nargs="+",type=int,dest="whitelist",default=None,help="ports to whitelist (default: all)",action="store",metavar="PORT")
		ns=parser.parse_args()
		if ns.keyfile is not None:
			if not os.path.isfile(ns.keyfile):
				print "Error: can not find file '{k}'!".format(k=ns.keyfile)
				sys.exit(1)
			with open(ns.keyfile,"rb") as f:
				key=f.read()
		else:
			key=None
		def handle_commands(ns,key):
			try:
				client=P22PClient(None,reactor)
				client.connect(ns.address)
				client.set_whitelist(ns.whitelist)
				if ns.command=="create":
					if ns.extend and (key is not None):
						nk=client.extend_reservation(key)
						if nk:
							with open(ns.keyfile,"wb") as f:
								f.write(nk)
							key=nk
					state=client.create(ns.name,ns.pswd,key)
					if not state:
						print "Error: Can not create Group!"
						sys.exit(1)
				elif ns.command=="join":
					state=client.join(ns.name,ns.pswd)
					if not state:
						print "Error: Can not join Group!"
						sys.exit(1)
					for peer,local,remote in ns.conns:
						client.relay(peer,remote,local)
			except:
				try:
					_stop()
				finally:
					raise
		reactor.callInThread(handle_commands,ns,key)
		reactor.run()
