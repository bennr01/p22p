# coding: utf-8
"""The p22p-server script/module. requires autobahn+twisted."""
import sys,struct,base64,os,hmac,time,hashlib,anydbm,atexit
from autobahn.twisted import websocket
import twisted.python
import twisted.internet
from twisted.internet.defer import inlineCallbacks

#speedup modules
try:
	import ujson as json
except ImportError:
	import json

#constants
VERSION=0.3
PROTOCOLS=["P22P-WS-P"]
RESERVATION_LIFETIME=60*60*24*90#90 days
DB_PATH=os.path.join(os.getenv("OPENSHIFT_DATA_DIR",os.getcwd()),"rgk.dbm")
SECRETPATH=os.path.join(os.getenv("OPENSHIFT_DATA_DIR",os.getcwd()),"secret.dat")
DEBUG=("-d" in sys.argv)
ID_CTRL="\x01"

#signing system for reserved domain

def load_secret(path=SECRETPATH):
	if os.path.exists(path):
		with open(path,"rb") as f:
			return f.read()
	else:
		length=25+ord(os.urandom(1))
		secret=os.urandom(length)
		with open(path,"wb") as f:
			f.write(secret)
		return secret

class ReservedGroupKey(object):
	"""This class represents a sicned key for restricting creation permissions for specific domains."""
	secret=load_secret()
	check_sign=("name","expires")
	def __init__(self,info):
		assert isinstance(info,dict)
		self.info=info
	def __getitem__(self,key):
		return self.info[key]
	def __nonzero__(self):
		return True
	@classmethod
	def load(cls,data):
		try:
			des=json.loads(data)
			des["name"]=str(des["name"])
			des["sign"]=str(des["sign"])
		except:
			return None
		ret=cls(des)
		if not ret.is_valid():
			return None
		return ret
	def save(self):
		return json.dumps(self.info)
	def is_valid(self):
		try:
			orgsign=self.info["sign"]
			tocheck=[]
			for key in self.check_sign:
				tocheck.append(self.info[key])
			ser=json.dumps(tocheck)
			sign=hmac.new(self.secret,ser,hashlib.sha256).hexdigest()
			a=(sign==orgsign)
			b=(self.info["expires"]>time.time())
			return (a and b)
		except KeyError:
			return False
	@classmethod
	def new(cls,name,sco=True):
		expires=time.time()+RESERVATION_LIFETIME
		ser=json.dumps([name,expires])
		sign=hmac.new(cls.secret,ser,hashlib.sha256).hexdigest()
		cd={"name":name,"sign":sign,"expires":expires,"sco":sco}
		db=anydbm.open(DB_PATH,"c")
		db[name]=str(expires)
		db.close()
		return cls(cd).save()
	def extend_key(self):
		return self.new(self.info["name"],self.info["sco"])
	@staticmethod
	def check_existence(name):
		db=anydbm.open(DB_PATH,"c")
		i=(name in db)
		db.close()
		return i
	@staticmethod
	def is_aviable(name):
		db=anydbm.open(DB_PATH,"c")
		if not name in db:
			db.close()
			return True
		exp=eval(db[name])
		ia=(exp<time.time())
		if ia:
			del db[name]
		db.close()
		return ia
	@staticmethod
	def clear_expired():
		db=anydbm.open(DB_PATH,"c")
		t=time.time()
		for k,v in db.iteritems():
			if v<t:
				del db[k]
		db.close()

#communication

class Group(object):
	"""A Group manages the communication between clients"""
	def __init__(self,srv,name,pswd,sco=False):
		self.srv=srv
		self.name=name
		self.pswd=pswd
		self.sco=sco
		self.destroying=False
		self.members={}
		self.c2id={}
	def new_cid(self):
		"""returns a new client id or None"""
		cids=self.members.keys()#only check one time to improve perfomance
		for i in xrange(256):
			if i not in cids:
				return i
		return False
	def join(self,client,pswd):
		"""check pswd and add client as member of this group if pswd match. return his new id if joined else False."""
		if pswd!=self.pswd:
			return False
		if len(self.members.keys())>=256:
			#no ids left
			return False
		nid=self.new_cid()
		if nid is False:
			return False
		self.members[nid]=client
		self.c2id[client]=nid
		client.group=self
		return nid
	def leave(self,client):
		"""remove client from group"""
		cid=self.c2id[client]
		self.send_leave(cid)
		del self.c2id[client]
		del self.members[cid]
		if len(self.members.keys())<=0 or (self.sco and cid==0):
			#remove this group if no clients are connected or if the creator left in sco-mode
			self.destroy()
	def destroy(self):
		"""removes this group."""
		if self.destroying:
			return #otherwise keyerror
		self.destroying=True
		self.pswd=None#disable joining
		for c in self.c2id.keys():
			c.sendClose()#kick from server
		del self.srv.groups[self.name]
	def send_leave(self,cid):
		"""tells the members that this client left the group."""
		for client in self.c2id.keys():
			if self.c2id[client]==cid:
				continue
			client.send_to_client(ID_CTRL+"LEAVE"+chr(cid))
	def send_to(self,cid,pid,msg):
		"""sends a message to client pid."""
		if pid not in self.members.keys():
			return
		if (cid!=0 and pid!=0) and self.sco:
			#disallow communication between clients in sco-mode
			return
		client=self.members[pid]
		idb,payload=msg[0],msg[1:]
		client.send_to_client(idb+chr(cid)+payload)

class P22PServerProtocol(websocket.WebSocketServerProtocol):
	"""The Protocol handles the communication and the connection."""
	def __init__(self,*args,**kwargs):
		nargs=tuple([self]+list(args))
		apply(websocket.WebSocketServerProtocol.__init__,nargs,kwargs)
		self.group=None
		self.cid=None
		self.s2g={}
		self.g2s={}
		self.did_handshake=False
		self.did_reserve=False
	def leave_group(self):
		"""leaves the group"""
		if self.group is None:
			return
		self.group.leave(self)
		self.group=None
		self.cid=None
		#self.did_handshake=False#why is this here? lets comment it out
		self.g2s={}
		self.s2g={}
	def send_to_client(self,msg):
		"""sends a message to this client"""
		self.sendMessage(msg,True)
	def processHandshake(self):
		"""for Openshift proxy compatibility, replace 'HEAD'-Method with 'GET'-Method"""
		if (not "GET" in self.data) and ("HEAD" in self.data):
			self.data=self.data.replace("HEAD","GET",1)
		websocket.WebSocketServerProtocol.processHandshake(self)
	def onClose(self,wasclean,code,reason):
		"""called when the connection was closed."""
		if self.group is not None:
			self.leave_group()
	#@inlineCallbacks
	def onMessage(self,msg,is_binary):
		"""handles a message."""
		#print "got message: "+repr(msg)
		if not self.did_handshake:
			#we do our handshake here
			if len(msg)!=8:
				self.sendClose()
			else:
				pv=struct.unpack("!d",msg)[0]
				if pv!=VERSION:
					self.sendMessage("F",True)
					self.sendClose()
				else:
					self.sendMessage("T",True)
					self.did_handshake=True
		elif not is_binary:
			pass#we cant do anything here
		else:
			idb=msg[0]
			payload=msg[1:]
			if idb==ID_CTRL:
				if payload=="LEAVE":
					if self.group is None:
						pass
					else:
						self.leave_group()
				elif payload.startswith("JOIN"):
					if self.group is not None:
						self.leave_group()
					gn,pswd=payload[4:].split("\x00")
					gn,pswd=base64.b64decode(gn),base64.b64decode(pswd)
					if gn in self.factory.groups.keys():
						group=self.factory.groups[gn]
						state=group.join(self,pswd)
						if state is False:
							self.sendMessage(ID_CTRL+"E:NOJOIN",True)
						else:
							self.group=group
							self.cid=state
							self.sendMessage(ID_CTRL+"I:JOIN"+chr(self.cid),True)
					else:
						self.sendMessage(ID_CTRL+"E:NOJOIN",True)
				elif payload=="DISCONNECT":
					self.leave_group()
					self.sendClose()
				elif payload.startswith("CREATE"):
					if self.group is not None:
						self.leave_group()
					ci=payload[6:].split("\x00")
					if len(ci)==2:
						gn,pswd,gk= ci[0],ci[1],None
					else:
						gn,pswd,gk=ci[0],ci[1],ci[2]
					gn,pswd=base64.b64decode(gn),base64.b64decode(pswd)
					cont=True
					sco=True
					if gk is not None:
						gk=base64.b64decode(gk)
						gk=ReservedGroupKey.load(gk)
						if gk is None:
							#invalid sign
							self.sendMessage(ID_CTRL+"E:NOCREATE",True)
							cont=False
						elif gk["name"]!=gn:
							self.sendMessage(ID_CTRL+"E:NOCREATE",True)
							cont=False
						else:
							sco=gk["sco"]
					if not cont:
						pass
					elif gk:
						if gn in self.factory.groups.keys():
							#only this client has the permission to have such a group, destroy the old one
							self.factory.groups[gn].destroy()
						self.factory.groups[gn]=Group(self.factory,gn,pswd,sco)
						self.cid=self.factory.groups[gn].join(self,pswd)
						self.sendMessage(ID_CTRL+"I:CREATE"+chr(self.cid),True)
					elif gn in self.factory.groups.keys() or gn.startswith("#"):
						self.sendMessage(ID_CTRL+"E:NOCREATE",True)
					else:
						self.factory.groups[gn]=Group(self.factory,gn,pswd,False)
						self.cid=self.factory.groups[gn].join(self,pswd)
						self.sendMessage(ID_CTRL+"I:CREATE"+chr(self.cid),True)
				elif payload.startswith("RESERVE"):
					if self.did_reserve:
						self.sendMessage(ID_CTRL+"E:NORESERVE",True)
					else:
						tup=payload[7:]
						name,sco=tup[:-1],tup[-1]=="T"
						ia=ReservedGroupKey.is_aviable(name)
						if not (ia and name.startswith("#")):
							self.sendMessage(ID_CTRL+"E:NORESERVE",True)
						else:
							gk=ReservedGroupKey.new(name,sco)
							self.sendMessage(ID_CTRL+"I:RESERVE"+gk,True)
							self.did_reserve=True
				elif payload.startswith("EXTEND"):
					certdata=payload[6:]
					cert=ReservedGroupKey.load(certdata)
					if cert:
						nc=cert.extend_key()
						self.sendMessage(ID_CTRL+"I:EXTEND"+nc,True)
					else:
						self.sendMessage(ID_CTRL+"E:NOEXTEND",True)
			else:
				if self.group is None:
					pass
				else:
					who=ord(payload[0])
					self.group.send_to(self.cid,who,idb+payload[1:])
				

class P22PServerFactory(websocket.WebSocketServerFactory):
	"""The Factory constructs the protocol and contains shared data"""
	def __init__(self,*args,**kwargs):
		nargs=tuple([self]+list(args))
		kwargs["debug"]=DEBUG
		kwargs["protocols"]=PROTOCOLS
		apply(websocket.WebSocketServerFactory.__init__,nargs,kwargs)
		self.groups={}

#single file code
if __name__=="__main__":
	#setup
	IP=os.getenv("OPENSHIFT_DIY_IP","0.0.0.0")
	PORT=int(os.getenv("OPENSHIFT_DIY_PORT",8080))
	#logging
	twisted.python.log.startLogging(sys.stdout)
	#free space in db
	ReservedGroupKey.clear_expired()
	#server
	server=P22PServerFactory()
	server.protocol=P22PServerProtocol
	#run
	reactor=twisted.internet.reactor#this should be a reference, right?
	reactor.listenTCP(PORT,server,interface=IP)
	reactor.run()