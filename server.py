# coding: utf-8
"""The p22p-server script/module. requires autobahn+twisted."""
import sys,struct,base64,os
from autobahn.twisted import websocket
import twisted.python
import twisted.internet
from twisted.internet.defer import inlineCallbacks

#constants
VERSION=0.2
PROTOCOLS=["P22P-WS-P"]
DEBUG=("-d" in sys.argv)
ID_CTRL="\x01"

#communication

class Group(object):
	"""A Group manages the communication between clients"""
	def __init__(self,srv,name,pswd):
		self.srv=srv
		self.name=name
		self.pswd=pswd
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
		if len(self.members.keys())<=0:
			#remove this group
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
	@inlineCallbacks
	def onMessage(self,msg,is_binary):
		"""handles a message."""
		#print "got message: "+repr(msg)
		if not self.did_handshake:
			#we do our handshake here
			if len(msg)!=8:
				self.sendClose()
			else:
				pv= yield struct.unpack("!d",msg)[0]
				if pv!=VERSION:
					yield self.sendMessage("F",True)
					yield self.sendClose()
				else:
					yield self.sendMessage("T",True)
					self.did_handshake=True
		elif not is_binary:
			pass#we cant do anything here
		else:
			idb=msg[0]
			payload= yield msg[1:]
			if idb==ID_CTRL:
				if payload=="LEAVE":
					if self.group is None:
						pass
					else:
						yield self.leave_group()
				elif payload.startswith("JOIN"):
					if self.group is not None:
						yield self.leave_group()
					gn,pswd=payload[4:].split("\x00")
					gn,pswd= yield base64.b64decode(gn),base64.b64decode(pswd)
					if gn in self.factory.groups.keys():
						group=self.factory.groups[gn]
						state=yield group.join(self,pswd)
						if state is False:
							yield self.sendMessage(ID_CTRL+"E:NOJOIN",True)
						else:
							self.group=group
							self.cid=state
							yield self.sendMessage(ID_CTRL+"I:JOIN"+chr(self.cid),True)
					else:
						yield self.sendMessage(ID_CTRL+"E:NOJOIN",True)
				elif payload=="DISCONNECT":
					yield self.leave_group()
					yield self.sendClose()
				elif payload.startswith("CREATE"):
					if self.group is not None:
						yield self.leave_group()
					gn,pswd= yield payload[6:].split("\x00")
					gn,pswd= yield base64.b64decode(gn),base64.b64decode(pswd)
					if gn in self.factory.groups.keys():
						yield self.sendMessage(ID_CTRL+"E:NOCREATE",True)
					else:
						self.factory.groups[gn]=Group(self.factory,gn,pswd)
						self.cid= yield self.factory.groups[gn].join(self,pswd)
						yield self.sendMessage(ID_CTRL+"I:CREATE"+chr(self.cid),True)
			else:
				if self.group is None:
					pass
				else:
					who=ord(payload[0])
					yield self.group.send_to(self.cid,who,idb+payload[1:])
				

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
	#setup (with Openshift compatiblity)
	IP=os.getenv("OPENSHIFT_DIY_IP","0.0.0.0")
	PORT=int(os.getenv("OPENSHIFT_DIY_PORT",8080))
	#logging
	twisted.python.log.startLogging(sys.stdout)
	#server
	server=P22PServerFactory()
	server.protocol=P22PServerProtocol
	#run
	reactor=twisted.internet.reactor#this should be a reference, right?
	reactor.listenTCP(PORT,server,interface=IP)
	reactor.run()
