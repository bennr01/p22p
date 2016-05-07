# coding: utf-8
"""The p22p client."""
import socket,select,struct,cmd,hashlib,sys,threading,os,time

#constants
VERSION=0.1
DEFAULT_SERVER="www.p22p-bennr01.rhcloud.com:8000"
BUFFERSIZE=8192
SELECT_TIMEOUT=0.05
ID_CTRL="\x01"
ID_MSG="\x02"
ID_PPC="\x03"

def recv_exact(s,nbytes):
	"""receives exact nbytes from s."""
	if os.name=="nt":
		#windows
		tr=nbytes
		ret=""
		while True:
			data=s.recv(tr)
			tr-=len(data)
			ret+=data
			if tr<=0:
				return ret
	else:
		return s.recv(nbytes,socket.MSG_WAITALL)

def hash_pswd(pswd):
	return hashlib.sha384(pswd).digest()

class CommunicationError(IOError):
	pass

class _FakeLock(object):
	"""A fake-implementation of threading.Lock, used for testing."""
	def acquire(self):
		pass
	def release(self):
		pass
	def locked(self):
		return False

class P22pClient(object):
	def __init__(self):
		self.s=None
		self.cid=None
		self.pid=None
		self.pswd=None
		self.connected=False
		self.ispairer=False
		self.chid=0
		self.conns={}
		self.id2s={}
		self.pingresult=None
		self.pingstart=None
		self.connlock=_FakeLock()#threading.Lock()
	def get_new_id(self):
		"""returns a new id for a channel"""
		if self.ispairer and self.chid%2==0: self.chid+=1#ensure ids are unique
		n=self.chid
		self.chid+=2
		return n
	def connect(self,addr):
		"""connects the client to a p22p-server"""
		assert not self.connected,"already conncted!"
		assert self.s is None,"already connected!"
		assert self.pswd is not None,"Password not set!"
		self.s=socket.create_connection(addr,10)
		self.s.settimeout(10)
		self.s.send(struct.pack("!d",VERSION))
		answ=recv_exact(self.s,1)
		if answ!="T":
			try: self.s.close()
			except: pass
			raise CommunicationError,"Version Mismatch!"
		idd=recv_exact(self.s,8)
		self.cid=struct.unpack("!Q",idd)[0]
		hp=hash_pswd(self.pswd)
		ld=struct.pack("!Q",len(hp))
		self.s.send(ld+hp)
		self.s.settimeout(None)
		self.connected=True
		self.run()
	def _dispatch(self,idb,msg):
		"""sends a message msg of type idb to server"""
		assert self.connected,"not connected!"
		tosend=idb+msg
		length=len(tosend)
		packed=struct.pack("!Q",length)
		self.s.send(packed+tosend)
	def on_disconnect(self):
		"""called on disconnect (either peer or server)"""
		for s in self.conns.keys():
			try: s.close()
			except: pass
		#self.connlock.acquire()
		self.conns={}
		self.id2s={}
		self.chid=0
		self.pid=None
		self.ispairer=False
		#self.connlock.release()
	def pair(self,pid,pswd):
		"""pairs with peer pid."""
		assert self.connected,"not connected!"
		assert self.pid is None,"already paired!"
		hp=hash_pswd(pswd)
		self._dispatch(ID_CTRL,"CONN "+struct.pack("!Q",pid)+hp)
		answ=recv_exact(self.s,1)
		if answ!="T":
			return False
		self.pid=pid
		self.ispairer=True
		return True
	def disconnect(self):
		"""disconnects from server"""
		self._dispatch(ID_CTRL,"CLOSE")
		try:
			self.s.close()
		except:
			pass
		self.s=None
		self.pswd=None
		self.on_disconnect()
		self.connected=False
	def loop(self):
		assert self.connected,"not connected!"
		try:
			while self.connected:
				self.connlock.acquire()
				trs=[self.s]+self.conns.keys()
				self.connlock.release()#release while waiting on select.select
				tws=[]
				txs=trs
				nrs,nws,nxs=select.select(trs,tws,txs,SELECT_TIMEOUT)
				self.connlock.acquire()
				for s in nxs:
					if s is self.s:
						self.on_disconnect()
						raise CommunicationError,"Error in server-connection."
					if s in nrs:
						nrs.remove(s)
					if s in nws:
						nws.remove(s)
					if self.conns[s]["type"]=="c":
						chid=self.conns[s]["id"]
						del self.id2s[chid]
						self._dispatch(ID_PPC,"CLOSE "+struct.pack("!Q",chid))
					try:
						s.close()
					except: pass
					del self.conns[s]
				for s in nrs:
					if s is self.s:
						ldata=recv_exact(self.s,8)
						length=struct.unpack("!Q",ldata)[0]
						data=recv_exact(self.s,length)
						idb=data[0]
						payload=data[1:]
						if idb==ID_CTRL:
							if payload=="DISCONNECT":
								self.on_disconnect()
								nws=[]
								break
							elif payload.startswith("PAIR "):
								self.pid=struct.unpack("!Q",payload[5:])[0]
							else:
								pass
						elif idb==ID_PPC:
							if payload.startswith("BRIDGE "):
								packed=payload[7:]
								chid,port=struct.unpack("!QQ",packed)
								s=socket.socket()
								try:
									s.connect(("localhost",port))
									s.settimeout(None)
									self.id2s[chid]=s
									localport=s.getsockname()[1]
									self.conns[s]={"id":chid,"type":"c","send":0,"recv":0,"target":localport}
								except:
									self._dispatch(ID_PPC,"CLOSE "+struct.pack("!Q",chid))
							elif payload.startswith("CLOSE "):
								chid=struct.unpack("!Q",payload[6:])[0]
								s=self.id2s[chid]
								del self.conns[s]
								del self.id2s[chid]
								s.close()
							elif payload=="PING":
								self._dispatch(ID_PPC,"PINGANSW")
							elif payload=="PINGANSW":
								if self.pingstart is not None:
									self.pingresult=time.time()-self.pingstart
							else:
								pass
						elif idb==ID_MSG:
							chid=struct.unpack("!Q",payload[:8])[0]
							msg=payload[8:]
							if chid not in self.id2s.keys():
								continue
							local=self.id2s[chid]
							local.send(msg)
							self.conns[local]["recv"]+=len(msg)
						else:
							pass
					else:
						if self.conns[s]["type"]=="c":
							chid=self.conns[s]["id"]
							data=s.recv(BUFFERSIZE)#NO FLAGS HERE. Maybe add timeout and send nothing if exceeded?
							if len(data)==0:
								#close this sockets
								if s in nws:
									nws.remove(s)
									chid=self.self.conns[s]
									del self.id2s[chid]
									del self.conns[s]
									try:
										s.close()
									except:
										pass
									self._dispatch(ID_PPC,"CLOSE "+struct.pack("!Q",chid))
									continue
							self._dispatch(ID_MSG,struct.pack("!Q",chid)+data)
							self.conns[s]["send"]+=len(data)
						else:
							new,addr=s.accept()
							new.settimeout(None)
							self.conns[s]["got"]+=1
							chid=self.get_new_id()
							port=self.conns[s]["port"]
							self.conns[new]={"id":chid,"type":"c","target":port,"recv":0,"send":0}
							self.id2s[chid]=new
							self._dispatch(ID_PPC,"BRIDGE "+struct.pack("!QQ",chid,port))
				for s in nws:
					pass
				self.connlock.release()
		except Exception,arg:
			#silently ignore errors after disconnect
			if self.connected:
				raise
		finally:
			try:
				self.s.close()
				self.on_disconnect()
			except:
				pass
			self.connected=False
	def relay_port(self,port):
		"""relays port as server. returns the port opened localy"""
		s=socket.socket()
		s.bind(("localhost",0))
		lp=s.getsockname()[1]
		s.listen(1)
		self.connlock.acquire()
		self.conns[s]={"type":"l","port":port,"got":0}
		self.connlock.release()
		return lp
	def close(self):
		"""closes the server"""
		self.disconnect()
	def run(self):
		"""starts the background thread."""
		assert self.connected,"not connected!"
		thr=threading.Thread(name="p22p Relay-Thread",target=self.loop)
		thr.daemon=True
		thr.start()
	def get_info(self):
		"""returns a list of tuples of (ID,type,port,target)"""
		ret=[]
		self.connlock.acquire()
		for s in self.conns.keys():
			if s is self.s:
				continue
			info=self.conns[s]
			if info["type"]=="l":
				ty="L2R"
				port=s.getsockname()[1]
				target=info["port"]
				ID=None
				send=None
				recv=info["got"]
			else:
				ty="R2L"
				port=s.getpeername()[1]
				target=info["target"]
				ID=info["id"]
				send=info["send"]
				recv=info["recv"]
			ret.append((ID,ty,port,target,recv,send))
		self.connlock.release()
		return ret
	def ping(self):
		"""sends a ping-message and wait for its answer. returns time passed is seconds."""
		self.pingresult=None
		self.pingstart=time.time()
		self._dispatch(ID_PPC,"PING")
		while self.pingresult is None:
			time.sleep(0.1)
		self.pingstart=None
		return self.pingresult

#========================================================================

class Console(cmd.Cmd):
	"""A controll console. Used in single-file mode"""
	prompt="(p22p)"
	intro="p22p-Client v{v} For help, type 'help' or '?'.".format(v=VERSION)
	use_rawinput=True
	client=P22pClient()
	def help_security(self):
		"""prints help about the security."""
		print """SECURITY
================
While p22p doesnt allow execution of code on your machine, all socket-
connections are done as localhost.
This means:
	-they may pass-by your firewall
	-some programs only accepts local requests to improve security. This wont work with p22p-request
Some other security-problems are:
	-no explicit port enabling: your peer can connect to any of your open ports, including (if any) active shells.
	-no notification about beeing paired.
"""
	def do_connect(self,cmd):
		"""connect PSWD [IP:PORT]: connects to target central server."""
		if self.client.connected:
			print "Already connected! Use disconnect to disconnect"
			return
		try:
			data=cmd.split(" ")
			if len(data)==1:
				pswd=data
				cmd=DEFAULT_SERVER
			elif len(data)==2:
				pswd,cmd=data
			else:
				raise Exception,"This will cause the except-clausel to be executed"
		except:
			print "Invalid Argument!"
			return
		self.client.pswd=pswd
		try: ip,port=cmd.split(":")
		except:
			print "Invalid argument!"
			return
		print "Connecting..."
		try:
			self.client.connect((ip,port))
		except Exception,arg:
			print "Connection failed! Reason: {a}".format(a=arg)
			return
		print "Connected. Your CID is {i}.".format(i=self.client.cid)
	def do_disconnect(self,cmd):
		"""disconnect: disconnects from the central server."""
		if not self.client.connected:
			print "Not connected!"
			return
		self.client.close()
		print "Disconnected."
	def do_exit(self,cmd):
		"""exit: exits the script, disconnecting if required."""
		if self.client.connected:
			self.client.close()
		sys.exit(0)
	def do_list(self,cmd):
		"""list: lists all connections and relayed ports."""
		if self.client.pid is None:
			print "Not connected/paired!"
			return
		info=self.client.get_info()
		print "Connections and relayed ports"
		print "|   ID   |  Type  | Local  | Remote |  Recv  |  Sent  |"
		print "+--------+--------+--------+--------+--------+--------+"
		for t in info:
			print "|"+("{:<8}|"*6).format(*t)
		#for i in info:
		#	print " | ".join([str(e) for e in i])
	def do_relay(self,cmd):
		"""relay PORT: relays a port to peer."""
		try:
			port=int(cmd)
		except:
			print "Invalid/Missing Argument!"
			return
		if self.client.pid is None:
			print "Not connected/paired!"
			return
		print "Initiating relaying..."
		try:
			np=self.client.relay_port(port)
		except Exception,arg:
			print "Failed to relay to peer Port {p}! Reason: {a}".format(p=port,a=arg)
			return
		print "Now relaying {local} to {target}.".format(local=np,target=port)
	def do_pair(self,cmd):
		"""pair PEER PSWD: pairs the client with target peer. PSWD must be the pswd of the other client."""
		if not self.client.connected:
			print "Not connected!"
			return
		if self.client.pid is not None:
			print "Already paired!"
			return
		try:
			pid,pswd=cmd.split(" ")
			pid=int(pid)
		except:
			print "Invalid/missing Argument!"
			return
		print "Pairing..."
		state=self.client.pair(pid,pswd)
		if state:
			print "Paired!"
		else:
			print "Pairing failed!"
	def do_id(self,cmd):
		"""id: prints your own CID and the CID of your Peer."""
		if not self.client.connected:
			print "Not connected!"
			return
		if self.client.pid is not None:
			m="The CID of your peer is {n}.".format(n=self.client.pid)
		else:
			m=""
		print "Your CID is {i}. {m}".format(i=self.client.cid,m=m)
	do_CID=do_ID=do_get_id=do_id
	def do_ping(self,cmd):
		"""ping: pings your peer (not the server!)."""
		if self.client.pid is None:
			print "Not connected/paired!"
			return
		print "Pinging..."
		res=self.client.ping()
		print "Ping is {p} seconds.".format(p=res)

if __name__=="__main__":
	Console().cmdloop()