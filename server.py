# coding: utf-8
"""The p22p Server."""
import socket,select,struct,os

#constants
VERSION=0.1
DEBUG=False
TIMEOUT=None
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

class P22pServer(object):
	"""The p22p-Server."""
	def __init__(self):
		self.s=None
		self.cmid=0
		self.conns={}
		self.id2s={}
	def get_new_id(self):
		"""returns a new id."""
		cid=self.cmid
		self.cmid+=1
		return cid
	def add_s(self,s):
		"""adds a socket to the select-loop."""
		try:
			s.settimeout(TIMEOUT)
			pv=struct.unpack("!d",recv_exact(s,8))[0]
			if pv!=VERSION:
				s.send("F")
				s.close()
			s.send("T")
			nid=self.get_new_id()
			s.send(struct.pack("!Q",nid))
			pwlength=struct.unpack("!Q",recv_exact(s,8))[0]
			hpw=recv_exact(s,pwlength)
			self.id2s[nid]=s
			self.conns[s]={"id":nid,"peer":None,"pswd":hpw}
		except Exception,arg:
			if DEBUG: raise
			else:
				pass
			try:
				self.remove_s(s)
			except:
				pass
	def remove_s(self,s):
		"""removes a socket from the select-loop."""
		try:
			cid=self.conns[s]["id"]
			pid=self.conns[s]["peer"]
			del self.conns[s]
			del self.id2s[cid]
			if pid is not None:
				self.send_disconnect(pid)
		except Exception,arg:
			if DEBUG:
				raise
	def send_disconnect(self,cid):
		"""tells the client cid that its peer disconnected."""
		s=self.id2s[cid]
		msg=ID_CTRL+"DISCONNECT"
		try: s.send(struct.pack("!Q",len(msg))+msg)
		except Exception,arg:
			if DEBUG:
				raise
		self.conns[s]["peer"]=None
	def loop(self):
		"""the mainloop of the server."""
		assert self.s is not None
		try:
			while True:
				crs=[self.s]+self.conns.keys()
				cws=[]
				cxs=crs
				nrs,nws,nxs=select.select(crs,cws,cxs,None)
				#handle exceptions
				if self.s in nxs:
					raise RuntimeError,"Error in listening socket."
				for s in nxs:
					self.remove_s(s)
					if s in nrs:
						nrs.remove(s)
					if s in nws:
						nws.remove(s)
				#handle readable sockets
				#first check for new conns.
				if self.s in nrs:
					conn,addr=self.s.accept()
					self.add_s(conn)
				#now handle aviable data
				for s in nrs:
					try:
						if s is self.s: continue
						ldata=recv_exact(s,8)
						length=struct.unpack("!Q",ldata)[0]
						data=recv_exact(s,length)
						if data.startswith(ID_MSG) or data.startswith(ID_PPC):
							tosend=ldata+data
							pid=self.conns[s]["peer"]
							if pid is None:
								continue
							peer=self.id2s[pid]
							peer.send(tosend)
						elif data.startswith(ID_CTRL):
							payload=data[1:]
							if payload=="CLOSE":
								self.remove_s(s)
								if s in nws:
									nws.remove(s)
								continue
							elif payload.startswith("CONN "):
								pid=struct.unpack("!Q",payload[5:13])[0]
								pswd=payload[13:]
								if not pid in self.id2s.keys():
									s.send("F")
									continue
								peer=self.id2s[pid]
								if self.conns[peer]["peer"] is not None:
									s.send("F")
									continue
								if self.conns[peer]["pswd"]!=pswd:
									s.send("F")
									continue
								cid=self.conns[s]["id"]
								self.conns[peer]["peer"]=cid
								self.conns[s]["peer"]=pid
								s.send("T")
								msg=ID_CTRL+"PAIR "+struct.pack("!Q",cid)
								tosend=struct.pack("!Q",len(msg))+msg
								peer.send(tosend)
								continue
						else:
							continue
					except Exception,arg:
						if DEBUG:
							raise
						self.remove_s(s)
		finally:
			if self.s is not None:
				self.s.close()
	def run(self,addr):
		"""runs the server"""
		self.s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,0)
		self.s.bind(addr)
		self.s.listen(1)
		self.loop()

if __name__=="__main__":
	import os
	print "starting server..."
	HOST=os.getenv("OPENSHIFT_PYTHON_IP","0.0.0.0")
	PORT=8000
	server=P22pServer()
	server.run((HOST,PORT))