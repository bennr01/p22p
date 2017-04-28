"""P22P v0.4 client GUI"""
import Tkinter
import tkMessageBox
import tkFileDialog

from twisted.internet import reactor, tksupport, defer, endpoints, task

import p22p
import p22p.common
import p22p.client


DEFAULT_SERVER = p22p.common.DEFAULT_SERVER + ":" + str(p22p.common.DEFAULT_PORT)


class AbortError(Exception):
    """An Exception raised when something is aborted"""
    pass


class P22PGui(object):
    """The GUI for the P22P client"""
    def __init__(self):
        self.protocol = None
        self.pingloop = None
        self.updateloop = None
        self.updatelist = []
        self.channels = []
        self.relayed_ports = []
        self.frame_entries = []
        
        self.screen = Tkinter.Tk()
        tksupport.install(self.screen)
        self.screen.title("P22P Client")
        self.screen.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.status_bar = Tkinter.Frame(self.screen, relief=Tkinter.RAISED)
        self.scrollframeframe = Tkinter.Frame(self.screen)
        self.scrollframe = VerticalScrolledFrame(self.scrollframeframe)
        self.frame = Tkinter.Frame(self.scrollframe.interior, relief=Tkinter.SUNKEN, borderwidth=1)
        
        self.status_bar.pack(anchor=Tkinter.N, fill=Tkinter.X, side=Tkinter.TOP)
        self.scrollframeframe.pack(anchor=Tkinter.N, fill=Tkinter.BOTH, side=Tkinter.BOTTOM, expand=True)
        self.scrollframe.pack(anchor=Tkinter.N, fill=Tkinter.BOTH, side=Tkinter.BOTTOM, expand=True)
        self.frame.pack(anchor=Tkinter.N, fill=Tkinter.BOTH, side=Tkinter.TOP, expand=True)

        self.setup_menu()
        self.setup_status_bar()

        self.screen.bind_all("<Enter>", self.scrollframe.bind_mousewheel)
        self.screen.bind_all("<Leave>", self.scrollframe.unbind_mousewheel)
        self.screen.bind_all("<MouseWheel>", self.scrollframe.on_mousewheel_change)

        self.set_status("not connected")

    def on_close(self):
        """called when the window should be closed"""
        self.ask_quit()

    def ask_quit(self):
        """asks the user if he wants to quit."""
        if tkMessageBox.askokcancel(title="Quit?", message="Are you sure you want to quit? All Connections will be closed."):
            self.quit()

    def show_connect_window(self):
        """shows the window asking for the server information"""
        d = defer.Deferred()
        d.addCallback(self.connected)
        d.addErrback(self.handle_acw_error)
        acw = AskConnectWindow(self, d)

    def handle_acw_error(self, f):
        """handles an error in the AskConnectWindow"""
        # f.trap(AbortError)
        # self.quit()
        pass

    def connected(self, protocol):
        self.protocol = protocol
        self.set_status("connected")
        self.start_pinging()
        self.start_updates()

    def setup_window(self):
        """setups the window"""
        pass

    def setup_menu(self):
        """creates the menu"""
        self.root_menu = Tkinter.Menu(self.screen)
        self.screen.config(menu=self.root_menu)

        self.main_menu = Tkinter.Menu(self.root_menu)
        self.main_menu.add_command(label="Connect", command=self.connect)
        self.main_menu.add_command(label="Disconnect", command=self.disconnect)
        self.main_menu.add_command(label="Quit", command=self.ask_quit)
        self.root_menu.add_cascade(label="P22P", menu=self.main_menu)

        self.group_menu = Tkinter.Menu(self.root_menu)
        self.group_menu.add_command(label="Create group", command=self.create_group)
        self.group_menu.add_command(label="Join group", command=self.join_group)
        self.group_menu.add_command(label="Reserve group", command=self.reserve_group)
        self.group_menu.add_command(label="Leave group", command=self.leave_group)
        self.root_menu.add_cascade(label="Group", menu=self.group_menu)

        self.connection_menu = Tkinter.Menu(self.root_menu)
        self.connection_menu.add_command(label="New", command=self.new_connection)
        self.root_menu.add_cascade(label="Connections", menu=self.connection_menu)

    def setup_status_bar(self):
        """setups the status bar"""
        self.status_label = Tkinter.Label(self.status_bar)
        self.cid_label = Tkinter.Label(self.status_bar)
        self.ping_label = Tkinter.Label(self.status_bar)
        for l in [self.status_label, self.cid_label, self.ping_label]:
            l.pack(side=Tkinter.LEFT)
            l.config(relief=Tkinter.RIDGE)

    def set_status(self, s):
        """sets the status message"""
        self.status_label.config(text="Status: {s}".format(s=s))

    def add_frame_entry(self, w):
        """adds a widget to the frame"""
        w.config(borderwidth=1)
        w.pack(side=Tkinter.TOP, anchor=Tkinter.NW, fill=Tkinter.X, expand=True)
        self.frame_entries.append(w)

    def on_disconnect(self):
        """called when the client was disconnected."""
        self.set_status("not connected")
        self.cid_label.config(text="")
        self.stop_pinging()
        self.channels = []
        self.relayed_ports = []
        self.cleanup_entries()

    def start_pinging(self):
        """starts the regular pinging"""
        self.pingloop = task.LoopingCall(self.do_pings)
        self.pingloop.start(3)

    def stop_pinging(self):
        """stops the pinging."""
        self.pingloop.stop()
        self.ping_label.config(text="")

    def do_pings(self):
        """pings the server and the clients"""
        if self.protocol is None:
            return
        self.protocol.ping_server().addCallback(self.got_server_ping)

    def got_server_ping(self, t):
        """Called when the server answered the ping"""
        ms = round(t * 1000, 3)
        self.ping_label.config(text="Ping to Server: {t}ms".format(t=ms))

    def run(self):
        """starts the GUI"""
        reactor.run()

    def quit(self):
        """quits the GUI"""
        if self.protocol is not None:
            self.protocol.disconnect()
            self.protocol = None
        self.screen.quit()
        self.screen.destroy()
        reactor.callLater(0.5, reactor.stop)

    def connect(self):
        """connects to a server"""
        if self.protocol is not None:
            tkMessageBox.showerror(title="Already connected", message="Already connected to a server.")
            return
        else:
            self.show_connect_window()

    def disconnect(self):
        """disconnects the client"""
        if self.protocol is None:
            tkMessageBox.showerror(title="Not connected", message="Not connected to a server.")
            return
        else:
            self.protocol.disconnect()
            self.protocol = None
            self.on_disconnect()

    def start_updates(self):
        """starts the updates"""
        self.updateloop = task.LoopingCall(self.perform_updates)
        d = self.updateloop.start(3)
        d.addErrback(self.show_error)

    def add_to_update_list(self, w):
        """adds a widget to the update list"""
        if w not in self.updatelist:
            self.updatelist.append(w)

    def remove_from_update_list(self, w):
        """removes a widget from the update list"""
        if w in self.updatelist:
            self.updatelist.remove(w)

    def perform_updates(self):
        """performs updates on the channel informations"""
        self.refresh_list()
        for w in self.updatelist:
            w.do_update()

    def refresh_list(self):
        """refreshes the list of channels"""
        modified = False
        if self.protocol is None:
            for w in self.updatelist:
                w.remove()
            return
        chids = self.protocol.get_chids()
        if chids != self.channels:
            modified = True
            for chid in chids:
                if chid not in self.channels:
                    p = self.protocol.get_channel(chid)
                    e = ChannelListElement(self.frame, self, p)
            self.channels = chids
        
        ports = self.protocol.get_relayed_ports()
        if ports != self.relayed_ports:
            modified = True
            for port in ports:
                if port not in self.relayed_ports:
                    f = self.protocol.get_relay(port)
                    e = RelayListElement(self.frame, self, f)
            self.relayed_ports = ports
                
        if modified:
            self.perform_updates()

    def new_connection(self):
        """create a new connection"""
        if self.protocol is None:
            tkMessageBox.showerror("Not connected", "Please connect to a server first")
            return
        elif not self.protocol.in_group():
            tkMessageBox.showerror("Not in a group", "Please join or create a group first")
            return
        else:
            d = defer.Deferred()
            d.addCallback(self.create_connection)
            d.addErrback(self.show_error)
            w = AskNewConnectionWindow(self, d)

    def create_connection(self, info):
        """creates a new connection"""
        from_port = info["fromport"]
        pid = info["pid"]
        to_port = info["toport"]
        d = self.protocol.relay_port_to(from_port, pid, to_port)
        d.addCallback(lambda x, self=self: self.perform_updates)
        d.addErrback(self.show_new_connection_error)
        self.perform_updates()
        return d

    def show_new_connection_error(self, f):
        """Shows a new connection error"""
        tkMessageBox.showerror("Can not relay connection", message=str(f))

    def reserve_group(self):
        """shows a dialog for reserving a new group"""
        if self.protocol is None:
            tkMessageBox.showerror("Not connected", "Please connect to a server first")
            return
        w = AskReserveGroupWindow(self)

    def do_reserve_group(self, name, sco, f):
        """actually reserve a group."""
        d = self.protocol.reserve_group(name, sco=sco)
        d.addCallback(lambda x, self=self, f=f: self.did_reserve(f, x))
        d.addErrback(self.can_not_reserve)

    def did_reserve(self, f, r):
        """called when a group was reserved"""
        f.write(r)
        f.close()
        tkMessageBox.showinfo("Group reserved.", "The group has been reserved and the key/cert was saved to '{n}'".format(n=f.name))

    def can_not_reserve(self, fail):
        """called when a group could not be reserved."""
        m = fail.value.message
        tkMessageBox.showerror("Could not reserve group", m)

    def create_group(self):
        """creates a group"""
        if self.protocol is None:
            tkMessageBox.showerror("Not connected", "Please connect to a server before creating a group.")
            return
        if self.in_group():
            tkMessageBox.showerror("Already in a group", "Please leave the group before creating a new group")
            return
        else:
            w = AskJoinCreateWindow(self, create=True)

    def join_group(self):
        """joins a group"""
        if self.protocol is None:
            tkMessageBox.showerror("Not connected", "Please connect to a server before joining a group.")
            return
        if self.in_group():
            tkMessageBox.showerror("Already in a group", "Please leave the group before joining another group")
            return
        else:
            w = AskJoinCreateWindow(self, create=False)

    def leave_group(self):
        """leaves the group"""
        if not self.in_group():
            tkMessageBox.showerror("Not in a group", "You have not yet joined/created a group.")
            return
        else:
            self.protocol.leave_group()
            self.cid_label.config(text="")
            self.cleanup_entries()
            self.perform_updates()

    def do_join_group(self, info):
        """actually join a group"""
        if self.in_group():
            tkMessageBox.showerror("Already in a group", "Please leave the group before joining another group")
            return
        d = self.protocol.join_group(**info)
        d.addCallback(self.did_join)
        d.addErrback(self.can_not_join)

    def do_create_group(self, info):
        """actually create a group"""
        if self.in_group():
            tkMessageBox.showerror("Already in a group", "Please leave the group before joining another group")
            return
        d = self.protocol.create_group(**info)
        d.addCallback(self.did_join)
        d.addErrback(self.can_not_join)

    def can_not_join(self, f=None):
        """Called when a group join or creation failed."""
        tkMessageBox.showerror(title="Error joining/creating group", message=repr(f))

    def did_join(self, r=None):
        """called when the client successfully joined or created a group"""
        cid = self.protocol.cid
        self.cid_label.config(text="CID: "+str(cid))

    def show_error(self, f=None):
        """Shows an error"""
        tkMessageBox.showerror(title="Error", message=f.value.message)

    def in_group(self):
        """returns True if the client is in a group, ohterwise False"""
        if self.protocol is None:
            return False
        else:
            return self.protocol.in_group()

    def cleanup_entries(self):
        """removes all entries from the list"""
        while len(self.frame_entries) > 0:
            e = self.frame_entries[0]
            e.remove()
        


class AskConnectWindow(object):
    """A window for connecting to a server"""
    def __init__(self, root, d):
        self.root = root
        self.d = d
        self.setup_window()

    def setup_window(self):
        """creates the window"""
        self.screen = Tkinter.Toplevel(master=self.root.screen)
        self.screen.title("Connect to Server")
        self.screen.protocol("WM_DELETE_WINDOW", self.on_close)
        self.label = Tkinter.Label(master=self.screen, text="Enter the Address of the server:")
        self.entry = Tkinter.Entry(master=self.screen)
        self.button = Tkinter.Button(master=self.screen, text="Connect", command=self.connect)
        self.label.grid(row=0, column=0, columnspan=3)
        self.entry.grid(row=1, column=0, columnspan=2)
        self.entry.delete(0, Tkinter.END)
        self.entry.insert(0, DEFAULT_SERVER)
        self.entry.focus_set()
        self.entry.bind("<Return>", self.connect)
        self.button.grid(row=1, column=2, columnspan=1)

    def connect(self, e=None):
        """creates the endpoint, closes the window and connects to the server"""
        inp = self.entry.get()
        if len(inp) == 0:
            inp = DEFAULT_SERVER
        ip, port = None, None
        if inp.count(":") == 0:
            # only IP
            ip = inp
            port = p22p.common.DEFAULT_PORT
        elif inp.count(":") == 1:
            # IP:port
            ip, port = inp.split(":")
            try:
                port = int(port)
            except ValueError:
                tkMessageBox.showerror(title="Invalid Input", message="Port must be an integer!")
                return
        if ip is None:
            epstr = inp
        else:
            epstr = "tcp:host={i}:port={p}:timeout=15".format(i=ip, p=port)
        ep = endpoints.clientFromString(reactor, epstr)
        d = endpoints.connectProtocol(ep, p22p.client.P22PClientProtocol())
        d.addCallback(self.connected)
        d.addErrback(self.connect_failed)

    def connected(self, p):
        """called when the connection was successfull"""
        self.quit()
        self.d.callback(p)

    def connect_failed(self, f):
        """called when the connection attempt failed"""
        tkMessageBox.showerror(title="Connection failed", message="Could not connect to server. Reason:\n{e}".format(e=f))

    def on_close(self):
        """called when the window is closed."""
        self.quit()
        self.d.errback(AbortError("Window closed"))

    def quit(self):
        """closes the window"""
        self.screen.destroy()


class AskNewConnectionWindow(object):
    "A Windows for asking details about a new connection trough p22p"""
    def __init__(self, root, d):
        self.root = root
        self.d = d
        self.screen = Tkinter.Toplevel(self.root.screen)
        self.screen.title("Relay port")

        self.title_label = Tkinter.Label(self.screen, text="Create new connection")
        self.fromport_label = Tkinter.Label(self.screen, text="Local port:")
        self.pid_label = Tkinter.Label(self.screen, text="PID / target CID:")
        self.toport_label = Tkinter.Label(self.screen, text="Remote port:")
        self.fromport_entry = Tkinter.Entry(self.screen)
        self.pid_entry = Tkinter.Entry(self.screen)
        self.toport_entry = Tkinter.Entry(self.screen)
        self.connect_button = Tkinter.Button(self.screen, text="Relay", command=self.connect)

        self.fromport_entry.bind("<Return>", self.handle_fromport_return)
        self.pid_entry.bind("<Return>", self.handle_pid_return)
        self.toport_entry.bind("<Return>", self.handle_toport_return)
        self.fromport_entry.focus_set()

        self.title_label.grid(row=0, column=0, columnspan=4)
        self.fromport_label.grid(row=1, column=0, columnspan=1)
        self.fromport_entry.grid(row=1, column=1, columnspan=3)
        self.pid_label.grid(row=2, column=0, columnspan=1)
        self.pid_entry.grid(row=2, column=1, columnspan=3)
        self.toport_label.grid(row=3, column=0, columnspan=1)
        self.toport_entry.grid(row=3, column=1, columnspan=3)
        self.connect_button.grid(row=4, column=3, columnspan=2)

    def connect(self):
        try:
            fromport = int(self.fromport_entry.get())
            pid = int(self.pid_entry.get())
            toport = int(self.toport_entry.get())
            assert fromport >= 0
            assert pid >= 0
            assert toport > 0
        except (ValueError, AssertionError):
            tkMessageBox.showerror("Invalid Input", "Please enter valid numbers")
        else:
            if pid == self.root.protocol.cid:
                tkMessageBox.showerror("Invalid Input","P22p v0.4 can not relay connections to the client from which the connections origins.\nPlease choose a different PID.")
            info = {
                "fromport": fromport,
                "pid": pid,
                "toport": toport,
                }
            self.screen.destroy()
            self.d.callback(info)

    def handle_fromport_return(self, e=None):
        """handles a return inside the "fromport" field"""
        self.pid_entry.focus_set()

    def handle_pid_return(self, e=None):
        """handles a return inside the "fromport" field"""
        self.toport_entry.focus_set()

    def handle_toport_return(self, e=None):
        """handles a return inside the "fromport" field"""
        self.connect()


class AskJoinCreateWindow(object):
    """A window for joining/creating a group"""
    def __init__(self, root, create=False):
        self.root = root
        self.create = create

        self.cert = None
        self.scovar = Tkinter.IntVar()

        self.screen = Tkinter.Toplevel(self.root.screen)
        self.screen.title(("Create" if self.create else "Join") + " group")

        self.name_label = Tkinter.Label(self.screen, text="Groupname:")
        self.pswd_label = Tkinter.Label(self.screen, text="Password:")
        self.name_entry = Tkinter.Entry(self.screen)
        self.pswd_entry = Tkinter.Entry(self.screen, show="*")
        self.cert_label = Tkinter.Label(self.screen, text="Groupkey:")
        self.cert_button = Tkinter.Button(self.screen, text="<None>", command=self.select_cert)
        self.connect_button = Tkinter.Button(self.screen, text=("Create" if self.create else "Join"), command=self.join_or_create)

        if self.create:
            self.sco_label = Tkinter.Label(self.screen, text="SCO:")
            self.sco_checkbutton = Tkinter.Checkbutton(self.screen, text="SCO", variable=self.scovar)
            shift = 1
        else:
            shift = 0

        self.name_label.grid(row=0, column=0, columnspan=1)
        self.name_entry.grid(row=0, column=1, columnspan=3)
        self.pswd_label.grid(row=1, column=0, columnspan=1)
        self.pswd_entry.grid(row=1, column=1, columnspan=3)
        self.cert_label.grid(row=2, column=0, columnspan=1)
        self.cert_button.grid(row=2, column=1, columnspan=3)
        if self.create:
            self.sco_label.grid(row=3, column=0, columnspan=1)
            self.sco_checkbutton.grid(row=3, column=1, columnspan=3)
        self.connect_button.grid(row=(3 + shift), column=2, columnspan=2)

        self.name_entry.bind("<Return>", self.name_entry_return)
        self.pswd_entry.bind("<Return>", self.pswd_entry_return)

        self.name_entry.focus_set()

    def name_entry_return(self, e=None):
        """called when return was pressed inside the name entry field"""
        self.pswd_entry.focus_set()

    def pswd_entry_return(self, e=None):
        self.join_or_create()

    def select_cert(self):
        """asks the user to select a cert"""
        cf = tkFileDialog.askopenfile(mode="rb")
        if cf in (None, False):
            self.cert = None
            self.cert_button.config(text="<None>")
        else:
            content = cf.read()
            self.cert_button.config(text=cf.name)
            cf.close()
            self.cert = content

    def join_or_create(self):
        """joins or create a group."""
        sco = bool(self.scovar.get())
        name = self.name_entry.get()
        pswd = self.pswd_entry.get()
        if (len(name) == 0) or (len(pswd) == 0):
            tkMessageBox.showerror("Invalid input", "Please enter a valid name and a valid password.")
            return
        info = {
            "name": name,
            "password": pswd,
            "cert": self.cert,
            }
        if self.create:
            info["sco"] = sco
        self.screen.destroy()
        if self.create:
            self.root.do_create_group(info)
        else:
            self.root.do_join_group(info)


class AskReserveGroupWindow(object):
    """A window for reserving a group"""
    def __init__(self, root):
        self.root = root
        self.screen = Tkinter.Toplevel(self.root.screen)
        self.screen.title("Reserve Group")

        self.sco_var = Tkinter.IntVar()
        self.f = None

        self.name_label = Tkinter.Label(self.screen, text="Group:")
        self.name_entry = Tkinter.Entry(self.screen)
        self.file_label = Tkinter.Label(self.screen, text="File to write to:")
        self.file_button = Tkinter.Button(self.screen, text="<Select>", command=self.select_file)
        self.sco_label = Tkinter.Label(self.screen, text="SCO:")
        self.sco_checkbutton = Tkinter.Checkbutton(self.screen, text="SCO", variable=self.sco_var)
        self.reserve_button = Tkinter.Button(self.screen, text="Reserve group", command=self.reserve)

        self.name_label.grid(row=0, column=0, columnspan=1)
        self.name_entry.grid(row=0, column=1, columnspan=3)
        self.sco_label.grid(row=1, column=0, columnspan=1)
        self.sco_checkbutton.grid(row=1, column=1, columnspan=3)
        self.file_label.grid(row=2, column=0, columnspan=1)
        self.file_button.grid(row=2, column=1, columnspan=3)
        self.reserve_button.grid(row=3, column=2, columnspan=2)

        self.name_entry.focus_set()
        self.name_entry.bind("<Return>", self.name_entry_return)

    def name_entry_return(self, e=None):
        """handles a return inside the name entry field"""
        self.reserve()

    def select_file(self):
        """selects a file."""
        f = tkFileDialog.askopenfile(mode="wb")
        if f in (None, False):
            return
        else:
            self.f = f
            t = f.name
            self.file_button.config(text=t)

    def reserve(self, e=None):
        """reserve a group"""
        name = self.name_entry.get()
        sco = bool(self.sco_var.get())
        if (len(name) == 0) or (self.f is None):
            tkMessageBox.showerror("Invalid input", "Please enter a valid name and choose a file to save the key into")
            return
        self.screen.destroy()
        self.root.do_reserve_group(name, sco, self.f)



class VerticalScrolledFrame(Tkinter.Frame):
    """
    copied from: https://stackoverflow.com/questions/16188420/python-tkinter-scrollbar-for-frame [modified]
    A pure Tkinter scrollable frame that actually works!
    * Use the 'interior' attribute to place widgets inside the scrollable frame
    * Construct and pack/place/grid normally
    * This frame only allows vertical scrolling

    """
    def __init__(self, parent, *args, **kw):
        Tkinter.Frame.__init__(self, parent, *args, **kw)            

        # create a canvas object and a vertical scrollbar for scrolling it
        vscrollbar = Tkinter.Scrollbar(self, orient=Tkinter.VERTICAL)
        vscrollbar.pack(fill=Tkinter.Y, side=Tkinter.RIGHT, expand=Tkinter.FALSE)
        self.canvas = canvas = Tkinter.Canvas(self, bd=0, highlightthickness=0,
                        yscrollcommand=vscrollbar.set)
        canvas.pack(side=Tkinter.LEFT, fill=Tkinter.BOTH, expand=Tkinter.TRUE)
        vscrollbar.config(command=canvas.yview)

        # reset the view
        canvas.xview_moveto(0)
        canvas.yview_moveto(0)

        # create a frame inside the canvas which will be scrolled with it
        self.interior = interior = Tkinter.Frame(canvas)
        interior_id = canvas.create_window(0, 0, window=interior,
                                           anchor=Tkinter.NW)

        # track changes to the canvas and frame width and sync them,
        # also updating the scrollbar
        def _configure_interior(event):
            # update the scrollbars to match the size of the inner frame
            size = (interior.winfo_reqwidth(), interior.winfo_reqheight())
            canvas.config(scrollregion="0 0 %s %s" % size)
            if interior.winfo_reqwidth() != canvas.winfo_width():
                # update the canvas's width to fit the inner frame
                canvas.config(width=interior.winfo_reqwidth())
        interior.bind('<Configure>', _configure_interior)

        def _configure_canvas(event):
            if interior.winfo_reqwidth() != canvas.winfo_width():
                # update the inner frame's width to fill the canvas
                canvas.itemconfigure(interior_id, width=canvas.winfo_width())
        canvas.bind('<Configure>', _configure_canvas)

    def bind_mousewheel(self, event=None):
        self.bind_all("<MouseWheel>", self.on_mousewheel_change)
        self.bind_all("<Button-4>", self.on_mousewheel_change)
        self.bind_all("<Button-5>", self.on_mousewheel_change)

    def unbind_mousewheel(self, event=None):
        self.unbind_all("<MouseWheel>")
        self.unbind_all("<Button-4>")
        self.unbind_all("<Button-5>")

    def on_mousewheel_change(self, event):
        if event.num == 5 or event.delta == -120:
            n = 1
        if event.num == 4 or event.delta == 120:
            n = -1
        self.canvas.yview_scroll(n, "units")


class ListElement(Tkinter.Frame):
    """An element for the scrollview"""
    def __init__(self, rootframe, root, *args, **kwargs):
        Tkinter.Frame.__init__(self, rootframe, *args, **kwargs)
        self.root = root
        self.root.add_frame_entry(self)

    def remove(self):
        """removes this element from the root object."""
        try:
            self.pack_forget()
        except:
            pass
        try:
            self.root.frame_entries.remove(self)
        except:
            pass


class ChannelListElement(ListElement):
    """Like ListElement, but for channels."""
    def __init__(self, rootframe, root, proto, *args, **kwargs):
        ListElement.__init__(self, rootframe, root, *args, **kwargs)
        self.proto = proto
        self.populate()
        self.add_to_update_list()
        d = self.proto.wait_disconnect()
        d.addCallback(self.on_disconnect)

    def populate(self):
        """creates and adds the widgets"""
        self.type_label = Tkinter.Label(self, text="Channel", justify=Tkinter.LEFT)
        self.status_label = Tkinter.Label(self, text="Status: preparing...", justify=Tkinter.LEFT)
        self.chid_label = Tkinter.Label(self, justify=Tkinter.LEFT)
        self.received_label = Tkinter.Label(self, text="", justify=Tkinter.LEFT)
        self.send_label = Tkinter.Label(self, text="", justify=Tkinter.LEFT)
        self.disconnect_button = Tkinter.Button(self, text="Close", fg="red", command=self.disconnect)
        for w in (self.chid_label, self.status_label, self.received_label, self.send_label, self.disconnect_button):
            w.pack(anchor=Tkinter.W, side=Tkinter.LEFT)  # , expand=True, fill=Tkinter.X)
        self.do_update()

    def set_status(self, msg):
        """sets the status message"""
        self.status_label.config(text="Status: " + msg)

    def do_update(self):
        """requests info from proto and adjusts the labels"""
        info = self.proto.get_info()
        self.set_status(info.get("status", "unknown"))
        for l, m, n in ((self.received_label, "Received", info.get("received", 0)), (self.send_label, "Sent", info.get("send", 0))):
            if n < 1024:
                u = "B"
            else:
                if n >= 1024:
                    n /= 1024
                    u = "kB"
                if n >= 1024:
                    n /= 1024
                    u = "mB"
                if n >= 1024:
                    n /= 1024
                    u = "gB"
                if n >= 1024:
                    n /= 1024
                    u = "tB"
            n = round(n, 3)
            l.config(text="{m}: {n}{u}".format(m=m, n=n, u=u))
        chidstr = ":".join(str(e) for e in info.get("chid", ""))
        self.chid_label.config(text="Chid: {s}".format(s=chidstr))

    def add_to_update_list(self):
        """adds this widget to the update list of the root"""
        self.root.add_to_update_list(self)

    def remove_from_update_list(self):
        """removes this widget from the update list of the root object"""
        self.root.remove_from_update_list(self)

    def cleanup(self):
        """perform cleanup tasks"""
        self.remove_from_update_list()

    def disconnect(self):
        """disconnectes"""
        self.proto.disconnect()
        self.remove()
        self.do_update()
        self.cleanup()

    def on_disconnect(self):
        """called when the proto is disconnected"""
        self.remove()
        self.do_update()
        self.cleanup()


class RelayListElement(ListElement):
    """A ListElement for relays"""
    def __init__(self, rootframe, root, factory, *args, **kwargs):
        ListElement.__init__(self, rootframe, root, *args, **kwargs)
        self.factory = factory
        self.populate()
        self.add_to_update_list()

    def populate(self):
        """creates and adds the widgets"""
        self.type_label = Tkinter.Label(self, text="Relay", justify=Tkinter.LEFT)
        self.status_label = Tkinter.Label(self, text="Status: preparing...", justify=Tkinter.LEFT)
        self.localport_label = Tkinter.Label(self, justify=Tkinter.LEFT)
        self.target_label = Tkinter.Label(self, justify=Tkinter.LEFT)
        self.conns_label = Tkinter.Label(self, justify=Tkinter.LEFT)
        self.disconnect_button = Tkinter.Button(self, text="Close", fg="red", command=self.disconnect)
        for w in (self.type_label, self.localport_label, self.status_label, self.conns_label, self.disconnect_button):
            w.pack(anchor=Tkinter.W, side=Tkinter.LEFT)  # , expand=True, fill=Tkinter.X)
        self.do_update()

    def set_status(self, msg):
        """sets the status message"""
        self.status_label.config(text="Status: " + msg)

    def do_update(self):
        """requests info from proto and adjusts the labels"""
        info = self.factory.get_info()
        self.set_status("listening...")
        self.localport_label.config(text="Port: {p}".format(p=info.get("local_port", "<Unknown>")))
        target = ":".join((str(info["pid"]), str(info["remote_port"])))
        self.target_label.config(text="Target: {t}".format(t=target))
        self.conns_label.config(text="Total Connections: {n}".format(n=info.get("total_connections", 0)))

    def add_to_update_list(self):
        """adds this widget to the update list of the root"""
        self.root.add_to_update_list(self)

    def remove_from_update_list(self):
        """removes this widget from the update list of the root object"""
        self.root.remove_from_update_list(self)

    def cleanup(self):
        """perform cleanup tasks"""
        self.remove_from_update_list()
        port = self.factory.listen_port
        if port in self.root.relayed_ports:
            self.root.relayed_ports.remove(port)

    def disconnect(self):
        """disconnectes"""
        self.set_status("closing...")
        self.factory.stop()
        self.set_status("closed")
        self.remove()
        self.do_update()


def main():
    """create and run a GUI"""
    gui = P22PGui()
    gui.run()

    
if __name__ == "__main__":
    main()
