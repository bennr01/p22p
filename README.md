# p22p
Relay data between two clients using a central server.
This is usefull if you want two programs to communicate, which would normally be blocked by a firewall of a router/proxy.
For example, if you want to play a Game with a friend, but the firewall of your/your friends router would block incomming connections, you could both use p22p to connect to the central server and bypass the restriction (both connections would be outgoing). This only works if your router/proxy allows outgoing connections.

# Features
- Relay any number of socket-connections using one connection
- clients have a default server configured
- can be used from commandline, GUI or python
- old pure-socket version available
- create any number of password protected groups with up to 65535 clients
- communication between groupmembers is compressed and encrypted with group password (=server cant read data, he only has a hashed version of the pswd)
- command-line-interface (command-line arguments and command-loop)
- asynchronous (=highly scaleable, no thread-overhead)
- create reserved groups (clients get json-data required to create a group)
- reserved groups can be configured to only allow data exchange between group-creator and the other clients (no connection between other clients allowed)
- pypy compatible (=higher performance)
- buitin help
- designed for TCP
- you can use any twisted endpoint to connect to the server.

# Features in v0.3
Due to a full rewrite, v0.4 does not support all the features of v0.3. Here is a list of additional features in v0.3
- uses websockets (you can still use them in v0.4 using the `-e` parameter)
- commandloop

# Requirements
P22P requires python 2.7.X (not tested with 3.X.X). Get it here: https://www.python.org/downloads/release/python-2711/
P22P requires the following packages from pypi:
- twisted

You can install these requirements by running `pip -r requirements.txt`.
If you dont have pip installed, see https://pip.pypa.io/en/latest/installing/ for a tutorial on installing pip.

# Installation
1. Install `python2.7` and `pip`.
2. In a console, type `pip install p22p`.

# Launching P22P
1. Open a Console/Shell
   - **Windows:** Press `Windows`and `r` at the same time, then type `cmd` and press enter.
   - **Linux:** If you are a linux user, you probably already know how to open a shell.
2. Start P22P:
   a) Type `p22p --help` (insert the path to the `client.py` file there) to see a list of available commands
   b) Type `p22p gui`
3. Done

# Security Warning
**Keep your Group Password secret! Only join Groups where you can thrust the other clients!**
Anyone in the group can open a connection between his computer and any port on your computer.
Because the connection to the target-port on your computer is opened localy, even programs only accepting connections from `localhost` may accept the connection.
`Reserved Groups` can be created with the option to disable connections between non-creator clients. This is usefull for groups where you cant thrust everyone. However, you should not rely on this security-feature.
**Always use the latest Version** unless you have a good reason to use an old version (e.g. requires the use of normal sockets)
Old Versions may be unstable and/or contain security issues

# Tipps
- you can improve performance by using pypy.
- There is a script to build an exe from the source. This requires `pyinstaller`.

# Versions
At the time of uploading the p22p-scripts, there have already been some versions.
Here are the most notable changes:
- `v0.1` is the original version. It uses a socket-select combo to achieve high efficency. It is unstable, only allows connections between two clients but has the best performance. It does not require any dependencies.
- `v0.2` is a complete rewrite from scratch. It now allows the use of Groups, uses websockets (autobahn+twisted).
- `v0.3` is based on `v0.2`. The most important new feature is the ability to reserve groups.
- `v0.4` is a complete rewrite from scratch. It offers nearly the same functionality as `v0.3`, but no interactie commandloop. It no longer uses websockets and is now fully asynchronous. It also adds a GUI for the client.
