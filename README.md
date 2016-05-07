# p22p
Relay data between two clients using a central server.

#Features
- Relay any number of socket-connections using one connection
- current version uses websockets (=easy website integration; old version used normal sockets)
- clients have a default server configured (ws://p22p-bennr01.rhcloud.com/)
- old pure-socket version aviable
- create any number of password protected groups with up to 256 clients
- communication between groups encrypted with group password (=server cant read data, he only has a hashed version of the pswd)
- command-line-interface (command-line arguments and command-loop)
- asynchronous (=highly scaleable, no thread-overhead)
- create reserved groups (clients get json-data required to create a group)
- reserved groups can be configured to only allow data exchange between group-creator and the other clients (no connection between other clients allowed)
- pypy compatible (=higher performance)
- buitin help

#Requirements
P22P requires python 2.7.X (not tested with 3.X.X).
P22P requires the following packages from pypi:
- twisted
- autobahn

You can install these requirements by running `pip -r requirements.txt`.

#Security Warning
**Keep your Group Password secret! Only join Groups where you can thrust the other clients!**
Anyone in the group can open a connection between his computer and any port on your computer.
Because the connection to the target-port on your computer is opened localy, even programs only accepting connections from `localhost` may accept the connection.
`Reserved Groups` can be created with the option to disable connections between non-creator clients. This is usefull for groups where you cant thrust everyone. However, you should not rely on this security-feature.
**Always use the latest Version** unless you have a good reason to use an old version (e.g. requires the use of normal sockets)
Old Versions may be unstable and/or contain security issues

#Tipps
- There is a builtin-help (type `help` in the command-loop)
- you can improve performance by using pypy or install the additional dependencies in `requirements.txt`.
- There is a script to build an exe from the source. This requires `pyinstaller`.

#Versions
At the time of uploading the p22p-scripts, there have already been some versions.
Here are the most notable changes:
- `v0.1` is the original version. It uses a socket-select combo to achieve high efficency. It is unstable, only allows connections between two clients but has the best performance. It does not require any dependencies.
- `v0.2` is a complete rewrite from scratch. It now allows the use of Groups, uses websockets (twisted+autobahn).
- `v0.3` is the current version and is based on `v0.2`. The most important new feature is the ability to reserve groups.
