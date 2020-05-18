A simple bash+python script that helps scanning a net to get information about ports ad hosts in a FAST way,
so it avoid asking fro user input and tries to scan most common ports, over the whole network where the host that runs
the script is connected.

The script is intended to be 'Automatic', meaning that it can be started on a machine after installing those few
dependencies and leave it run until it ends without any interaction.
All results will be than transferred to a remote server with SSH, the script now has done and can
be removed from the host (see 'SSH Server Configuration').

# Dependencies:
The only few dependencies required for the script to work are:
- a python3 interpreter
- pip module for python3 (usually distributed with python)
- net-tools

To install this dependencies (in a debian based distro with APT package manager) is to execute the following in
terminal:

        sudo apt update && sudo apt install -y python3 python3-pip net-tools

Everything else needed by the script can be auto downloaded when launching it.

# Usage:
    Script doesn't require installation.
    You can start the scan by moving into project directory and simply doing:

        "sudo ./pScan.sh <interface-name>"

    by using this syntax, the script will start arp-scanning all hosts of the current LAN, and for each found host,
    it will scan for the most common 200 UDP and TCP ports (accordingly to nmap most scanned ports db).

    This will use the default values for the script.

    If you want to customize the scan you can use directly the python class in 'portScanner.py', the code is python-documented
    and ready-to-use.

    There is also a 'pscan.py' script that is somehow a mid-step between writing your own script or using the 'fast'
    pre-configured bash executable. For scan, it uses 'portScanner.py'.

    'pscan.py' is the one actually used by the bash script with predefined parameters.

# SSH Server Configuration:
    For running the auto script, you have to configure a remote SSH server listening on port 22.
    The server must be configured to accept connection without password, only with a key-pair authentication.
    To accomplish this, you have to put the '.pub' file in project folder to the ssh configuration
    dir (~/.ssh) on the remote server.

    If the server is not correctly the script will ask for password after the scan is completed.

# Output File:
    The output file sent to the SSH server will use the following syntax:

        <active-host-1-ip> <active-host-1-mac>
        (\t)    TCP:<port1_num>
        (\t)    TCP:<port2_num>
        (\t)    UDP:<port3_num>-<status>
        ...     ...
        <active-host-2-ip> <active-host-2-mac>
        (\t)    TCP:<port1_num>
        (\t)    UDP:<port2_num>-<status>
        ...     ...

    - Ports closed are not even listed in the output.
    - TCP ports that are listed are open, else they are not listed.
    - UDP ports will have all their own status, one from:
        open (unlikely and really rare)
        filtered
        open|filtered (most of the cases a UDP scan can tell only this)

# Info:
    Script created by Luca Pasini for SUPSI under no particular license.
    Script uses 'scapy' python module (included in project), for more info:

        https://scapy.net/
