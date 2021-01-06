# Vulnerability Scanner 9001
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
[![python](https://img.shields.io/badge/python-3-blue.svg)](https://www.python.org/downloads/)

Vulnerability Scanner with a power level of over 9000!!

----
## Video Example
[![asciicast](https://asciinema.org/a/BNCWbC2DzuK9z6o93FKIQblMP.svg)](https://asciinema.org/a/BNCWbC2DzuK9z6o93FKIQblMP)


## How it works
The script has 2 modes, Full and Fast.  

Full mode starts with a threaded port scan of all 65535 TCP ports and saves any open ports.  The script then passes the ports into nmap for service enumeration.  Based on the results of this scan, the script will run additional enumeration on the machine.  For example, if HTTP is running on the machine, the script will run various enumeration tools related to information gathering of the HTTP protocol.

Fast mode starts with the same threaded port scan as Full mode.  But instead of running multiple enumeration tools, it only passes the ports into a single nmap scan.  Think of it like running `nmap -p- -A <target>` but much faster!

## To Do:

* Add more enumeration tools to Full scan
* Add option to change speed of Port Scanner
* Add searchsploit results
* Add VulnDB API calls
