#!/usr/bin/python3
import socket
import subprocess
import os
import sys
from datetime import datetime
import threading
from queue import Queue
import time

try:
	import pyfiglet
except ImportError:
	print("pyliglet library not found.  Please install prior to running script")
	sys.exit()

print_lock = threading.Lock()

def banner():
    ascii_banner1 = pyfiglet.figlet_format("  Vuln-Scanner")
    ascii_banner2 = pyfiglet.figlet_format("                      9001")

    print("\n")
    print("\n")
    print("#" * 70)
    print(ascii_banner1)
    print(ascii_banner2)
    print("#" * 70)
    print("\n")
    time.sleep(1)
    print("Vulnerability Scanner with a power level of over 9000!!")
    print("")
    print("What?!? 9000!?! That's IMPOSSIBLE!!")
    print("\n")
    print("#" * 70)
    #print("#" * 70)
    time.sleep(1)
    print("\n")
    print("\n")
    print("\n")



def main():
    banner()
    print_lock = threading.Lock()
    target = input("Enter your target IP: ")

##########  Need to change
    dir_ip = "mkdir ~/Projects/vuln_scan_9001/scans/{ip} 2>/dev/null".format(ip=target)
    os.system(dir_ip)
    print("")
    print("#" * 70)
    print("Scanning for Open Ports")
    print("#" * 70)
    print("")
    print("")

    open_ports = []

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((target,port))
            with print_lock:
                print('Port %s is Open' %port)
                open_ports.append(str(port))
                con.close()
        except:
            pass


    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()

    q = Queue()

    for x in range(200):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()


    start = time.time()

############## NEED to change to 65535
    for worker in range(1,65535):
        q.put(worker)

        # wait until the thread terminates.
    q.join()

    print("")
    print("")
    print("#" * 70)
    print("Running Light Service Enumeration")
    print("#" * 70)
    print("")
    print("")

    light_serv_enum = "nmap -p{ports} -sV --version-intensity 0 -Pn -T4 {ip}".format(ports=",".join(open_ports), ip=target)
    os.system(light_serv_enum)

    print("")
    print("")
    print("#" * 70)
    print("Running Nmap Aggressive Service Enumeration")
    print("#" * 70)
    print("")
    print("")

    heavy_serv_enum = "nmap -p{ports} -A --version-all --script=vulners -Pn -T4 {ip}".format(ports=",".join(open_ports), ip=target)
    os.system(heavy_serv_enum)


    print("")
    print("")
    print("#" * 70)
    print("Running Vulscan")
    print("#" * 70)
    print("")
    print("")

#################### Need to change
    vulscan_dir = "mkdir ~/Projects/vuln_scan_9001/scans/{ip}/vulscan 2>/dev/null".format(ip=target)
    os.system(vulscan_dir)

    for num in range(1,65535):
        if str(num) in open_ports:
            vulscan = "nmap -p{ports} -sV --script=vulscan/vulscan.nse -Pn -oN ~/Projects/vuln_scan_9001/scans/{ip}/vulscan/port_{ports}.txt {ip} >/dev/null".format(ports=num, ip=target)
            print("Scanning for Vulnerabilities on Port %s" %num)
            os.system(vulscan)
        else:
            pass
    print("")
    print("Output Files Saved at ./scans/ip_address/vulscan")

    if "80" in open_ports:
        print("80 is here")
    else:
        pass

#    if "445" in open_ports:
#        print("")
#        print("")
#        print("#" * 70)
#        print("Running SMB Enumeration on Port 445")
#        print("#" * 70)
#        print("")
#        print("")
#        smb_enum = "nmap -p139,445 --script=smb-security-mode,smb-double-pulsar-backdoor,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-server-stats,smb-system-info,smb-vuln-ms17-010,smb-vuln-webexec -Pn {ip}".format(ip=target)
#        os.system(smb_enum)
#    else:
#        pass

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye!")
        quit()
