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
    print("\n")
    #print("What?!? 9000!?! That's IMPOSSIBLE!!")
    #print("\n")
    print("#" * 70)
    #print("#" * 70)
    time.sleep(1)
    print("\n")
    print("\n")
    print("\n")



def main():
    print_lock = threading.Lock()
    print("")
    target = input("Enter your target IP: ")
    #target = "10.10.50.151"
    
    
    current_dir = os.getcwd()
    dir_scans = "mkdir {pwd}/scans 2>/dev/null".format(pwd=current_dir)
    os.system(dir_scans)
    dir_ip = "mkdir {pwd}/scans/{ip} 2>/dev/null".format(pwd=current_dir, ip=target)
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
            #print("fail")


    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()

    q = Queue()

    for x in range(100):
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
    dir_nmap = "mkdir {pwd}/scans/{ip}/nmap 2>/dev/null".format(pwd=current_dir, ip=target)
    os.system(dir_nmap)
    light_serv_enum = "nmap -p{ports} -sV --version-intensity 0 -Pn -T4 -oN {pwd}/scans/{ip}/nmap/light.txt {ip}".format(ports=",".join(open_ports), pwd=current_dir, ip=target)
    os.system(light_serv_enum)
    
    print("")
    print("")
    print("#" * 70)
    print("Running Nmap Aggressive Service Enumeration")
    print("#" * 70)
    print("")
    print("")

    heavy_serv_enum = "nmap -p{ports} -A --script=vulners -Pn -T4 -oN {pwd}/scans/{ip}/nmap/heavy.txt {ip}".format(ports=",".join(open_ports), pwd=current_dir, ip=target)
    os.system(heavy_serv_enum)


    print("")
    print("")
    print("#" * 70)
    print("Running Vulscan")
    print("#" * 70)
    print("")
    print("")
    

    vulscan_dir = "mkdir {pwd}/scans/{ip}/vulscan 2>/dev/null".format(pwd=current_dir, ip=target)
    os.system(vulscan_dir)

    for num in range(1,65535):
        if str(num) in open_ports:
            vulscan = "nmap -p{ports} -sV --script=vulscan/vulscan.nse -Pn -oN {pwd}/scans/{ip}/vulscan/port_{ports}.txt {ip} >/dev/null".format(ports=num, pwd=current_dir, ip=target)
            print("Scanning for Vulnerabilities on Port %s" %num)
            os.system(vulscan)
        else:
            pass
    print("")
    print("Output Files Saved at ./scans/ip_address/vulscan")
    

    if "80" in open_ports:
        print("")
        print("")
        print("#" * 70)
        print("Running HTTP Enumeration on Port 80  -  Nmap")
        print("#" * 70)
        print("")
        print("")
        http_nmap = "nmap -p80 --script=http-apache-server-status,http-aspnet-debug,http-auth,http-auth-finder,http-backup-finder,http-brute,http-coldfusion-subzero,http-comments-displayer,http-config-backup,http-cookie-flags,http-default-accounts,http-enum,http-headers,http-methods,http-ntlm-info,http-userdir-enum,http-sql-injection,http-sql-injection,http-server-header -Pn -oN {pwd}/scans/{ip}/nmap/http.txt {ip}".format(pwd=current_dir, ip=target)
        os.system(http_nmap)
        print("")
        print("")
        print("#" * 70)
        print("Running HTTP Enumeration on Port 80  -  Nikto")
        print("#" * 70)
        print("")
        print("")
        dir_nikto = "mkdir {pwd}/scans/{ip}/nikto".format(pwd=current_dir, ip=target)
        os.system(dir_nikto)
        nikto = "nikto -h {ip} -Tuning x,6 -maxtime 40m -output {pwd}/scans/{ip}/nikto/40min_scan.txt".format(ip=target, pwd=current_dir)
        os.system(nikto)
        print("")
        print("")
        print("#" * 70)
        print("Busting Directories on Port 80  -  Gobuster")
        print("#" * 70)
        print("")
        print("")
        dir_go = "mkdir {pwd}/scans/{ip}/gobuster".format(pwd=current_dir, ip=target)
        os.system(dir_go)
        gobust = "gobuster dir -u {ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o {pwd}/scans/{ip}/gobuster".format(ip=target, pwd=current_dir)
        os.system(gobust)
    else:
        pass
    
    
    if "22" in open_ports:
        print("")
        print("")
        print("#" * 70)
        print("Running SSH Enumeration on Port 22  -  Nmap")
        print("#" * 70)
        print("")
        print("")
        ssh_nmap = "nmap -p22 --script=ssh-auth-methods,ssh-hostkey,ssh-publickey-acceptance -Pn -oN {pwd}/scans/{ip}/nmap/ssh.txt {ip}".format(pwd=current_dir, ip=target)
        os.system(ssh_nmap)
    else:
        pass
    
    if "445" in open_ports:
        print("")
        print("")
        print("#" * 70)
        print("Running SMB Enumeration on Port 445")
        print("#" * 70)
        print("")
        print("")
        smb_enum = "nmap -p139,445 --script=smb-security-mode,smb-double-pulsar-backdoor,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-os-discovery,smb-protocols,smb-server-stats,smb-system-info,smb-vuln-ms17-010,smb-vuln-webexec -Pn -oN {pwd}/scans/{ip}/nmap/smb.txt {ip}".format(pwd=current_dir, ip=target)
        os.system(smb_enum)
        print("")
        print("")
        print("#" * 70)
        print("Enumerating NetBIOS - nmblookup")
        print("#" * 70)
        print("")
        print("")
        netbio = "nmblookup -A {ip}".format(ip=target)
        os.system(netbio)
        print("")
        print("")
        print("#" * 70)
        print("Enumerating Possible Shares - smbmap & smbclient")
        print("#" * 70)
        print("")
        print("")
        print("##### smbmap #####")
        print("")
        smbmap = "smbmap -H {ip}".format(ip=target)
        os.system(smbmap)
        print("")
        print("")
        print("##### smbclient #####")
        print("")
        smbclient = "smbclient -N -L //{ip}////".format(ip=target)
        os.system(smbclient)
        print("")
        print("")
        print("#" * 70)
        print("Running Enum4Linux")
        print("#" * 70)
        print("")
        print("")
        enum4linux = "enum4linux -a {ip}".format(ip=target)
        os.system(enum4linux)
    else:
        pass
    
    
    if "21" in open_ports:
        print("")
        print("")
        print("#" * 70)
        print("Running FTP Enumeration on Port 21  -  Nmap")
        print("#" * 70)
        print("")
        print("")
        ftp_enum = "nmap -p21 -sV --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -Pn -oN {pwd}/scans/{ip}/nmap/ftp.txt {ip}".format(ip=target)
        os.system(ftp_enum)
    
try:
    banner()
    print("1 = Full    2 = Fast")
    choice = input("Do you want Full or Fast Scan? ")
    if choice == "1":
        main()
    elif choice == "2":
        part()
    else:
        print("Invalid Entry.  Exiting.")
        sys.exit()
        
except KeyboardInterrupt:
    print("\nGoodbye!")
    quit()
