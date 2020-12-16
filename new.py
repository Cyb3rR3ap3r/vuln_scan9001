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
    #target = "10.10.255.198"


    current_dir = "/root"
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
        if port == 1000:
            print("10% Complete")
        if port == 5000:
            print("20% Complete")
        if port == 10000:
            print("30% Complete")
        if port == 20000:
            print("40% Complete")
        if port == 30000:
            print("50% Complete")
        if port == 40000:
            print("60% Complete")
        if port == 50000:
            print("70% Complete")
        if port == 60000:
            print("80% Complete")
        if port == 65000:
            print("90% Complete")
        try:
            con = s.connect((target,port))
            with print_lock:
                #print('Port %s is Open' %port)
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
    print("Running Nmap Service Enumeration")
    print("#" * 70)
    print("")
    print("")
    dir_nmap = "mkdir {pwd}/scans/{ip}/nmap 2>/dev/null".format(pwd=current_dir, ip=target)
    os.system(dir_nmap)
    light_serv_enum = "nmap -p{ports} -sV -Pn -T4 -oN {pwd}/scans/{ip}/nmap/main.txt {ip}".format(ports=",".join(open_ports), pwd=current_dir, ip=target)
    os.system(light_serv_enum)
    print("######\n")

    # Enumerate HTTP

    find_http = subprocess.check_output("cat {pwd}/scans/{ip}/nmap/main.txt | grep tcp | grep open | grep http".format(pwd=current_dir, ip=target), shell=True)
    find_http1 = find_http.decode('utf8')

    if "http" in find_http1:

        http_ports = subprocess.check_output("cat {pwd}/scans/{ip}/nmap/main.txt | grep tcp | grep http | cut -d ' ' -f 1 | cut -d '/' -f 1 | tr '\n' ',' | rev | cut -c 2- | rev".format(pwd=current_dir, ip=target), shell=True)
        open_http = http_ports.decode('utf8').rstrip().split(',')


    for x in open_http:
        print("")
        print("")
        print("#" * 70)
        print("Running HTTP Enumeration on Port {x}  -  Nmap".format(x=x))
        print("#" * 70)
        print("")
        print("")
        http_nmap = "nmap -p{x} -A -Pn -oN {pwd}/scans/{ip}/nmap/{x}-http.txt {ip}".format(x=x, pwd=current_dir, ip=target)
        os.system(http_nmap)
        print("")
        print("")
        print("#" * 70)
        print("Running HTTP Enumeration on Port {x}  -  Dirsearch".format(x=x))
        print("#" * 70)
        print("")
        print("")
        dirsearch = "dirsearch -u http://{ip}:{x} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 400,500 -e php,asp,aspx,html,txt,bak,old,war,jsp -f -r -t 100".format(ip=target, x=x)
        os.system(dirsearch)


    # Enumerate FTP

    find_ftp = subprocess.check_output("cat {pwd}/scans/{ip}/nmap/main.txt | grep tcp | grep open | grep ftp".format(pwd=current_dir, ip=target), shell=True)
    find_ftp1 = find_ftp.decode('utf8')

    if "ftp" in find_ftp1:

        ftp_ports = subprocess.check_output("cat {pwd}/scans/{ip}/nmap/main.txt | grep tcp | grep ftp | cut -d ' ' -f 1 | cut -d '/' -f 1 | tr '\n' ',' | rev | cut -c 2- | rev".format(pwd=current_dir, ip=target), shell=True)
        open_ftp = ftp_ports.decode('utf8').rstrip().split(',')



        for x in open_ftp:
            print("")
            print("")
            print("#" * 70)
            print("Running FTP Enumeration on Port {x}  -  Nmap".format(x=x))
            print("#" * 70)
            print("")
            print("")
            ftp_enum = "nmap -p{x} -A -Pn -oN {pwd}/scans/{ip}/nmap/{x}-ftp.txt {ip}".format(x=x, pwd=current_dir, ip=target)
            os.system(ftp_enum)


    # Enumerate SSH

    find_ssh = subprocess.check_output("cat {pwd}/scans/{ip}/nmap/main.txt | grep tcp | grep open | grep ssh".format(pwd=current_dir, ip=target), shell=True)
    find_ssh1 = find_ssh.decode('utf8')

    if "ssh" in find_ssh1:

        ssh_ports = subprocess.check_output("cat {pwd}/scans/{ip}/nmap/main.txt | grep tcp | grep ssh | cut -d ' ' -f 1 | cut -d '/' -f 1 | tr '\n' ',' | rev | cut -c 2- | rev".format(pwd=current_dir, ip=target), shell=True)
        open_ssh = ssh_ports.decode('utf8').rstrip().split(',')



        for x in open_ssh:
            print("")
            print("")
            print("#" * 70)
            print("Running SSH Enumeration on Port {x}  -  Nmap".format(x=x))
            print("#" * 70)
            print("")
            print("")
            ssh_enum = "nmap -p{x} -A -Pn -oN {pwd}/scans/{ip}/nmap/{x}-ftp.txt {ip}".format(x=x, pwd=current_dir, ip=target)
            os.system(ssh_enum)


    if "445" in open_ports:
        print("")
        print("")
        print("#" * 70)
        print("Running SMB Enumeration on Port 445")
        print("#" * 70)
        print("")
        print("")
        smb_enum = "nmap -p139,445 -A -Pn -oN {pwd}/scans/{ip}/nmap/smb.txt {ip}".format(pwd=current_dir, ip=target)
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


def part():
	print_lock = threading.Lock()
	print("")
	target = input("Enter your target IP: ")


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
		if port == 1000:
			print("10% Complete")
		if port == 5000:
			print("20% Complete")
		if port == 10000:
			print("30% Complete")
		if port == 20000:
			print("40% Complete")
		if port == 30000:
			print("50% Complete")
		if port == 40000:
			print("60% Complete")
		if port == 50000:
			print("70% Complete")
		if port == 60000:
			print("80% Complete")
		if port == 65000:
			print("90% Complete")

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
	print("Running Nmap Service Enumeration")
	print("#" * 70)
	print("")
	print("")
	dir_nmap = "mkdir {pwd}/scans/{ip}/nmap 2>/dev/null".format(pwd=current_dir, ip=target)
	os.system(dir_nmap)
	light_serv_enum = "nmap -p{ports} -A -Pn -T4 -oN {pwd}/scans/{ip}/nmap/main.txt {ip}".format(ports=",".join(open_ports), pwd=current_dir, ip=target)
	os.system(light_serv_enum)




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
