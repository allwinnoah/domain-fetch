import subprocess
import requests
import json
import xmltodict
import socket
import nmap
import re
import pyfiglet
from datetime import datetime
from tabulate import tabulate

# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# Initialising the port numbers, will be using the variables later on.
port_min = 0
port_max = 65535


ascii_banner = pyfiglet.figlet_format("ASSET DISCOVERY TOOL")
print(ascii_banner)
print("-" * 50)

# Set the target domain
target_domain = input("Enter the domain name:")

# Look up the IP address for the target domain
try:
	ip_address = socket.gethostbyname(target_domain)
# Print the IP address
	print(f"IP address for {target_domain}: {ip_address}")
except socket.gaierror:
	print(f"NO IP address for {target_domain}")	
print("-" * 50)


print("Sub-Domain Scanning started at:" + str(datetime.now()))
print("Please Wait")
print("- "*25)

# Find the subdomains of the target domain
subdomain_response = subprocess.run(["assetfinder", "--subs-only", target_domain], capture_output=True).stdout.decode().split("\n")
#subdomains = [s for s in subdomain_response if s]
#print(subdomains)
subdomain=list(set(subdomain_response))
subdomain.sort()
if not subdomain:
	print("No Possible Subdomains are found")
else:
	headers = ["Subdomain", "IP Address"]
	table_data = []
	print(f"Subdomains for {target_domain}:")
	#httprobe_response = subprocess.run(["httprobe", *subdomain], capture_output=True).stdout.decode().split("\n")
	for s in range(0,len(subdomain)-1):
		#subdomain_alive = False
		try:
			subdomain_ip = socket.gethostbyname(subdomain[s+1])
		except socket.gaierror:
			subdomain_ip = "No IP Found"
		#if subdomain[s+1] in httprobe_response:
			#subdomain_alive = True
		table_data.append([subdomain[s+1], subdomain_ip])
		#print("%s    {%s}"%(subdomain[s+1],subdomain_ip))
		print("%s"%(subdomain[s+1]))
	print(tabulate(table_data, headers, tablefmt="fancy_grid"))
	print("\n")
	print("Total Subdomains found: %s"%(len(subdomain)-1))
print("-" * 50)

while True:
    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning all the ports is not advised.
    print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
    port_range = input("Enter port range: ")
    # We pass the port numbers in by removing extra spaces that people sometimes enter. So if you enter 80 - 90 instead of 80-90 the program will still work.
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        # We're extracting the low end of the port scanner range the user want to scan.
        port_min = int(port_range_valid.group(1))
        # We're extracting the upper end of the port scanner range the user want to scan.
        port_max = int(port_range_valid.group(2))
        break

print("Port Scanning started at:" + str(datetime.now()))
print("Please Wait")
print("- "*25)
#Find the open ports on the target IP address
# initialize the port scanner
nmScan = nmap.PortScanner()

# scan host for ports in range 
nmScan.scan(target_domain, str(port_range), arguments=' -sV -A -T5 -Pn')
print(nmScan.scaninfo())
#print(nmScan.all_hosts())
#run a loop to print all the found result about the ports
for host in nmScan.all_hosts():
     print('Host : %s (%s)' % (host, nmScan[host].hostname()))
     print('State : %s' % nmScan[host].state())
     for proto in nmScan[host].all_protocols():
         print('----------')
         print('Protocol : %s\n' % proto)
         lport = nmScan[host][proto].keys()
         for port in lport:
         	if(nmScan[host][proto][port]['state']=='open'):
         		print('Port : %s'%port)
         		print('Port_state : %s'%nmScan[host][proto][port]['state'])
         		print('Service : %s'%nmScan[host][proto][port]['name'])
         		print('Product : %s'%nmScan[host][proto][port]['product'])
         		if not nmScan[host][proto][port]['version']:
         			print("Version not listed")
         		else:
         			print('Version: %s'%nmScan[host][proto][port]['version'])
         		print('\n')
print("-" * 50)

print("Retriving CVE at nist.gov start at:" + str(datetime.now()))
print("Please Wait")
print("- "*25)
# Find the CVEs associated with the target domain
cve_response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/1.0", headers={"Accept": "application/json"}, params={"product": f"web server:{target_domain}"})
cve_data = cve_response.json()
cves = cve_data["result"]["CVE_Items"]
print(f"Possible CVEs for {target_domain}:")
for cve in cves:
    print(cve["cve"]["CVE_data_meta"]["ID"])
