#!/usr/bin/python
# Create a certificate with openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# Modify variables below for server IP address, port number etc. 
# Easy way to generate a SYSLOG message that works with this code is -> nc -w0 -u 192.168.0.5 514 <<< "1.1.1.36/32"

from scapy.all import *
import time
import os
from netaddr import *
import BaseHTTPServer, SimpleHTTPServer
import ssl


file = 'feed'
compressed_file = 'feed.gz'
server_ip = 'Server_IP'
port = '4443'

vpnlist = [IPNetwork(line.rstrip('\n')) for line in open(file)]
vpnlist.sort()
print "Existing VPN list loaded..."

def start_server():
    httpd = BaseHTTPServer.HTTPServer((server_ip, int(port)), SimpleHTTPServer.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
    print "Server running and serving at https://"+server_ip+":"+port+"/"+compressed_file
    print "JUNOS SRX configuration"
    print "=========="
    print "set security dynamic-address feed-server custom-feed hostname "+server_ip+":"+port
    print "set security dynamic-address feed-server custom-feed update-interval 30"
    print "set security dynamic-address feed-server custom-feed hold-interval 300"
    print "set security dynamic-address feed-server custom-feed feed-name "+file+" path "+compressed_file
    print "set security dynamic-address address-name custom-feed profile feed-name custom-feed"
    print "=========="
    httpd.serve_forever()

def write_to_file(vpnlist):
    txt_file = open(file, "w+")
    for ip_addr in vpnlist:
        txt_file.write(str(ip_addr)+"\n")
    txt_file.close()
    gzip_file()

def gzip_file():
    with open(file) as f_in, gzip.open(compressed_file, 'wb') as f_out:
        f_out.writelines(f_in)

def syslog_print(packet):
    line = str(packet[UDP].payload)
    log = line.split('\n')
    ip_addr = IPNetwork(log[0])
    if ip_addr not in vpnlist:
        print "New address detected -> "+str(ip_addr)
        vpnlist.append(ip_addr)
        vpnlist.sort()
        #print vpnlist
        write_to_file(vpnlist)

thread.start_new_thread(start_server, ())
sniff(prn=syslog_print, filter='udp and (port 514) and (not ip6)', store=0)
