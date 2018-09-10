#!/usr/bin/python
# Create a certificate with openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# Modify variables below for server IP address, port number etc.

import thread
import time
import os
import re
import BaseHTTPServer, SimpleHTTPServer
import ssl
from netaddr import *
from scapy.all import *


#vars

psiphon_servers_file = 'vpnfeed'
psiphon_clients_file = 'clientfeed'
psiphon_servers_file_compressed = 'vpnfeed.gz'
psiphon_clients_file_compressed = 'clients.gz'
server_ip = '0.0.0.0'
port = '4443'


def start_server():
    httpd = BaseHTTPServer.HTTPServer((server_ip, int(port)), SimpleHTTPServer.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
    print "Server running and serving at https://"+server_ip+":"+port+"/"+psiphon_servers_file_compressed
    print "Server running and serving at https://"+server_ip+":"+port+"/"+psiphon_clients_file_compressed
    print "JUNOS SRX configuration"
    print "=========="
    print "set security dynamic-address feed-server custom-feed hostname "+server_ip+":"+port
    print "set security dynamic-address feed-server custom-feed update-interval 30"
    print "set security dynamic-address feed-server custom-feed hold-interval 300"
    print "set security dynamic-address feed-server custom-feed feed-name "+psiphon_servers_file+" path "+psiphon_servers_file_compressed
    print "set security dynamic-address address-name custom-feed profile feed-name custom-feed"
    print "set security dynamic-address feed-server custom-feed feed-name "+psiphon_clients_file+" path "+psiphon_clients_file_compressed
    print "set security dynamic-address address-name custom-feed-clients profile feed-name clientfeed"
    print "=========="
    httpd.serve_forever()

def write_to_file(f, f_gz, liste):
    txt_file = open(f, "w+")
    for ip in liste:
        txt_file.write(str(ip)+"\n")
    txt_file.close()
    gzip_file(f, f_gz)

def gzip_file(f, f_compressed):
    with open(f) as f_in, gzip.open(f_compressed, 'wb') as f_out:
        f_out.writelines(f_in)

def syslog_print(packet):
    psiphon_server_regex = re.compile(r'^.*source-address=\"(([0-9]{1,3}\.){3}[0-9]{1,3}).*destination-address=\"(([0-9]{1,3}\.){3}[0-9]{1,3}).*(attack-name=\"PSIPHON-).*$')
    line = str(packet[UDP].payload)
    log = line.split('\n')

    psiphon_syslog = psiphon_server_regex.search(log[0])
    if psiphon_syslog != None:
        print "match! Source IP: "+str(psiphon_syslog.group(1))+" - Destination IP "+str(psiphon_syslog.group(3))+"\n"
        ip_addr = psiphon_syslog.group(3) + "/32"
        #ip_addr = IPNetwork(log[0])
        if ip_addr not in vpnlist:
            print "New server detected -> "+str(ip_addr)
            vpnlist.append(ip_addr)
            vpnlist.sort()
            #print vpnlist
            write_to_file(psiphon_servers_file, psiphon_servers_file_compressed, vpnlist)

        ip_client = psiphon_syslog.group(1) + "/32"
        if ip_client not in clientlist:
            print "New Client detected -> "+str(ip_client)
            clientlist.append(ip_client)
            clientlist.sort()
            write_to_file(psiphon_clients_file, psiphon_clients_file_compressed, clientlist)
        else:
            print "Client %s already known" %ip_client


def fileExist(fname):

  if os.path.isfile(fname):
    return True
  else:
    open(fname, 'a').close()
    return True



if __name__ == "__main__":

    fileExist(psiphon_servers_file)
    fileExist(psiphon_clients_file)

    vpnlist = [IPNetwork(line.rstrip('\n')) for line in open(psiphon_servers_file)]
    vpnlist.sort()
    print "Existing VPN list loaded..."

    clientlist = [IPNetwork(line.rstrip('\n')) for line in open(psiphon_clients_file)]
    clientlist.sort()
    print "Existing Clients list loaded..."

    thread.start_new_thread(start_server, ())
    sniff(prn=syslog_print, filter='udp and (port 514) and (not ip6)', store=0)
