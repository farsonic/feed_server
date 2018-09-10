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
import logging

#vars

psiphon_servers_file = 'vpnfeed'
psiphon_clients_file = 'clientfeed'
psiphon_servers_file_compressed = 'vpnfeed.gz'
psiphon_clients_file_compressed = 'clients.gz'
server_ip = '0.0.0.0'
port = '4443'



def init_logger():

  logging.basicConfig(filename='./thread_clients_update',
                      level = logging.INFO,
                      format='%(asctime)s %(levelname)-8s %(message)s',
                      datefmt='%a, %d %b %Y %H:%M:%S')
  global logger
  logger = logging.getLogger(__name__) 

  logger.info(" -- Start -- ")

  return logger;

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
    now = time.time()
    for ip in liste:
        txt_file.write(str(ip)+";"+str(now)+"\n")
    txt_file.close()
    gzip_file(f, f_gz)

def gzip_file(f, f_compressed):
    with open(f) as f_in, gzip.open(f_compressed, 'wb') as f_out:
	for line in f_in:
		ip = line.split(";")[0]
        	f_out.write(ip+"\n")

def syslog_print(packet):
    psiphon_server_regex = re.compile(r'^.*source-address=\"(([0-9]{1,3}\.){3}[0-9]{1,3}).*destination-address=\"(([0-9]{1,3}\.){3}[0-9]{1,3}).*(attack-name=\"PSIPHON-).*$')
    line = str(packet[UDP].payload)
    log = line.split('\n')

    psiphon_syslog = psiphon_server_regex.search(log[0])
    if psiphon_syslog != None:
        #print "match! Source IP: "+str(psiphon_syslog.group(1))+" - Destination IP "+str(psiphon_syslog.group(3))+"\n"
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


def monitorClientsList(filename):

  client_to_remove = []

  logger.info("Starting thread for clients notification feed update")

  while True:

    logger.info("Checking if some clients can be removed from notification feed.")
    if os.path.exists(filename):
      f = open(filename, "r")
      for client in f:
        # lets fix it to 5 minutes -> 300 seconds
        if time.time() - float(client.split(";")[1]) > 300:
	  #can be remobe from the list
   	  client_to_remove.append(client.split(";")[0])
      f.close()
    else:
      logger.info("Cannot find the file %s" %filename)

    if len(client_to_remove) > 0:
      logger.info("%d clients can be removed from the notification feed" % len(client_to_remove))
      try:
        logger.info("Trying to open %s to remove expired entries" % filename)
        f = open(filename, 'a')
        if f:
          logger.info("%s is not locked. Cleaning the file" % filename)
          data = f.readlines()
          f.seek(0)
          for i in data:
            ip_client = i.split(";")[0]
            if ip_client not in client_to_remove:
              f.write(i)
            else:
              logger.info("Client IP %s has been removed" %ip_client)
              client_to_remove.remove(ip_client)
          f.truncate()
      except IOError, message:
        logger.info("File is locked (unable to open in append mode). Retry in next iteration.")
      finally:
        if f:
          f.close()
          logger.info("%s closed." % filename)
    else:
      logger.info("No entry has expired")

    time.sleep(10)

if __name__ == "__main__":

    init_logger()

    fileExist(psiphon_servers_file)
    fileExist(psiphon_clients_file)

    vpnlist = [IPNetwork(line.rstrip('\n').split(";")[0]) for line in open(psiphon_servers_file)]
    vpnlist.sort()
    print "Existing VPN list loaded..."

    clientlist = [IPNetwork(line.rstrip('\n').split(";")[0]) for line in open(psiphon_clients_file)]
    clientlist.sort()
    print "Existing Clients list loaded..."

    thread.start_new_thread(start_server, ())
    thread.start_new_thread(monitorClientsList, (psiphon_clients_file,))
    sniff(prn=syslog_print, filter='udp and (port 514) and (not ip6)', store=0)

    
