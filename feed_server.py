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
from IPy import IP

#vars

psiphon_servers_file = 'vpnfeed'
psiphon_clients_file = 'clientfeed'
psiphon_servers_file_compressed = 'vpnfeed.gz'
psiphon_clients_file_compressed = 'clients.gz'
server_ip = '0.0.0.0'
port = '4443'



def init_logger():

  logging.basicConfig(filename='./feeds_server_log',
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
    print "set security dynamic-address address-name custom-feed-psiphon-nodes profile feed-name vpnfeed"
    print "set security dynamic-address feed-server custom-feed feed-name "+psiphon_clients_file+" path "+psiphon_clients_file_compressed
    print "set security dynamic-address address-name custom-feed-clients profile feed-name clientfeed"
    print "=========="
    httpd.serve_forever()


def isNewEntry(f, ip):

    isFound = False

    f.seek(0)
    for line in f:
      if line.split(";")[0] == ip: 
        isFound = True

    return isFound  

def write_to_file(f, f_gz, liste):

    global _lock

    while _lock.locked():
        time.sleep(1)
        logger.error("Cant acquire lock. Wait 1 sec and retry.")
        continue

    _lock.acquire()

    txt_file = open(f, "a+")
    now = time.time()
    for ip in liste:
      if isNewEntry(txt_file, ip) == False:
        #print "IP %s does not exist in the file %s" % (ip, f)
        txt_file.seek(2)
        txt_file.write(str(ip)+";"+str(now)+"\n")
      #else:
        #print "IP %s is already known in the file %s" % (ip, f)
    txt_file.close()

    #release
    _lock.release()
    gzip_file(f, f_gz)

def gzip_file(f, f_compressed):

  ip_list = []

  with open(f) as f_in, gzip.open(f_compressed, 'w') as f_out:
    for line in f_in:
      ip = line.split(";")[0]
      ip_list.append(ip)
    # required to sort IP properly
    ipl = [(IP(ip).int(), ip) for ip in ip_list]
    ipl.sort()
    ip_list = [ip[1] for ip in ipl]
    for elt in ip_list:
      f_out.write(elt+"\n")



def syslog_print(packet):
    psiphon_server_regex = re.compile(r'^.*source-address=\"(([0-9]{1,3}\.){3}[0-9]{1,3}).*destination-address=\"(([0-9]{1,3}\.){3}[0-9]{1,3}).*(attack-name=\"PSIPHON-).*$')
    psiphon_client_regex = re.compile(r'^.*RT_FLOW_SESSION_DENY.*source-address=\"(([0-9]{1,3}\.){3}[0-9]{1,3}).*(policy-name=\"Block-Psiphon-Users).*$')
    line = str(packet[UDP].payload)
    log = line.split('\n')

    psiphon_syslog_idp = psiphon_server_regex.search(log[0])
    psiphon_syslog_rt = psiphon_client_regex.search(log[0])
    if psiphon_syslog_idp != None:
        #print "match! Source IP: "+str(psiphon_syslog_idp.group(1))+" - Destination IP "+str(psiphon_syslog_idp.group(3))+"\n"
        ip_addr = psiphon_syslog_idp.group(3) + "/32"
        #ip_addr = IPNetwork(log[0])
        if ip_addr not in vpnlist:
            logger.info("New server detected -> %s" % str(ip_addr))
            vpnlist.append(ip_addr)
            vpnlist.sort()
            write_to_file(psiphon_servers_file, psiphon_servers_file_compressed, vpnlist)

        ip_client = psiphon_syslog_idp.group(1) + "/32"
        if ip_client not in clientlist:
            logger.info("New Client detected -> %s" % str(ip_client))
            clientlist.append(ip_client)
            clientlist.sort()
            write_to_file(psiphon_clients_file, psiphon_clients_file_compressed, clientlist)
    elif psiphon_syslog_rt != None:
        logger.info("Match! New Source Client IP of a psiphon user: %s" % str(psiphon_syslog_rt.group(1)))
        ip_client = psiphon_syslog_rt.group(1) + "/32"
        if ip_client not in clientlist:
            logger.info("This Client is not is in the current blocking list -> %s" % str(ip_client))
            clientlist.append(ip_client)
            clientlist.sort()
            write_to_file(psiphon_clients_file, psiphon_clients_file_compressed, clientlist)



def fileExist(fname, gz=None):

  if os.path.isfile(fname):
    return True
  else:
    if gz != None:
      gzip.open(fname, 'a').close()
    else:
      open(fname, 'a').close()
  return True


def monitorClientsList(filename):

  global _lock

  client_to_remove = []

  logger.debug("Starting thread for clients notification feed update")

  while True:

    while _lock.locked():
        time.sleep(1)
        logger.error("cant acquire lock on the file")
        continue

    _lock.acquire()

    logger.debug("Checking if some clients can be removed from notification feed.")
    if os.path.exists(filename):
      f = open(filename, "r")
      #dump current data
      data = f.readlines()
      f.seek(0)
      for client in f:
        # lets fix it to 5 minutes -> 300 seconds
        if time.time() - float(client.split(";")[1]) > 100:
	  #can be remobe from the list
	  if client.split(";")[0] not in client_to_remove:
   	    client_to_remove.append(client.split(";")[0])
      f.close()
    else:
      logger.debug("Cannot find the file %s" %filename)

    # test if any entries has to be removed.
    if len(client_to_remove) > 0:
      logger.info("%d clients can be removed from the notification feed" % len(client_to_remove))
      
      #open file
      f_client = open(filename, 'w+')
      #f.seek(0)
      #data = f.readlines()
      logger.info("data is %s" %data)	
      f_client.seek(0)
      for i in data:
        ip_client = i.split(";")[0]
        logger.debug("comparing now %s (%s)" % (ip_client, i))
        if ip_client not in client_to_remove:
          f_client.write(i)
        else:
          logger.debug("Found %s in file (%s)" % ( ip_client, i))
          logger.info("Client IP %s has been removed" %ip_client)
          client_to_remove.remove(ip_client)
          logger.debug("Client list is: %s" % clientlist)
          logger.debug("Client List to remove is: %s" % client_to_remove)
          clientlist.remove(ip_client)
          logger.debug("Client list is now: %s" % clientlist)
          logger.debug("Client List to remove is now: %s" % client_to_remove)

      #unlock and close
      f_client.close()
        
      #rewrite gz
      gzip_file(filename, psiphon_clients_file_compressed)

    else:
      logger.debug("No entry has expired")

    _lock.release()
    time.sleep(20)

if __name__ == "__main__":

    init_logger()

    fileExist(psiphon_servers_file)
    fileExist(psiphon_clients_file)
    fileExist(psiphon_servers_file_compressed, "gz")
    fileExist(psiphon_clients_file_compressed, "gz")

    vpnlist = [IPNetwork(line.rstrip('\n').split(";")[0]) for line in open(psiphon_servers_file)]
    vpnlist.sort()
    logger.info("Existing VPN list loaded...")

    clientlist = [IPNetwork(line.rstrip('\n').split(";")[0]) for line in open(psiphon_clients_file)]
    clientlist.sort()
    logger.info("Existing Clients list loaded...")

    _lock = thread.allocate_lock()

    thread.start_new_thread(start_server, ())
    thread.start_new_thread(monitorClientsList, (psiphon_clients_file,))
    sniff(prn=syslog_print, filter='udp and (port 514) and (not ip6)', store=0)

    
