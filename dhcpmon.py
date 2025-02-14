#!/usr/bin/env python3
from scapy.all import *
import os
import io
import re
import sys
import getpass
import time
from datetime import datetime

DEBUGMODE=True
CONFIGFILE=r"~/.dhcplisten"
HOSTSFILE=r"/srv/storage/data/macaddresses.csv"
OUIFILE="/srv/storage/data/ouis.csv"
MAXCOUNT = -1
detectcount = 0

# Format of tuples [ name, device_type, interface_type, mac_address ]
known_devices = [ ]

# Manufacturers
manufacturers = [ ]

# Detected DHCP Servers [ mac, ip, detected_timestamp ]
dhcpservers = [ ]

# Server Replies [ from, to_who, ip, mask, router, dns1, timestamp ]
serverreplies = [ ]

# Detected DHCP Clients [ timestamp, mac, ip, xid, manu, known_record ]
dhcpclients = [ ]

# Debug Messages (Enabled by DEBUGMODE=True)
def DbgMsg(message):
	global DEBUGMODE

	if DEBUGMODE:
		print("{0} : {1}\n".format(datetime.now(),message))

# AmIRoot : Because I must be Root to work
def AmIRoot():
	if getpass.getuser() == "root":
		return True

	return False

# Load Manufacturers
def LoadOuis(ouifile):
	global manufacturers

	if os.path.exists(ouifile):
		with open(ouifile,"r") as ouis:
			for line in ouis:
				data = line.strip().split(",")

				manu = [ data[0], data[2], data[1] ]

				manufacturers.append(manu)

		print("Loaded {0} oui code record(s)".format(len(manufacturers)))
	else:
		print("Oui code file {0} not found!".format(ouifile))

# Load Hosts file if located
def LoadHosts(hostsfile):
	global known_devices

	if os.path.exists(hostsfile):
		loadedcount = 0

		print("Loading hosts file : {0}".format(hostsfile))

		with open(hostsfile,"r") as hosts:
			for line in hosts:
				if re.match(r"^\s*\#",line) is None:
					t = line.strip().split(',')

					known_devices.append(t)
					loadedcount = loadedcount + 1

		print("Loaded {0} hosts record(s)".format(loadedcount))
	else:
		print("Hosts file {0} not found!".format(hostsfile))

# Load Config File
def LoadConfig(configfile):
	global MAXCOUNT, known_devices, DEBUGMODE

	if os.path.exists(configfile):
		with open(configfile,"r") as config:
			for line in config:
				data = line.strip().split(" ")

				if data[0] == "maxcount":
					MAXCOUNT = int(data[1])
				elif data[0] == "hosts":
					LoadHosts(data[1])
				elif data[0] == "debugmode":
					DEBUGMODE=True

# Find Manufacturer
def FindManufacturer(macaddress):
	global manufacturers

	manufact = "Unknown"

	for manu in manufacturers:
		if macaddress.startswith(manu[0]):
			manufact = manu[2]
			break

	return manufact

# Attempt to find MACAddress in know devices list
def SearchKnownDevices(macaddress):
	global known_devices

	device = None

	for item in known_devices:
		if macaddress == item[3]:
			device = item
			break

	return device

# Test Routine
def Test(pkt):
	pass

# IsDiscover : Determine if DHCP packet is a discover packet
def IsDiscover(pkt):
	flag = False

	for opt in pkt[DHCP].options:
		if opt[0] == "message-type" and opt[1] == 1:
			flag = True
			break

	return flag

# IsOffer : Detect DHCP Offer Packet
def IsOffer(pkt):
        flag = False

        for opt in pkt[DHCP].options:
                if opt[0] == "message-type" and opt[1] == 2:
                        flag = True
                        break

        return flag

# IsRequest : Detect DHCP Request Packet
def IsRequest(pkt):
        flag = False

        for opt in pkt[DHCP].options:
                if opt[0] == "message-type" and opt[1] == 3:
                        flag = True
                        break

        return flag

# IsACK : Detect DHCP Ack Packet
def IsACK(pkt):
        flag = False

        for opt in pkt[DHCP].options:
                if opt[0] == "message-type" and opt[1] == 4:
                        flag = True
                        break

        return flag

# ProcessDiscover : Process discover packet
def ProcessDiscover(pkt):
        global dhcpclients, detectcount

        detectcount = detectcount + 1
        srcMacAddress = pkt[Ether].src

        if not srcMacAddress in dhcpclients[1:1]:
                device = SearchKnownDevices(srcMacAddress)
                manufacturer = FindManufacturer(srcMacAddress)

                client = [ datetime.now(), srcMacAddress, "", pkt[BOOTP].xid, manufacturer, device ]

                if not device is None:
                        print("{0} {1} - {2}/{3} - {4}".format(client[0],device[0],device[1],device[2],srcMacAddress))
                else:
                        print("{0} New/Unknown Device : {1} - {2}".format(client[0],srcMacAddress,manufacturer))
        else:
                print("{0} {1} sent another discover packet".format(datetime.now(),srcMacAddress))

# ProcessOffer : Process Offer Packets
def ProcessOffer(pkt):
        global dhcpclients, dhcpservers, serverreplies

        server = [ pkt[Ether].src, pkt[IP].src, datetime.now() ]

        if not server[0] in dhcpservers[0:0]:
                dhcpservers.append(server)

        # map pkt[BOOTP].xid to xid in client record
        target = None

        for client in dhcpclients:
                if client[3] == pkt[BOOTP].xid:
                        target = client[1]
                        break

        reply = [ pkt[IP].src, target, pkt[BOOTP].yiaddr, pkt[DHCP].options[8], pkt[DHCP].options[10], pkt[DHCP].options[12], datetime.now() ]

        serverreplies.append(reply)

        if target is None:
                target = "Unknown"

        print("{0} {1} replied to {2} with {3}".format(reply[6],reply[0],target,reply[2]))

# DumpPacket : Debugging Dump Packet
def DumpPacket(pkt):
        if DEBUGMODE:
                pkt.summary()
                # pkt.show()
                pkt.show2()

                if DHCP in pkt:
                        for opt in pkt[DHCP].options:
                                if opt[0] == "message-type":
                                        print("**** DHCP Message Option : {0}".format(opt[1]))

# DHCP Handler
def dhcp_display(pkt):
	global detectcount

	srcMacAddress = ""

	if DHCP in pkt:
                # DumpPacket(pkt)

                if IsDiscover(pkt):
                        ProcessDiscover(pkt)
                elif IsOffer(pkt):
                        ProcessOffer(pkt)
                elif IsRequest(pkt):
                        pass
                elif IsACK(pkt):
                        pass

if __name__ == "__main__":

	if AmIRoot():
		LoadConfig(CONFIGFILE)
		LoadHosts(HOSTSFILE)
		LoadOuis(OUIFILE)

		if DEBUGMODE:
			MAXCOUNT=5

		print("Now listening for DHCP DISCOVER Packets...")
		while detectcount < MAXCOUNT or MAXCOUNT == -1:
			list = sniff(prn=dhcp_display, filter="udp and port 67", store=0, count=60)
			time.sleep(0.5)
	else:
		print("You need to run this as root")
