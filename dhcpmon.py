#!/usr/bin/python
from scapy.all import *
import os
import io
import re
import sys
import getpass
import time
from datetime import datetime

DEBUGMODE=False
CONFIGFILE=r"~/.dhcplisten"
HOSTSFILE=r"/srv/storage/data/macaddresses.csv"
OUIFILE="/srv/storage/data/ouis.csv"
MAXCOUNT = -1
detectcount = 0

# Format of tuples [ name, device_type, interface_type, mac_address ]
known_devices = [ ]

# Manufacturers
manufacturers = [ ]

# Debug Messages (Enabled by DEBUGMODE=True)
def DbgMsg(message):
	global DEBUGMODE

	if DEBUGMODE:
		print "{0} : {1}\n".format(datetime.now(),message)

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

		print "Loaded {0} oui code record(s)".format(len(manufacturers))
	else:
		print "Oui code file {0} not found!".format(ouifile)

# Load Hosts file if located
def LoadHosts(hostsfile):
	global known_devices

	if os.path.exists(hostsfile):
		loadedcount = 0

		print "Loading hosts file : {0}".format(hostsfile)

		with open(hostsfile,"r") as hosts:
			for line in hosts:
				if re.match(r"^\s*\#",line) is None:
					t = line.strip().split(',')

					known_devices.append(t)
					loadedcount = loadedcount + 1

		print "Loaded {0} hosts record(s)".format(loadedcount)
	else:
		print "Hosts file {0} not found!".format(hostsfile)

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

# DHCP Handler
def dhcp_display(pkt):
	global detectcount

	srcMacAddress = ""

	if DHCP in pkt and IsDiscover(pkt):
		srcMacAddress = pkt[Ether].src

		found = False

		device = SearchKnownDevices(srcMacAddress)

		if not device is None:
			print "{0} - {1}/{2} - {3}".format(device[0],device[1],device[2],srcMacAddress)
			detectcount = detectcount + 1
		else:
			manufacturer = FindManufacturer(srcMacAddress)
			print "New/Unknown Device : {0} - {1}".format(srcMacAddress,manufacturer)
			detectcount = detectcount + 1

if __name__ == "__main__":

	if AmIRoot():
		LoadConfig(CONFIGFILE)
		LoadHosts(HOSTSFILE)
		LoadOuis(OUIFILE)

		if DEBUGMODE:
			MAXCOUNT=5

		print "Now listening for DHCP DISCOVER Packets..."
		while detectcount < MAXCOUNT or MAXCOUNT == -1:
			list = sniff(prn=dhcp_display, filter="udp and port 67", store=0, count=60)
			time.sleep(0.5)
	else:
		print "You need to run this as root"
