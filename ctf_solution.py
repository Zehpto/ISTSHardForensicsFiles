from scapy.all import *
import binascii, base64
from zipfile import ZipFile

def fontRed(string):
	return("\033[1;31m%s\033[1;m\033[1;37m\033[1;m" % string)

def fontMagenta(string):
	return("\033[1;35m%s\033[1;m\033[1;37m\033[1;m" % string)	

def fontGreen(string):
	return("\033[1;32m%s\033[1;m\033[1;37m\033[1;m" % string)

def fontBlue(string):
	return("\033[1;34m%s\033[1;m\033[1;37m\033[1;m" % string)

def main():
	packets = rdpcap('hard.pcap')

	baseFile = ""
	binaryPassword = ""
	prevRequest = ""
	request = ""

	for packet in packets:
		if packet.haslayer(DNS):
			if packet.haslayer(IP):
				if packet[IP].src == "192.168.1.42" or packet[IP].src == "192.168.1.248":
					prevRequest = request
					request = packet.summary()[28:].split('.')

					if packet[IP].flags == 0x06:

						binaryPassword += "1"

						if prevRequest[0] == "equals":
							baseFile += '='
						else:
							baseFile += prevRequest[0]

					elif packet[IP].flags == 0x00:

						if packet.haslayer(DNSRR):
							binaryPassword += "0"


	print("Base64 File: %s\n" % fontRed(baseFile))
	print("Binary Password: %s\n" % fontBlue(binaryPassword))
	n = int('0b' + binaryPassword, 2)
	recoveredPassword = (binascii.unhexlify('%x' % n))
	print("Recovered Password: " + fontMagenta(recoveredPassword))


	print("\nWriting archive to current directory...")
	# Write Archive to Disk
	archive = "null.zip"
	with open(archive, "wb") as f:
		f.write(base64.b64decode(baseFile))
	f.close()

	print("\nExtracting flag.txt...")
	with ZipFile(archive) as zf:
		zf.extractall(pwd=recoveredPassword)
	zf.close()

	with open("flag.txt", "r") as flagFile:
		flag = flagFile.read()
	flagFile.close()

	print("\nContent:\n%s" % fontGreen(flag))


main()
