#Importing the necessary modules
import logging
import subprocess
import re

#Importing Scapy and handling the ImportError exception
try:
    from scapy.all import *

except ImportError:
    print("Scapy is not installed on your system.")
    print("Try using: sudo pip3.8 install scapy")
    sys.exit()

#This will suppress all messages that have a lower level of seriousness than error messages.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

#Setting the checkIPaddr parameter to False
conf.checkIPaddr = False

#Reading allowed DHCP servers from an external file
with open("dhcp.txt") as f:
    allowed_dhcp_servers = f.read()

#Listing all network interfaces on the Ubuntu host
host_if = subprocess.run(["ip link"], shell = True, stdout = subprocess.PIPE)
#print(host_if)

#Extracting interface names from the output stored above
interfaces = re.findall(r"\d:\s(.+?):\s", str(host_if))
#print(interfaces)

#Detecting Rogue DHCP servers per interface (except the loopback interface)
for interface in interfaces:
    if interface != "lo":
        #Getting the hardware address
        hw = get_if_raw_hwaddr(interface)[1]
        #print(hw)

        #Creating the DHCP Discover packet
        dhcp_discover = Ether(dst = "ff:ff:ff:ff:ff:ff") / IP(src = "0.0.0.0", dst = "255.255.255.255") / UDP(sport = 68, dport = 67) / BOOTP(chaddr = hw) / DHCP(options = [("message-type", "discover"), "end"])

        #Sending the Discover packet and accepting multiple answers for the same Discover packet
        ans, unans = srp(dhcp_discover, multi = True, iface = interface, timeout = 5, verbose = 0)
        #print(ans)
        #print(unans)

        #Defining a dictionary to store mac-ip pairs
        mac_ip = {}

        for pair in ans:
            #print(pair)
        	mac_ip[pair[1][Ether].src] = pair[1][IP].src

        if ans:
            #Printing the results
            print("\n--> The following DHCP servers found on the {} LAN:\n".format(interface))

            for mac, ip in mac_ip.items():
                if ip in allowed_dhcp_servers:
                    print("OK! IP Address: {}, MAC Address: {}\n".format(ip, mac))
                else:
                    print("ROGUE! IP Address: {}, MAC Address: {}\n".format(ip, mac))

        else:
            print("\n--> No active DHCP servers found on the {} LAN.\n".format(interface))

    else:
        pass

#End of program
