import sys
from scapy.all import *

ICMP_ECHO_REQUEST = 8
MAX_TIMEOUT = 2
VM_INTERFACE = "VMware Virtual Ethernet Adapter for VMnet1"

def detect_promiscuous(device_ip):
    # Build the ethernet layer with fake destination address
    request_packet = Ether(dst="ab:cd:ef:11:22:33")
    # Add IP layer with the (real) target IP 
    request_packet /= IP(dst=device_ip)
    # Craft ICMP echo request (ping)
    request_packet /= ICMP(type=ICMP_ECHO_REQUEST)

     # Send the packet and check the results
    response = srp1(request_packet, timeout=MAX_TIMEOUT, iface=VM_INTERFACE, verbose=False)

    # If no repnonse came back - the request has been filtered and therefore we can assume that the target 
    # NIC is not in promiscuous mode.
    if response is None:
        print("Device {DEVICE_IP} is not in promiscuous mode.".format(DEVICE_IP = device_ip))
    else:
        print("Device {DEVICE_IP} is in promiscuous mode.".format(DEVICE_IP = device_ip))
        

def main():
    target_device_ip = sys.argv[1]
    detect_promiscuous(target_device_ip)

if __name__ == '__main__':
    main()