import sys
from scapy.all import *

MAX_TIMEOUT = 2
VM_INTERFACE = "VMware Virtual Ethernet Adapter for VMnet1" # Change to your interface name


def detect_promiscuous(device_ip):
    # This destination address will not perform well due to the software filtering
    # arp_packet = Ether(dst="aa:bb:cc:dd:ee:ff")

    # This destination address should pass the software filter
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:fe")
    arp_packet /= ARP(pdst= device_ip)

    # Sometimes scapy sets the src address of the ethernet header to be different from the
    # sender MAC of the ARP header. To prevent possible inconsistency- make them equals
    arp_packet.hwsrc=arp_packet.src

    # Send the packet and check the results
    response = srp1(arp_packet, timeout=MAX_TIMEOUT, iface=VM_INTERFACE, verbose=False)
    if response is None:
        print("Device {DEVICE_IP} is not promiscuous mode.".format(DEVICE_IP = device_ip))
    else:
        print("Device {DEVICE_IP} is in promiscuous mode.".format(DEVICE_IP = device_ip))


def main():
    target_device_ip = sys.argv[1]
    detect_promiscuous(target_device_ip)


if __name__ == '__main__':
    main()
