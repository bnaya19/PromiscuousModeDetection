from scapy.all import *
from random import randint

MAX_TIMEOUT = 5
VM_INTERFACE = "VMware Virtual Ethernet Adapter for VMnet1"
FAKE_MAC = "aa:bb:cc:dd:ee:ff"
PTR_QUERY_TYPE = 12 


def get_fake_ip():
    """
        This function generate pseudo random ip. 
        The reason is simple- 
        Sniffers cache their rDNS results, therefore in every execution we should use different ip.
        
        Another thing to notice: 
        The generate address is only in the form of x.x.x.x where x has the same digits. 
        The reason for that is that in the funcion "get_sniffing_hosts" we are checking if 
        the fake IP was resolved. However, the IP that lies in the rDNS request is reversed- 
        so to make the reverse easier (or actually, to just avoid the convertion)- the generated
        address have that format.
    """
    rand_number = randint(1, 9)
    num_of_digits = randint(1, 3)
    fake_ip_addr = str(rand_number)*num_of_digits + "."
    fake_ip_addr *= 4
    return fake_ip_addr[0:-1]


def get_sniffing_hosts(dns_packets, fake_ip):
    sniffing_hosts = []

    for packet in dns_packets:
        for query in packet[DNS].qd:
            if query.qtype == PTR_QUERY_TYPE and fake_ip in query.qname: 
                sniffing_hosts.append((packet[Ether].src, packet[IP].src))

    return list(set(sniffing_hosts))


def detect_promiscuous():
    # Get pseudo random generated address
    fake_ip_address = get_fake_ip()

    # Build Fake request to a none-existing web server
    request_packet = Ether(dst=FAKE_MAC)
    request_packet /= IP(dst=fake_ip_address)
    request_packet /= TCP(sport=randint(1025, 65535), dport=80, flags="S")
    sendp(request_packet, iface=VM_INTERFACE, verbose=False)

    # Filter the results to get only dns requests 
    dns_packets = sniff(filter="udp and dst port 53", timeout=MAX_TIMEOUT, iface=VM_INTERFACE)
    sniffing_hosts = get_sniffing_hosts(dns_packets, fake_ip_address)

    if len(sniffing_hosts) == 0:
        print "There is no sniffer in the network."
    else:
        print "Found {SNIFFERS_NUMBER} sniffer(s) in the network:".format(SNIFFERS_NUMBER=len(sniffing_hosts))
        for host in sniffing_hosts:
            print "\tMAC: {MAC_ADDRESS}. IP: {IP_ADDRESS}".format(MAC_ADDRESS=host[0], IP_ADDRESS=host[1])
        

def main():
    detect_promiscuous()


if __name__ == '__main__':
    main()