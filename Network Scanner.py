from scapy.all import ARP, Ether, srp

def scan_network(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("Devices on the network:")
    print("IP\t\t\tMAC Address")
    print("-----------------------------")
    for client in clients:
        print(f"{client['ip']}\t\t{client['mac']}")

# Example usage:
network_ip = "192.168.1.0/24"
scan_network(network_ip)
