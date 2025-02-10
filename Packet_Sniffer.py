from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            sport = "N/A"
            dport = "N/A"
        
        print(f"{protocol} Packet: {ip_src}:{sport} -> {ip_dst}:{dport}")

print("Starting network sniffer...")
sniff(prn=packet_callback, store=False)
