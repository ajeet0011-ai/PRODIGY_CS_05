from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def process_packet(packet):
    print("\n" + "=" * 60)
    print(f"Time: {datetime.now()}")

    if packet.haslayer(IP):
        ip = packet[IP]

        print(f"Source IP      : {ip.src}")
        print(f"Destination IP : {ip.dst}")
        print(f"Protocol ID    : {ip.proto}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol       : TCP")
            print(f"Source Port    : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol       : UDP")
            print(f"Source Port    : {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                print("\nPayload Preview:")
                print(payload[:200])
            except Exception:
                pass

    print("=" * 60)

def main():
    print("Packet Sniffer Started... Press CTRL+C to stop.")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
