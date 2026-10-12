
from datetime import datetime
import csv
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Project: Basic Network Sniffer
# Domain: Cyber Security
# Purpose: Capture and analyze network packets

CSV_FILE = "packet_analysis.csv"
PACKET_LIMIT = 20
packet_count = 0
packet_records = []


def analyze_packet(packet):
    global packet_count

    # Process only packets containing an IP layer
    if IP not in packet:
        return

    packet_count += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    protocol = "Other"
    source_port = ""
    destination_port = ""

    # Identify the protocol and ports
    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    packet_size = len(packet)
    capture_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Display packet details
    print("\n" + "=" * 55)
    print(f"Packet Number:       {packet_count}")
    print(f"Capture Time:        {capture_time}")
    print(f"Source IP:           {source_ip}")
    print(f"Destination IP:      {destination_ip}")
    print(f"Protocol:            {protocol}")
    print(f"Source Port:         {source_port}")
    print(f"Destination Port:    {destination_port}")
    print(f"Packet Size:         {packet_size} bytes")
    print("=" * 55)

    # Store packet information for the CSV report
    packet_records.append({
        "Packet Number": packet_count,
        "Capture Time": capture_time,
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "Protocol": protocol,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Packet Size (bytes)": packet_size
    })


def save_results():
    if not packet_records:
        print("\nNo IP packets were captured.")
        return

    fieldnames = list(packet_records[0].keys())

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(packet_records)

    print(f"\nTotal IP packets analyzed: {packet_count}")
    print(f"Analysis results saved to: {CSV_FILE}")


def main():
    print("=" * 55)
    print("          BASIC NETWORK SNIFFER")
    print("       ARCH TECHNOLOGIES - CYBER SECURITY")
    print("=" * 55)
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Packet Limit: {PACKET_LIMIT}")
    print("Capturing IP packets on the available network interface.")
    print("Use only networks you own or have permission to monitor.")
    print("Press Ctrl+C to stop the capture early.")
    print("=" * 55)

    try:
        sniff(
            filter="ip",
            prn=analyze_packet,
            count=PACKET_LIMIT,
            store=False
        )

    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    except PermissionError:
        print("\nPermission denied.")
        print("Try opening VS Code as Administrator.")

    except Exception as error:
        print(f"\nCapture error: {error}")
        print("Check that Npcap is installed and the capture interface is available.")

    finally:
        save_results()
        print("\nNetwork sniffer finished.")


if __name__ == "__main__":
    main()
