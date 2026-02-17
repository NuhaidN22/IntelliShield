"""
Simple Attack Simulator - No special libraries needed
Tests IntelliShield detection without requiring scapy
"""

import socket
import time
import random
import threading

def syn_flood_simple(target_ip="127.0.0.1", duration=10):
    """
    Simple flood attack - sends lots of connections quickly
    """
    print(f"🔥 Starting SYN Flood Attack")
    print(f"   Target: {target_ip}")
    print(f"   Duration: {duration} seconds")
    print(f"   This will generate LOTS of packets!\n")
    
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        try:
            # Create multiple connections rapidly
            for _ in range(10):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                try:
                    sock.connect((target_ip, random.randint(1, 65535)))
                except:
                    pass
                sock.close()
                count += 1
        except:
            pass
    
    print(f"\n✅ Attack completed: {count} connection attempts in {duration} seconds")
    print(f"   Rate: {count/duration:.0f} connections/second")


def port_scan_simple(target_ip="127.0.0.1", start_port=1, end_port=100):
    """
    Simple port scan - tries to connect to many ports
    """
    print(f"🔥 Starting Port Scan")
    print(f"   Target: {target_ip}")
    print(f"   Scanning ports {start_port}-{end_port}\n")
    
    open_ports = []
    
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
            print(f"   Port {port}: OPEN")
        
        sock.close()
        
        if port % 20 == 0:
            print(f"   Progress: {port}/{end_port}")
    
    print(f"\n✅ Scan completed: Found {len(open_ports)} open ports")


def http_flood_simple(target_ip="127.0.0.1", target_port=80, duration=10):
    """
    HTTP flood - sends many HTTP requests
    """
    print(f"🔥 Starting HTTP Flood")
    print(f"   Target: http://{target_ip}:{target_port}")
    print(f"   Duration: {duration} seconds\n")
    
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, target_port))
            
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            sock.send(request.encode())
            
            sock.close()
            count += 1
            
            if count % 50 == 0:
                print(f"   Sent {count} requests...")
        except:
            pass
        
        time.sleep(0.01)
    
    print(f"\n✅ Attack completed: {count} HTTP requests in {duration} seconds")


def udp_flood_simple(target_ip="127.0.0.1", target_port=53, duration=10):
    """
    UDP flood - sends lots of UDP packets
    """
    print(f"🔥 Starting UDP Flood")
    print(f"   Target: {target_ip}:{target_port}")
    print(f"   Duration: {duration} seconds\n")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        try:
            # Send random data
            data = bytes([random.randint(0, 255) for _ in range(1024)])
            sock.sendto(data, (target_ip, target_port))
            count += 1
            
            if count % 100 == 0:
                print(f"   Sent {count} packets...")
        except:
            pass
    
    sock.close()
    print(f"\n✅ Attack completed: {count} UDP packets in {duration} seconds")


def multi_threaded_attack(target_ip="127.0.0.1", threads=5, duration=10):
    """
    Multi-threaded attack - simulates DDoS from multiple sources
    """
    print(f"🔥 Starting Multi-Threaded Attack")
    print(f"   Target: {target_ip}")
    print(f"   Threads: {threads}")
    print(f"   Duration: {duration} seconds per thread\n")
    
    def attack_worker():
        syn_flood_simple(target_ip, duration)
    
    # Start multiple threads
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=attack_worker)
        t.start()
        thread_list.append(t)
        print(f"   Started thread {i+1}/{threads}")
    
    # Wait for all threads
    for t in thread_list:
        t.join()
    
    print(f"\n✅ Multi-threaded attack completed")


def main():
    print("=" * 70)
    print("🛡️  IntelliShield Simple Attack Simulator")
    print("=" * 70)
    print("\n⚠️  WARNING: Only test on your own system (127.0.0.1)!")
    print("⚠️  Make sure IntelliShield is running before testing!\n")
    
    print("Attack Types:")
    print("  1. SYN Flood (Fast connections)")
    print("  2. Port Scan (Scan 100 ports)")
    print("  3. HTTP Flood (Many HTTP requests)")
    print("  4. UDP Flood (UDP packet spam)")
    print("  5. Multi-threaded Attack (DDoS simulation)")
    print("  6. Slow Attack (Low and slow)")
    print("  7. All attacks (one by one)")
    
    choice = input("\nSelect attack (1-7): ").strip()
    
    # Always use localhost for safety
    target = "127.0.0.1"
    
    print(f"\n🎯 Target: {target}")
    print("🚀 Starting in 3 seconds...\n")
    time.sleep(3)
    
    try:
        if choice == "1":
            syn_flood_simple(target, duration=10)
        
        elif choice == "2":
            port_scan_simple(target, start_port=1, end_port=100)
        
        elif choice == "3":
            http_flood_simple(target, target_port=80, duration=10)
        
        elif choice == "4":
            udp_flood_simple(target, target_port=53, duration=10)
        
        elif choice == "5":
            multi_threaded_attack(target, threads=5, duration=5)
        
        elif choice == "6":
            print("🔥 Starting Slow Attack (low and slow)")
            for i in range(30):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((target, random.randint(1, 65535)))
                    sock.close()
                    print(f"   Packet {i+1}/30")
                    time.sleep(2)
                except:
                    pass
            print("✅ Slow attack completed")
        
        elif choice == "7":
            print("\n📋 Running all attacks...\n")
            syn_flood_simple(target, duration=5)
            time.sleep(2)
            port_scan_simple(target, start_port=1, end_port=50)
            time.sleep(2)
            udp_flood_simple(target, duration=5)
            print("\n✅ All attacks completed!")
        
        else:
            print("❌ Invalid choice")
            return
        
        print("\n" + "=" * 70)
        print("✅ Attack simulation finished!")
        print("=" * 70)
        print("\n📊 Now check your IntelliShield output:")
        print("   - Look for 🚨 ATTACK DETECTED messages")
        print("   - Check confidence scores (should be > 50%)")
        print("   - Verify model predictions are high")
        print("=" * 70)
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Simulation interrupted by user")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()