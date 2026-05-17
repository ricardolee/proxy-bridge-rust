import socket
import threading
import sys
import time

# A simple target HTTP server
def run_target_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('10.99.0.2', 80))
    s.listen(5)
    print("Target server listening on 10.99.0.2:80", flush=True)
    while True:
        try:
            conn, addr = s.accept()
            req = conn.recv(1024)
            response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nHello, Target"
            conn.sendall(response)
            conn.close()
        except Exception as e:
            break

# A simple mock SOCKS5 proxy server
def handle_socks5_client(conn, addr):
    try:
        # Handshake
        greet = conn.recv(262)
        if not greet or greet[0] != 5:
            conn.close()
            return
        conn.sendall(b"\x05\x00")
        
        # Request
        req = conn.recv(1024)
        if not req or req[0] != 5 or req[1] != 1: # CONNECT
            conn.close()
            return
            
        # Target details
        atyp = req[3]
        if atyp == 1: # IPv4
            dest_ip = socket.inet_ntoa(req[4:8])
            dest_port = int.from_bytes(req[8:10], 'big')
        else:
            conn.close()
            return
            
        print(f"SOCKS5: proxying request to {dest_ip}:{dest_port}", flush=True)
        
        # Connect to target
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.connect((dest_ip, dest_port))
        
        # Respond success
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        
        # Bidirectional relay
        def relay(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass
            finally:
                try: src.close()
                except: pass
                try: dst.close()
                except: pass
                
        threading.Thread(target=relay, args=(conn, target), daemon=True).start()
        threading.Thread(target=relay, args=(target, conn), daemon=True).start()
    except Exception as e:
        try: conn.close()
        except: pass

def run_socks5_proxy():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('10.99.0.1', 1080))
    s.listen(5)
    print("SOCKS5 proxy listening on 10.99.0.1:1080", flush=True)
    while True:
        try:
            conn, addr = s.accept()
            threading.Thread(target=handle_socks5_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            break

if __name__ == '__main__':
    t1 = threading.Thread(target=run_target_server, daemon=True)
    t2 = threading.Thread(target=run_socks5_proxy, daemon=True)
    t1.start()
    t2.start()
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
