import socket       # Fundamental para todas as operações de rede
import argparse     # Para parsing de argumentos
import re           # Para extração de URLs no HTML parsing
from urllib.parse import urlparse  # Para análise de URLs
import ssl          # Para HTTPS no banner grabbing
import sys          # Para tratamento de erros e exit codes
import threading
from queue import Queue  # Necessário para o port scan
import time  # Usado no cálculo de duração do scan
import random

socket.setdefaulttimeout(3)  # Timeout padrão para todas as operações

ART = [
r"""
    ___           _      __                  
   /   \__ _ _ __| | __ / / _   _ _ __ __  __
  / /\ / _` | '__| |/ // / | | | | '_ \\ \/ /
 / /_// (_| | |  |   </ /__| |_| | | | |>  < 
/___,' \__,_|_|  |_|\_\____/\__, |_| |_/_/\_\
                            |___/            
""",
r"""

██▄   ██   █▄▄▄▄ █  █▀ █    ▀▄    ▄  ▄       ▄  
█  █  █ █  █  ▄▀ █▄█   █      █  █    █  ▀▄   █ 
█   █ █▄▄█ █▀▀▌  █▀▄   █       ▀█ ██   █   █ ▀  
█  █  █  █ █  █  █  █  ███▄    █  █ █  █  ▄ █   
███▀     █   █     █       ▀ ▄▀   █  █ █ █   ▀▄ 
        █   ▀     ▀               █   ██  ▀     
       ▀                                        

""",
r"""

      :::::::::      :::     :::::::::  :::    ::: :::     :::   ::: ::::    ::: :::    ::: 
     :+:    :+:   :+: :+:   :+:    :+: :+:   :+:  :+:     :+:   :+: :+:+:   :+: :+:    :+:  
    +:+    +:+  +:+   +:+  +:+    +:+ +:+  +:+   +:+      +:+ +:+  :+:+:+  +:+  +:+  +:+    
   +#+    +:+ +#++:++#++: +#++:++#:  +#++:++    +#+       +#++:   +#+ +:+ +#+   +#++:+      
  +#+    +#+ +#+     +#+ +#+    +#+ +#+  +#+   +#+        +#+    +#+  +#+#+#  +#+  +#+      
 #+#    #+# #+#     #+# #+#    #+# #+#   #+#  #+#        #+#    #+#   #+#+# #+#    #+#      
#########  ###     ### ###    ### ###    ### ########## ###    ###    #### ###    ###       

""",
r"""

oooooooooo.                      oooo        ooooo                                            
`888'   `Y8b                     `888        `888'                                            
 888      888  .oooo.   oooo d8b  888  oooo   888         oooo    ooo ooo. .oo.   oooo    ooo 
 888      888 `P  )88b  `888""8P  888 .8P'    888          `88.  .8'  `888P"Y88b   `88b..8P'  
 888      888  .oP"888   888      888888.     888           `88..8'    888   888     Y888'    
 888     d88' d8(  888   888      888 `88b.   888       o    `888'     888   888   .o8"'88b   
o888bood8P'   `Y888""8o d888b    o888o o888o o888ooooood8     .8'     o888o o888o o88'   888o 
                                                          .o..P'                              
                                                          `Y8P'                               
                                                                                              

""",
r"""

.------..------..------..------..------..------..------..------.
|D.--. ||A.--. ||R.--. ||K.--. ||L.--. ||Y.--. ||N.--. ||X.--. |
| :/\: || (\/) || :(): || :/\: || :/\: || (\/) || :(): || :/\: |
| (__) || :\/: || ()() || :\/: || (__) || :\/: || ()() || (__) |
| '--'D|| '--'A|| '--'R|| '--'K|| '--'L|| '--'Y|| '--'N|| '--'X|
`------'`------'`------'`------'`------'`------'`------'`------'

""",
r"""
 (                   (                    
 )\ )              ) )\ )                 
(()/(     ) (   ( /((()/((             )  
 /(_)) ( /( )(  )\())/(_))\ )  (    ( /(  
(_))_  )(_)|()\((_)\(_))(()/(  )\ ) )\()) 
 |   \((_)_ ((_) |(_) |  )(_))_(_/(((_)\  
 | |) / _` | '_| / /| |_| || | ' \)) \ /  
 |___/\__,_|_| |_\_\|____\_, |_||_|/_\_\  
                         |__/             
""",
r"""

▓█████▄  ▄▄▄       ██▀███   ██ ▄█▀ ██▓   ▓██   ██▓ ███▄    █ ▒██   ██▒
▒██▀ ██▌▒████▄    ▓██ ▒ ██▒ ██▄█▒ ▓██▒    ▒██  ██▒ ██ ▀█   █ ▒▒ █ █ ▒░
░██   █▌▒██  ▀█▄  ▓██ ░▄█ ▒▓███▄░ ▒██░     ▒██ ██░▓██  ▀█ ██▒░░  █   ░
░▓█▄   ▌░██▄▄▄▄██ ▒██▀▀█▄  ▓██ █▄ ▒██░     ░ ▐██▓░▓██▒  ▐▌██▒ ░ █ █ ▒ 
░▒████▓  ▓█   ▓██▒░██▓ ▒██▒▒██▒ █▄░██████▒ ░ ██▒▓░▒██░   ▓██░▒██▒ ▒██▒
 ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░▒ ▒▒ ▓▒░ ▒░▓  ░  ██▒▒▒ ░ ▒░   ▒ ▒ ▒▒ ░ ░▓ ░
 ░ ▒  ▒   ▒   ▒▒ ░  ░▒ ░ ▒░░ ░▒ ▒░░ ░ ▒  ░▓██ ░▒░ ░ ░░   ░ ▒░░░   ░▒ ░
 ░ ░  ░   ░   ▒     ░░   ░ ░ ░░ ░   ░ ░   ▒ ▒ ░░     ░   ░ ░  ░    ░  
   ░          ░  ░   ░     ░  ░       ░  ░░ ░              ░  ░    ░  
 ░                                        ░ ░                         

""",
r"""

·▄▄▄▄   ▄▄▄· ▄▄▄  ▄ •▄ ▄▄▌   ▄· ▄▌ ▐ ▄ ▐▄• ▄ 
██▪ ██ ▐█ ▀█ ▀▄ █·█▌▄▌▪██•  ▐█▪██▌•█▌▐█ █▌█▌▪
▐█· ▐█▌▄█▀▀█ ▐▀▀▄ ▐▀▀▄·██▪  ▐█▌▐█▪▐█▐▐▌ ·██· 
██. ██ ▐█ ▪▐▌▐█•█▌▐█.█▌▐█▌▐▌ ▐█▀·.██▐█▌▪▐█·█▌
▀▀▀▀▀•  ▀  ▀ .▀  ▀·▀  ▀.▀▀▀   ▀ • ▀▀ █▪•▀▀ ▀▀

"""
]

NAME = "DarkLynx Network Reconnaissance & Port Scanning Suite"
SLOG = "    Unseen. Unstoppable. Uncover every port."

def whois(url):
    site = url.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]

    whoisServer = "whois.iana.org"
    whoisPort = 43
    timeout = 10 #sec

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        s.connect((whoisServer, whoisPort))
        s.send((site + "\r\n").encode())

        data = b""
        while True:
            part = s.recv(4096)
            if not part:
                break
            data += part

        result = data.decode('utf-8', errors='ignore')

        #regional who is for the url
        for line in result.splitlines():
            if "whois:" in line.lower():
                regionalServer = line.split(":")[1].strip()
                return regionalConsult(site, regionalServer)
            
        return result
        
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        s.close()

def regionalConsult(site, server):

    port = 43
    timeout = 10

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, port))
        s.send((site + "\r\n").encode())

        data = b""
        while True:
            part = s.recv(4096)
            if not part:
                break
            data += part

        return data.decode('utf-8', errors='ignore')
    
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        s.close()
                                                                                              

def valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def valid_port(port):
    try:
        return 1 <= int(port) <= 65535
    except ValueError:
        return False

def fetch_html(host, port=80):
    try:
        # Create socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)

        if port == 443:
            context = ssl.create_default_context()
            s = context.wrap_socket(s, server_hostname=host)

        s.connect((host, port))
        
        # Send HTTP GET request
        request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(request.encode())
        
        # Receive response
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        
        return response.decode('utf-8', errors='ignore')
    
    except Exception as e:
        raise ValueError(f"Connection error: {str(e)}")
    finally:
        s.close()

def extract_domains(html):
    # Simple regex pattern to find href attributes
    href_pattern = re.compile(r'href=["\'](https?://[^"\']+)["\']', re.IGNORECASE)
    domains = set()
    
    for match in href_pattern.finditer(html):
        url = match.group(1)
        parsed = urlparse(url)
        if parsed.netloc:
            domains.add(parsed.netloc)
    
    return sorted(domains)

def resolve_dns(domains):
    domain_ips = []
    for domain in domains:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            for ip in ips:
                domain_ips.append((domain, ip))
        except socket.gaierror:
            domain_ips.append((domain, "DNS resolution failed"))
    
    return domain_ips

def html_parse(args):
    # Argument processing
    if not args.htmlparsing:
        raise ValueError("IP address is required for HTML parsing")
    
    ip = args.htmlparsing[0]
    if not valid_ip(ip):
        raise ValueError(f"Invalid IP: {ip}")
    
    port = int(args.htmlparsing[1]) if len(args.htmlparsing) > 1 else 80
    if not valid_port(port):
        raise ValueError(f"Invalid port: {port} (must be 1-65535)")

    try:
        # Fetch HTML content
        html_content = fetch_html(ip, port)
        
        # Extract domains from hrefs
        domains = extract_domains(html_content)
        if not domains:
            print("No domains found in the HTML content")
            return []
        
        # Resolve DNS
        domain_ip_table = resolve_dns(domains)
        
        # Print results
        print("\nDOMAIN TO IP MAPPING:")
        print("-" * 50)
        print(f"{'DOMAIN':<30} | {'IP':<15}")
        print("-" * 50)
        for domain, ip in domain_ip_table:
            print(f"{domain:<30} | {ip:<15}")
        print("-" * 50)
        
        return domain_ip_table
    
    except Exception as e:
        raise ValueError(f"HTML parsing failed: {str(e)}")

def banner_grabbing(args):
    # Validação dos argumentos
    if not args.bannergrabbing or len(args.bannergrabbing) != 2:
        raise ValueError("IP and port are required for banner grabbing")
    
    target_ip = args.bannergrabbing[0]
    target_port = int(args.bannergrabbing[1])

    if not valid_port(target_port):
        raise ValueError(f"Invalid port number: {target_port}")

    # Socket configuration
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)  # 5 seconds timeout

    try:
        # Connect to target
        sock.connect((target_ip, target_port))
        
        # Send generic probe (varies by protocol)
        if target_port == 80:  # HTTP
            sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
        elif target_port == 21:  # FTP
            sock.send(b"USER anonymous\r\n")
        elif target_port == 22:  # SSH
            sock.send(b"SSH-2.0-Client\r\n")
        elif target_port == 25:  # SMTP
            sock.send(b"EHLO example.com\r\n")
        elif target_port == 443: # HTTPS
            context = ssl.create_default_context()
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                ssock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                banner = ssock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()
        else:  # Generic TCP
            sock.send(b"\r\n\r\n")

        # Receive banner (first 1024 bytes)
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        
        return banner.strip()

    except socket.timeout:
        raise ValueError("Connection timeout")
    except ConnectionRefusedError:
        raise ValueError("Connection refused")
    except Exception as e:
        raise ValueError(f"Connection error: {str(e)}")
    finally:
        sock.close()

def port_scan(args):
    if not args.portscan:
        raise ValueError("IP address is required for port scanning")
    
    target_ip = args.portscan[0]
    
    # Verifica se o host está respondendo
    try:
        socket.gethostbyname(target_ip)
    except socket.gaierror:
        raise ValueError("Target host is unreachable")

    # Determina as portas a serem escaneadas
    if len(args.portscan) == 1:          # Apenas IP (default 1-1024)
        ports = range(1, 1025)
    elif len(args.portscan) == 2:        # IP + 1 porta
        ports = [int(args.portscan[1])]
    else:                                # IP + 2 portas (intervalo)
        start, end = sorted(map(int, args.portscan[1:3]))
        ports = range(start, end + 1)
    
    # Configurações de threading
    port_queue = Queue()
    results = []
    print_lock = threading.Lock()
    thread_count = min(100, len(ports))  # Limita threads desnecessárias
    
    # Preenche a fila com as portas
    for port in ports:
        port_queue.put(port)

    def grab_quick_banner(sock, port):
        """Função auxiliar para pegar banners rapidamente"""
        try:
            if port == 80:    # HTTP
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:  # FTP
                sock.send(b"USER anonymous\r\n")
            elif port == 22:  # SSH
                sock.send(b"SSH-2.0-Client\r\n")
            elif port == 25:  # SMTP
                sock.send(b"EHLO example.com\r\n")
            elif port == 443: # HTTPS (não suportado aqui - precisa de SSL)
                return "[HTTPS - use banner grabbing mode]"
            else:             # Genérico
                sock.send(b"\r\n\r\n")
            
            return sock.recv(256).decode(errors='ignore').strip()
        except:
            return ""

    def worker():
        while not port_queue.empty():
            port = port_queue.get()
            
            if args.verbose:
                with print_lock:
                    print(f"Scanning port {port}...")
            
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.0)
                    result = sock.connect_ex((target_ip, port))
                    
                    if result == 0:  # Porta aberta
                        try:
                            service = socket.getservbyport(port)
                            banner = grab_quick_banner(sock, port)
                            if len(banner) > 30:
                                banner = banner[:27] + "..."
                        except (OSError, OverflowError):
                            service = "unknown"
                            banner = ""
                        
                        status = "OPEN"
                    else:
                        status = "CLOSED"
                        service = "-"
                        banner = ""
                    
                    with print_lock:
                        results.append((port, status, service, banner))
            
            except Exception as e:
                with print_lock:
                    if args.verbose:
                        print(f"Error on port {port}: {str(e)}")
                    results.append((port, "ERROR", "-", ""))
            
            finally:
                port_queue.task_done()
                time.sleep(0.01)  # Evita sobrecarga da rede
    
    # Cria e inicia as threads
    threads = []
    for _ in range(thread_count):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    
    # Barra de progresso
    print(f"\nScanning {target_ip} ({len(ports)} ports)")
    start_time = time.time()
    
    while any(t.is_alive() for t in threads):
        elapsed = time.time() - start_time
        print(f"\rProgress: {len(ports) - port_queue.qsize()}/{len(ports)} | "
              f"Elapsed: {elapsed:.1f}s | "
              f"Open: {len([r for r in results if r[1] == 'OPEN'])}", end='')
        time.sleep(0.2)
    
    # Ordena e retorna resultados
    results.sort(key=lambda x: x[0])
    return target_ip, results

def main():
    print("\n \n \n" + random.choice(ART) + "\n" + NAME + "\n" + SLOG + "\n \n \n")
    parser = argparse.ArgumentParser(description=NAME)
    subparsers = parser.add_subparsers(dest="command", help="Commands", required=True)

    # Argumento global verbose
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # --- Port Scanning Command ---
    ps_parser = subparsers.add_parser("ps", help="Port scanning (usage: ps IP [start-port end-port]")
    ps_parser.add_argument(
        "target",
        type=str,
        nargs='+',
        metavar=("ip", "port..."),
        help="Target IP and optional ports (default: scan 1-1024)"
    )

    # --- Banner Grabbing Command ---
    bg_parser = subparsers.add_parser("bg", help="Banner grabbing (usage: bg IP PORT)")
    bg_parser.add_argument(
        "target",
        type=str,
        nargs=2,
        metavar=("ip", "port"),
        help="Target IP and port (e.g., 192.168.1.1 80)"
    )

    # --- DNS Resolver Command ---
    dr_parser = subparsers.add_parser("dr", help="DNS resolver (usage: dr URL)")
    dr_parser.add_argument(
        "url",
        type=str,
        help="URL to resolve (e.g., example.com)"
    )

    # --- HTML Parsing Command ---
    hp_parser = subparsers.add_parser("hp", help="HTML parsing (usage: hp IP [PORT])")
    hp_parser.add_argument(
        "target",
        type=str,
        nargs='+',
        metavar=("ip", "port..."),
        help="Target IP and optional port (default: 80)"
    )

    # --- WhoIS Resolver Command --- 
    wi_parser = subparsers.add_parser("wi", help="WhoIS (usage: wi URL)")
    wi_parser.add_argument(
        "url",
        type=str,
        help="URL to search in WhoIS Database"
    )

    args = parser.parse_args()

    try:
        if args.command == "hp":  # HTML Parsing
            if not args.target:
                raise ValueError("IP address is required for HTML parsing")
            
            # Adaptação para os novos argumentos
            ip = args.target[0]
            port = int(args.target[1]) if len(args.target) > 1 else 80
            
            # Cria um namespace simulado com a estrutura esperada pelas funções existentes
            html_args = argparse.Namespace(
                htmlparsing=[ip, str(port)] if len(args.target) > 1 else [ip]
            )
            
            results = html_parse(html_args)
            if results:
                print("\nHTML parsing completed successfully!")

        elif args.command == "dr":  # DNS Resolver
            if not args.url:
                raise ValueError("URL is required for DNS resolution")
            
            print(f"\nResolving DNS for: {args.url}")
            results = resolve_dns([args.url])
            
            print("\nDNS RESOLUTION RESULTS:")
            print("-" * 50)
            print(f"{'DOMAIN':<30} | {'IP':<15}")
            print("-" * 50)
            for domain, ip in results:
                print(f"{domain:<30} | {ip:<15}")
            print("-" * 50)

        elif args.command == "ps":  # Port Scan
            if not args.target:
                raise ValueError("IP address is required for port scanning")
            
            # Adapta os argumentos para a estrutura existente
            portscan_args = argparse.Namespace(
                portscan=args.target,
                verbose=args.verbose
            )
            
            start_time = time.time()
            target_ip, results = port_scan(portscan_args)
            
            print(f"\n\nPORT SCAN RESULTS for {target_ip}:")
            print("-" * 85)
            print(f"{'PORT':<8} | {'STATUS':<8} | {'SERVICE':<20} | {'BANNER':<40}")
            print("-" * 85)
            
            for port, status, service, banner in results:
                if status == "OPEN":
                    print(f"{port:<8} | {status:<8} | {service:<20} | {banner:<40}")
            
            open_ports = [r[0] for r in results if r[1] == "OPEN"]
            duration = time.time() - start_time
            
            print("\nSummary:")
            print(f"Total ports scanned: {len(results)}")
            print(f"Open ports found: {len(open_ports)}")
            print(f"Scan duration: {duration:.2f} seconds")
            print("-" * 85)

        elif args.command == "bg":  # Banner Grabbing
            if len(args.target) != 2:
                raise ValueError("IP and port are required for banner grabbing")
            
            # Adapta os argumentos
            bg_args = argparse.Namespace(
                bannergrabbing=args.target
            )
            
            target = f"{args.target[0]}:{args.target[1]}"
            print(f"\nGrabbing banner from {target}...")
            
            banner = banner_grabbing(bg_args)
            
            print("\nBANNER GRABBING RESULTS:")
            print("-" * 50)
            print(banner if banner else "No banner received")
            print("-" * 50)

        elif args.command == "wi": #Who is
            if not args.url:
                raise ValueError("URL is required for WhoIS search")
            
            print(f"\nSearching {args.url} in WhoIS Database...")
            results = whois(args.url)
            print(f"WhoIS search results:\n")
            print(results)

    except ValueError as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        sys.exit(1)

def check_dependencies():
    try:
        socket.gethostbyname('example.com')
        ssl.create_default_context()
    except Exception as e:
        print(f"Dependency error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        check_dependencies()
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Critical error: {str(e)}", file=sys.stderr)
        sys.exit(1)