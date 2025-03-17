import socket
import argparse
import time # estm.time

ART = r"""
    ___           _      __                  
   /   \__ _ _ __| | __ / / _   _ _ __ __  __
  / /\ / _` | '__| |/ // / | | | | '_ \\ \/ /
 / /_// (_| | |  |   </ /__| |_| | | | |>  < 
/___,' \__,_|_|  |_|\_\____/\__, |_| |_/_/\_\
                            |___/            
"""
NAME = "DarkLynx Network Reconnaissance & Port Scanning Suite"
SLOG = "    Unseen. Unstoppable. Uncover every port."

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        r = sock.connect_ex((host,port))
        if r == 0:
            print(f"Port {port} in {host}: OPEN")
        else:
            print(f"Port {port} in {host}: CLOSED")
        sock.close
    except socket.error:
        print(f"Unable to connect port.")

def main():
    print("\n \n \n" + ART + "\n" + NAME + "\n" + SLOG + "\n \n \n")
    parser = argparse.ArgumentParser(description=NAME)
    parser.add_argument("host", help="Host to scan")
    parser.add_argument("-p", "--ports", type=int, nargs=2, metavar=("start-port", "end-port"), help="Port interval")
    args = parser.parse_args()

    host = args.host
    start_port, end_port = args.ports

    print(f"Scanning {host} ports {start_port} to {end_port}...\n")
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        scan_port(host, port)

    print(f"Scanner Completed\nElapsed Time: {time.time()-start_time:.2f} seconds")



if __name__ == "__main__":
    main()