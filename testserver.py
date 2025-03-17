import socket

def start_server(host='127.0.0.1', port=67):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:

        server_socket.bind((host, port))

        server_socket.listen()
        print(f"Servidor escutando em {host}:{port}")

        while True:

            client_socket, client_address = server_socket.accept()
            with client_socket:
                print(f"Conexão estabelecida com {client_address}")
                while True:

                    data = client_socket.recv(1024)
                    if not data:

                        print(f"Conexão com {client_address} fechada")
                        break

                    client_socket.sendall(data)

if __name__ == "__main__":
    start_server()