import socket
import struct

def start_server():
    # Escuta especificamente o protocolo UDP na camada raw
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.bind(("127.0.0.1", 0))
    print("Servidor Raw aguardando pacotes UDP...")

    while True:
        packet, addr = s.recvfrom(9999)

        # O cabeçalho IP tem 20 bytes, o UDP tem 8 bytes
        # O payload começa após o byte 28
        ip_header = packet[0:20]
        udp_header = packet[20:28]
        payload = packet[28:]

        # Desempacotando IP para ver quem enviou (opcional)
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        s_addr = socket.inet_ntoa(iph[8])

        print(f"\n--- Novo Pacote de {s_addr} ---")
        print(f"IP Header: {ip_header.hex()}")
        print(f"UDP Header: {udp_header.hex()}")
        print(f"Payload Recebido: {payload.decode(errors='ignore')}")

if __name__ == "__main__":
    start_server()