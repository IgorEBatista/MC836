import socket
import struct

def checksum(msg):
    s = 0
    # Adiciona preenchimento se o comprimento for ímpar
    if len(msg) % 2 != 0:
        msg += b'\x00'
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i+1])
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def send_raw_packet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("Erro: Requer privilégios de Root/Admin.")
        return

    src_ip = "127.0.0.1"
    dest_ip = "127.0.0.1"

    while True:
        msg = input("Cliente: ")
        if msg.lower() == 'sair':
            print("Encerrando cliente.")
            break
        msg = msg.encode('utf-8')

        # --- CABEÇALHO IP (20 Bytes) ---
        ip_ver_ihl = (4 << 4) + 5  # Versão 4, IHL 5
        ip_tos = 0
        ip_tot_len = 20 + 8 + len(msg)
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0 # Kernel preenche se deixarmos 0 em alguns sistemas
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dest_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_tos, ip_tot_len, 
                                ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, 
                                ip_saddr, ip_daddr)

        # --- CABEÇALHO UDP (8 Bytes) ---
        sport = 12345
        dport = 9999
        udp_len = 8 + len(msg)
        udp_check = 0 # Opcional para UDP em IPv4

        udp_header = struct.pack('!HHHH', sport, dport, udp_len, udp_check)

        # Envio do pacote completo: IP + UDP + MSG
        packet = ip_header + udp_header + msg
        s.sendto(packet, (dest_ip, 0))
        print(f"Pacote bruto enviado com sucesso para {dest_ip}!")

if __name__ == "__main__":
    send_raw_packet()