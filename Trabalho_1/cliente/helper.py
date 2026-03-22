import struct
import socket

# Formatos para auxiliar o struct.unpack e struct.pack
# IP_FORMAT: 20 bytes, seguindo a ordem do cabeçalho IPv4
IP_FORMAT = "!BBHHHBBH4s4s"   
# UDP_FORMAT: 8 bytes (Source Port, Dest Port, Length, Checksum)
UDP_FORMAT = "!HHHH"          

def unpack_iph(pkg: bytes) -> tuple[int, int, int, int, int, int, int, int, bytes, bytes]:
    """
    Realiza o unpack do header IP (os primeiros 20 bytes do pacote).

    Ordem retornada:
    (version_ihl, tos, total_length, identification, flags_offset, ttl, protocol, checksum, src_addr, dest_addr)
    
    Instruções:
    1. Utilize a constante IP_FORMAT com struct.unpack.
    2. O header IP começa no índice 0 e vai até o 20.
    3. Retorne a tupla com os campos desempacotados.
    """
    return struct.unpack(IP_FORMAT, pkg[0:20])

def unpack_udp(pkg: bytes) -> tuple[int, int, int, int]:
    """
    Realiza o unpack do header UDP.

    Ordem retornada:
    (src_port, dest_port, length, checksum)

    Instruções:
    1. O header UDP começa logo após o header IP (índice 20) e tem 8 bytes de tamanho.
    2. Utilize a constante UDP_FORMAT.
    3. Retorne a tupla com (src_port, dest_port, length, checksum).
    """
    return struct.unpack(UDP_FORMAT, pkg[20:28])

def unpack_data(pkg: bytes) -> bytes:
    """
    Extrai o payload (dados) do pacote.

    Instruções:
    1. O payload começa após o header IP (20 bytes) e o header UDP (8 bytes).
    2. Retorne apenas os bytes correspondentes aos dados.
    """
    return pkg[28:]

def calculate_checksum(msg: bytes) -> int:
    """
    Calcula o Checksum de 16 bits para o cabeçalho.

    Instruções:
    1. Verifique se o tamanho da mensagem é ímpar; se for, adicione um byte nulo (b'\x00').
    2. Some os valores de 16 bits (2 bytes por vez).
    3. Realize o 'carry' (soma os bits que excederem 16 bits de volta ao total).
    4. Retorne o complemento de um da soma final, mascarado para 16 bits (0xffff).
    """
    s = 0
    # 1. Verifica se o tamanho é ímpar; se for, adiciona um byte nulo
    if len(msg) % 2 != 0:
        msg += b'\x00'
    # 2. Soma os valores de 16 bits (2 bytes por vez)
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i + 1])
        s = s + w
    # 3. Realiza o carry (bits que excederam 16 bits são somados de volta)
    s = (s >> 16) + (s & 0xffff)
    # 4. Retorna o complemento de um, mascarado para 16 bits
    s = ~s & 0xffff
    return s

def build_udp_packet(src_ip: str, dest_ip: str, src_port: int, dest_port: int, data: str) -> bytes:
    """
    Constrói um pacote IP/UDP completo do zero.

    Passos necessários:
    1. Encode do payload para bytes.
    2. Construção do Pseudo-Header UDP (IP Origem, IP Destino, Zero, Protocolo 17, UDP Length).
    3. Cálculo do Checksum UDP (Pseudo-Header + Header UDP temporário + Payload).
    4. Construção do Header UDP final com o Checksum calculado.
    5. Construção do Header IP:
        - Definir campos como Versão/IHL (0x45), TTL (64), Protocolo (17).
        - Calcular o Checksum do Header IP.
    6. Concatenar Header IP + Header UDP + Payload e retornar os bytes.
    """
    # 1. Encode do payload para bytes
    payload = data.encode()

    # 2. Construção do Pseudo-Header UDP
    src_addr = socket.inet_aton(src_ip)
    dest_addr = socket.inet_aton(dest_ip)
    protocol = 17  # UDP
    udp_length = 8 + len(payload)  # Header UDP (8) + Payload

    pseudo_header = struct.pack('!4s4sBBH', src_addr, dest_addr, 0, protocol, udp_length)

    # 3. Cálculo do Checksum UDP (Pseudo-Header + Header UDP temporário + Payload)
    udp_header_tmp = struct.pack(UDP_FORMAT, src_port, dest_port, udp_length, 0)
    udp_checksum = calculate_checksum(pseudo_header + udp_header_tmp + payload)

    # 4. Construção do Header UDP final com o Checksum calculado
    udp_header = struct.pack(UDP_FORMAT, src_port, dest_port, udp_length, udp_checksum)

    # 5. Construção do Header IP
    version_ihl = 0x45       # IPv4, IHL = 5 (20 bytes)
    tos = 0                  # Type of Service
    total_length = 20 + udp_length  # Header IP (20) + UDP Length
    identification = 54321   # ID do pacote
    flags_offset = 0         # Sem fragmentação
    ttl = 64
    ip_checksum = 0          # Temporário para cálculo

    ip_header_tmp = struct.pack(IP_FORMAT,
        version_ihl, tos, total_length, identification, flags_offset,
        ttl, protocol, ip_checksum, src_addr, dest_addr
    )

    # Calcula o Checksum do Header IP
    ip_checksum = calculate_checksum(ip_header_tmp)

    ip_header = struct.pack(IP_FORMAT,
        version_ihl, tos, total_length, identification, flags_offset,
        ttl, protocol, ip_checksum, src_addr, dest_addr
    )

    # 6. Concatenar Header IP + Header UDP + Payload
    return ip_header + udp_header + payload