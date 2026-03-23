import os
import re
import time
import socket
from rich import print
from helper import unpack_iph, unpack_udp, unpack_data, build_udp_packet, build_udp_packet_bytes, ERROR_NOT_FOUND, ERROR_BAD_COMMAND
from rtp_protocol import rtp_pack, make_ssrc, RTP_HEADER_SIZE

VIDEOS_DIR = "videos"  # Diretório onde os vídeos estão armazenados

def send_catalog(sender, src_ip: str, src_port: int, client_ip: str, client_port: int):
    """
    Envia uma mensagem de catálogo para o cliente.

    Instruções:
    1. Defina a mensagem de resposta (ex: "Catálogo: video1, video2").
    2. Utilize a função build_udp_packet para montar o pacote completo.
    3. Envie o pacote usando o socket 'sender'.
    """

    # Recupera os nomes dos vídeos disponíveis (exemplo: arquivos .mp4 na pasta 'videos')
    video_files = [f for f in os.listdir('videos') if f.endswith('.ts')]
    if not video_files:
        msg = "\n\tCatálogo: Nenhum vídeo disponível."
    else:
        msg = "\n\tCatálogo: " + ", ".join(video_files)

    # TAREFA: Chamar build_udp_packet e sender.sendto()
    packet = build_udp_packet(
        src_ip=src_ip, 
        dest_ip=client_ip,
        src_port=src_port,
        dest_port=client_port,
        data=msg
    )
    sender.sendto(packet, (client_ip, 0))
    print(f"[-] Catálogo enviado para {client_ip}:{client_port}")

def start_streaming(sender, src_ip: str, src_port: int, client_ip: str, client_port: int, video_name: str):
    """
    Inicia o streaming do vídeo solicitado para o cliente usando RTP.

    Cada pacote UDP carrega: [IP Header][UDP Header][RTP Header (12B)][Chunk de vídeo]
    O RTP adiciona sequência, timestamp e SSRC para o cliente poder:
    - Detectar pacotes perdidos (seq)
    - Reproduzir no tempo certo (timestamp)
    - Identificar a fonte (ssrc)
    """
    video_path = os.path.join(VIDEOS_DIR, video_name)
    if not os.path.isfile(video_path):
        print(f"[!] Vídeo '{video_name}' não encontrado.")
        return

    CHUNK_SIZE = 1316       # Bytes de vídeo por pacote, 7 frames de 188 bytes (tamanho típico de um pacote TS)
    CLOCK_RATE = 90000      # Clock RTP padrão para vídeo (90 kHz)
    SEND_INTERVAL = 0.002    # 2ms entre pacotes (~500 pacotes/s)

    ssrc = make_ssrc()
    seq = 0
    timestamp = 0
    ts_increment = int(CLOCK_RATE * SEND_INTERVAL)  # Incremento de timestamp por pacote

    print(f"[+] Streaming '{video_name}' para {client_ip}:{client_port} (SSRC=0x{ssrc:08X})")

    with open(video_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break  # Fim do arquivo

            # Monta pacote RTP: header (12 bytes) + chunk de vídeo
            rtp_data = rtp_pack(
                seq=seq,
                timestamp=timestamp,
                ssrc=ssrc,
                payload=chunk,
                marker=(seq == 0),  # Marca o primeiro pacote
            )

            # Empacota RTP dentro de UDP/IP e envia
            packet = build_udp_packet_bytes(
                src_ip=src_ip,
                dest_ip=client_ip,
                src_port=src_port,
                dest_port=client_port,
                data=rtp_data,
            )
            sender.sendto(packet, (client_ip, 0))

            seq = (seq + 1) & 0xFFFFFFFF       # Wrap-around em 32 bits
            timestamp = (timestamp + ts_increment) & 0xFFFFFFFF

            time.sleep(SEND_INTERVAL)

    print(f"[+] Streaming de '{video_name}' finalizado. {seq} pacotes enviados.")

def send_error(sender, src_ip: str, src_port: int, client_ip: str, client_port: int, message: str):
    """
    Envia uma mensagem de erro para o cliente.

    Instruções:
    1. Utilize a função build_udp_packet para montar o pacote completo.
    2. Envie o pacote usando o socket 'sender'.
    """
    packet = build_udp_packet(
        src_ip=src_ip, 
        dest_ip=client_ip,
        src_port=src_port,
        dest_port=client_port,
        data=f"Erro: {message}"
    )
    sender.sendto(packet, (client_ip, 0))
    print(f"[-] Mensagem de erro enviada para {client_ip}:{client_port}: {message}")

def start_server(interface, src_ip, buffer_size, src_port, dst_port):
    """
    Loop principal do servidor que escuta pacotes brutos e processa comandos.
    """
    # Socket para ENVIAR (Raw IP)
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Socket para ESCUTAR (Sniffer na interface)
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sniffer.bind((interface, 0))

    print(f"[+] Servidor rodando em {src_ip}:{src_port} na interface {interface}")

    try:
        while True:
            # Recebe o pacote bruto da rede
            raw_packet, _ = sniffer.recvfrom(buffer_size)
            raw_packet = raw_packet[14:]  # Pula o header Ethernet (14 bytes)
            # --- TAREFA: PROCESSAMENTO DO CABEÇALHO IP ---
            # 1. Chamar unpack_iph(raw_packet)
            iph = unpack_iph(raw_packet)
            # 2. Validar se o protocolo é UDP (valor 17)
            if iph[6] != 17:
                continue

            # Dica: O endereço IP do cliente estará no header IP. 
            # Use socket.inet_ntoa() para converter os bytes do IP para string.

            client_ip = socket.inet_ntoa(iph[8])

            # --- TAREFA: PROCESSAMENTO DO CABEÇALHO UDP ---
            # 1. Chamar unpack_udp(raw_packet)
            udph = unpack_udp(raw_packet)
            # 2. Validar se a porta de destino do pacote é a porta do servidor (src_port)
            if udph[1] != src_port:
                continue
            client_port = udph[0]
            print(f"\n[+] Pacote recebido de {client_ip}:{client_port}")
            # --- TAREFA: PAYLOAD E LÓGICA ---
            # 1. Chamar unpack_data(raw_packet)
            data = unpack_data(raw_packet).decode(errors='ignore')
            print(f"Payload recebido: {data}")
            # 2. Se o dado for 'catalog', chamar a função send_catalog()
            if data.strip() == 'catalog':
                send_catalog(sender, src_ip, src_port, client_ip, client_port)
            # --- TAREFA: Streaming ---
            # 3. Se o dado for 'stream <nome_video>', chamar a função start_streaming()
            elif match := re.match(r'^stream\s+(\S+)$', data.strip()):
                nome_video = match.group(1)
                video_path = os.path.join(VIDEOS_DIR, nome_video)
                if not os.path.isfile(video_path):
                    print(f"[!] Vídeo '{nome_video}' não encontrado em {VIDEOS_DIR}/")
                    send_error(sender, src_ip, src_port, client_ip, client_port, ERROR_NOT_FOUND)
                    continue
                start_streaming(sender, src_ip, src_port, client_ip, client_port, nome_video)
            else:
                print(f"[!] Comando desconhecido: {data} (esperado 'catalog' ou 'stream <nome_video>')")
                send_error(sender, src_ip, src_port, client_ip, client_port, ERROR_BAD_COMMAND)
                continue

    except KeyboardInterrupt:
        print("\n[!] Desligando servidor...")
    finally:
        sender.close()
        sniffer.close()

if __name__ == "__main__":
    # Parâmetros: interface, ip_do_servidor, buffer, porta_servidor, porta_cliente
    start_server("eth0", "10.0.1.2", 65535, 9999, 12345)