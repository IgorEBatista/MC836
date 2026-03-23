import os
import socket
import time
from rich import print
from rich.markdown import Markdown
from helper import unpack_iph, unpack_udp, unpack_data, build_udp_packet
from rtp_protocol import rtp_unpack, RTP_HEADER_SIZE

# Porta onde o cliente espera receber a resposta
REC_PORT = 12345
# Diretório para salvar vídeos recebidos
VIDEOS_DIR = "videos"


def receive_text_response(sniffer: socket.socket) -> str:
    """Aguarda uma única resposta de texto (catálogo, erro, etc.)."""
    while True:
        raw_packet, _ = sniffer.recvfrom(65535)
        raw_packet = raw_packet[14:]  # Pula header Ethernet

        if len(raw_packet) < 28:
            continue
        iph = unpack_iph(raw_packet)
        if iph[6] != 17:
            continue
        udph = unpack_udp(raw_packet)
        if udph[1] != REC_PORT:
            continue

        data = unpack_data(raw_packet)
        return data.decode("utf-8", errors="ignore")


def receive_stream(sniffer: socket.socket, video_name: str):
    """
    Recebe pacotes RTP do servidor e salva o vídeo em disco.
    Detecta automaticamente se a resposta é erro (texto) ou stream (RTP).

    Detecção: se o payload UDP tem ≥ 12 bytes e o primeiro byte indica
    versão RTP = 2 (bits 6-7 == 0b10), é um pacote RTP. Caso contrário,
    é uma mensagem de texto (erro do servidor).
    """
    TIMEOUT = 3.0  # Segundos sem pacotes para considerar fim do stream

    os.makedirs(VIDEOS_DIR, exist_ok=True)
    output_path = os.path.join(VIDEOS_DIR, video_name)

    total_packets = 0
    total_bytes = 0
    lost_packets = 0
    expected_seq = None
    file_handle = None

    sniffer.settimeout(TIMEOUT)
    try:
        while True:
            try:
                raw_packet, _ = sniffer.recvfrom(65535)
            except socket.timeout:
                if total_packets == 0:
                    print("[!] Timeout: nenhuma resposta do servidor.")
                else:
                    print(f"[!] Timeout de {TIMEOUT}s sem pacotes. Fim do stream.")
                break

            raw_packet = raw_packet[14:]  # Pula header Ethernet

            if len(raw_packet) < 28:
                continue
            iph = unpack_iph(raw_packet)
            if iph[6] != 17:
                continue
            udph = unpack_udp(raw_packet)
            if udph[1] != REC_PORT:
                continue

            udp_payload = unpack_data(raw_packet)

            # --- Detecção: RTP ou mensagem de texto? ---
            # Pacote RTP: ≥ 12 bytes e versão = 2 (bits 6-7 do primeiro byte)
            is_rtp = len(udp_payload) >= RTP_HEADER_SIZE and ((udp_payload[0] >> 6) & 0x03) == 2

            if not is_rtp:
                # É uma mensagem de texto (erro do servidor)
                text = udp_payload.decode("utf-8", errors="ignore")
                print(f"> Resposta do Servidor: {text}")
                break

            # --- É pacote RTP: processar stream ---
            if file_handle is None:
                print(f"[+] Recebendo stream → {output_path}")
                file_handle = open(output_path, "wb")

            rtp = rtp_unpack(udp_payload)

            # Detecção de perda de pacotes pelo sequence number
            if expected_seq is not None:
                diff = (rtp["seq"] - expected_seq) & 0xFFFF
                if 1 < diff < 0x8000:
                    lost_packets += diff - 1
            expected_seq = (rtp["seq"] + 1) & 0xFFFF

            file_handle.write(rtp["payload"])
            total_packets += 1
            total_bytes += len(rtp["payload"])

            if total_packets % 100 == 0:
                print(f"  [{total_packets} pkts | {total_bytes / 1316:.1f} KB | perdidos: {lost_packets}]")

    finally:
        sniffer.settimeout(None)
        if file_handle is not None:
            file_handle.close()

    if total_packets > 0:
        print(f"\n[bold green]✓ Stream finalizado![/bold green]")
        print(f"  Pacotes recebidos: {total_packets}")
        print(f"  Pacotes perdidos:  {lost_packets}")
        print(f"  Total recebido:    {total_bytes / 1024:.1f} KB")
        print(f"  Salvo em:          {output_path}")


def start_client():
    """
    Inicia o cliente de streaming utilizando Raw Sockets.
    """

    # Socket para ENVIAR pacotes (Nível IP bruto)
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Socket para SNIFFING (Capturar pacotes que chegam na interface)
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sniffer.bind(("eth0", 0))

    dest_ip = "10.0.1.2"  # IP do Servidor

    print(Markdown("""# Aplicação de Streaming (Client-Side)
                   BEM VINDO A TWITCHÊ!
    - Digite **catalog** para listar vídeos.
    - Digite **stream <nome_do_video>** para assistir.
    - Digite **q** para sair.
    """))
    print("-" * 25)

    try:
        while True:
            msg = input("\nTu (Cliente) > ")
            if msg.strip() == 'q':
                break

            # Envia o comando para o servidor
            packet = build_udp_packet(
                src_ip="10.0.2.2",
                dest_ip=dest_ip,
                src_port=REC_PORT,
                dest_port=9999,
                data=msg,
            )
            sender.sendto(packet, (dest_ip, 0))
            print("[-] Pacote enviado. Aguardando resposta do servidor...")

            # Se for streaming, entra no modo de recepção RTP
            if msg.strip().startswith("stream "):
                video_name = msg.strip().split(" ", 1)[1]
                receive_stream(sniffer, video_name)
            else:
                # Resposta de texto (catalog, erro, etc.)
                response = receive_text_response(sniffer)
                print(f"> Resposta do Servidor: {response}")

    except KeyboardInterrupt:
        print("\n[!] Encerrando cliente...")
    finally:
        sender.close()
        sniffer.close()


if __name__ == "__main__":
    start_client()