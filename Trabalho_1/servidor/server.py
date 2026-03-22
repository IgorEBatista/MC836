import socket
from rich import print
from helper import unpack_iph, unpack_udp, unpack_data, build_udp_packet

def send_catalog(sender, src_ip: str, src_port: int, client_ip: str, client_port: int):
    """
    Envia uma mensagem de catálogo para o cliente.

    Instruções:
    1. Defina a mensagem de resposta (ex: "Catálogo: video1, video2").
    2. Utilize a função build_udp_packet para montar o pacote completo.
    3. Envie o pacote usando o socket 'sender'.
    """
    msg = "Catálogo: [Ainda não disponível - Implemente no servidor]"

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

            # --- TAREFA: PROCESSAMENTO DO CABEÇALHO IP ---
            # 1. Chamar unpack_iph(raw_packet)
            iph = unpack_iph(raw_packet)
            # 2. Validar se o protocolo é UDP (valor 17)
            if iph[6] != 17:
                continue

            # Dica: O endereço IP do cliente estará no header IP. 
            # Use socket.inet_ntoa() para converter os bytes do IP para string.

            client_ip = socket.inet_ntoa(iph[8])
            print(f"\n[+] Pacote recebido de {client_ip}")

            # --- TAREFA: PROCESSAMENTO DO CABEÇALHO UDP ---
            # 1. Chamar unpack_udp(raw_packet)
            udph = unpack_udp(raw_packet)
            # 2. Validar se a porta de destino do pacote é a porta do servidor (src_port)
            if udph[1] != src_port:
                continue
            client_port = udph[0]
            # --- TAREFA: PAYLOAD E LÓGICA ---
            # 1. Chamar unpack_data(raw_packet)
            data = unpack_data(raw_packet).decode(errors='ignore')
            print(f"Payload recebido: {data}")
            # 2. Se o dado for 'catalog', chamar a função send_catalog()
            if data.strip() == 'catalog':
                send_catalog(sender, src_ip, src_port, client_ip, client_port)
            # 3. Se o dado for 'stream nome_video', chamar a função start_streaming() (a ser implementada) #TODO: IMPLEMENTAR
            elif data.startswith('stream'):
                print("[!] Comando de streaming recebido, mas a função start_streaming() ainda não foi implementada.")
                # start_streaming(sender, src_ip, src_port, client_ip, client_port, nome_video)
                pass
            # --- TAREFA: Streaming ---
            # 1. Chamar unpack_data(raw_packet)
            # 2. Se o dado for 'stream nome_video', chamar a função start_streaming()

            pass

    except KeyboardInterrupt:
        print("\n[!] Desligando servidor...")
    finally:
        sender.close()
        sniffer.close()

if __name__ == "__main__":
    # Parâmetros: interface, ip_do_servidor, buffer, porta_servidor, porta_cliente
    start_server("eth0", "10.0.1.2", 65535, 9999, 12345)