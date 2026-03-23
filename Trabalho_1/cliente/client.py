import socket
from rich import print
from rich.markdown import Markdown
from helper import unpack_iph, unpack_udp, unpack_data, build_udp_packet

# Porta onde o cliente espera receber a resposta
REC_PORT = 12345

def start_client():
    """
    Inicia o cliente de streaming utilizando Raw Sockets.
    Você deve garantir que as funções de unpack e build_packet estejam prontas.
    """

    # Socket para ENVIAR pacotes (Nível IP bruto)
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Socket para SNIFFING (Capturar pacotes que chegam na interface)
    # Nota: "eth0" deve ser alterado conforme a interface da máquina
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sniffer.bind(("eth0", 0))

    dest_ip = "10.0.1.2" # IP do Servidor

    print(Markdown("""# Aplicação de Streaming (Client-Side)
    - Digite **catalog** para listar vídeos.
    - Digite **stream <nome_do_video>** para assistir.
    - Digite **q** para sair.
    """))
    print("-" * 25)

    try:
        while True:            
            msg = input("\nTu (Cliente) > ")
            if msg == 'q': break

            # --- TAREFA: CONSTRUÇÃO ---
            # Você deve usar sua implementação de build_udp_packet aqui
            packet = build_udp_packet(
                src_ip="10.0.2.2", 
                dest_ip=dest_ip,
                src_port=REC_PORT,
                dest_port=9999,
                data=msg
            )

            sender.sendto(packet, (dest_ip, 0))
            print("[-] Pacote enviado. Aguardando resposta do servidor...")

            # --- TAREFA: FILTRAGEM E UNPACK ---
            while True:
                # Captura o pacote bruto da rede
                raw_packet, _ = sniffer.recvfrom(65535)
                raw_packet = raw_packet[14:]  # Pula o header Ethernet (14 bytes)
                # 1. Verificar se o pacote tem o tamanho mínimo (IP + UDP = 28 bytes)
                if len(raw_packet) < 28: 
                    continue

                # 2. Extrair o Header IP usando unpack_iph()
                iph = unpack_iph(raw_packet)
                # 3. Validar se o protocolo no Header IP é UDP (17)
                if iph[6] != 17:
                    continue

                # 4. Extrair o Header UDP usando unpack_udp()
                udph = unpack_udp(raw_packet)
                # 5. Validar se a porta de destino (Dest Port) é a REC_PORT do cliente
                if udph[1] != REC_PORT:
                    continue
                # 6. Extrair os dados usando unpack_data()
                data = unpack_data(raw_packet)
                # 7. Exibir a resposta do servidor e quebrar o loop de espera
                print(f'> Resposta do Servidor: {data.decode("utf-8")}')
                break
                
                # Exemplo de lógica esperada dentro deste loop:
                # iph = unpack_iph(raw_packet)
                # if iph_valido and protocolo_udp:
                #     udph = unpack_udp(raw_packet)
                #     if porta_correta:
                #         data = unpack_data(raw_packet)
                #         print(f'> Server response: {data.decode("utf-8")}')
                #         break  

    except KeyboardInterrupt:
        print("\n[!] Encerrando cliente...")
    finally:
        sender.close()
        sniffer.close()

if __name__ == "__main__":
    # Certifique-se de que build_udp_packet e as funções de unpack 
    # estejam no mesmo arquivo ou importadas.
    start_client()