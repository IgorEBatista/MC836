"""
Implementação simplificada do protocolo RTP (Real-time Transport Protocol).

Header RTP (12 bytes fixos):
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|X|  CC   |M|     PT      |       Sequence Number         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           Timestamp                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             SSRC                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

import struct
import random

# Header: 1 byte (V|P|X|CC) + 1 byte (M|PT) + 2 bytes (Seq) + 4 bytes (TS) + 4 bytes (SSRC) = 12 bytes
RTP_HEADER_FORMAT = "!BBHII"
RTP_HEADER_SIZE = 12

# Payload type para vídeo (faixa dinâmica: 96-127)
PT_VIDEO = 96


def rtp_pack(seq: int, timestamp: int, ssrc: int, payload: bytes, marker: bool = False, pt: int = PT_VIDEO) -> bytes:
    """
    Monta um pacote RTP (header 12 bytes + payload).

    Args:
        seq: Número de sequência (0-65535)
        timestamp: Timestamp relativo ao clock do codec
        ssrc: Identificador da fonte
        payload: Dados de mídia em bytes
        marker: True no primeiro pacote de um frame
        pt: Payload Type (default: 96 = vídeo dinâmico)

    Retorna:
        bytes: Pacote RTP completo
    """
    byte0 = (2 << 6)  # V=2, P=0, X=0, CC=0
    byte1 = (int(marker) << 7) | (pt & 0x7F)
    header = struct.pack(RTP_HEADER_FORMAT, byte0, byte1, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc & 0xFFFFFFFF)
    return header + payload


def rtp_unpack(data: bytes) -> dict:
    """
    Faz o parse de um pacote RTP.

    Args:
        data: Bytes do pacote RTP (mín. 12 bytes)

    Retorna:
        dict com: version, marker, payload_type, seq, timestamp, ssrc, payload
    """
    if len(data) < RTP_HEADER_SIZE:
        raise ValueError(f"Pacote RTP muito curto: {len(data)} bytes")

    byte0, byte1, seq, timestamp, ssrc = struct.unpack(RTP_HEADER_FORMAT, data[:RTP_HEADER_SIZE])

    return {
        "version": (byte0 >> 6) & 0x03,
        "marker": bool((byte1 >> 7) & 0x01),
        "payload_type": byte1 & 0x7F,
        "seq": seq,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "payload": data[RTP_HEADER_SIZE:],
    }


def make_ssrc() -> int:
    """Gera um SSRC aleatório de 32 bits."""
    return random.randint(0, 0xFFFFFFFF)
