from scapy.all import *
from scapy.packet import Packet, Protocol
from scapy.fields import ByteField, IntField, IPField, FieldLenField, PacketListField
import os

# Define AODV packets
class AODVRREQ(Packet):
    name = "AODV RREQ"
    fields_desc = [
        ByteField("type", 1),  # Tipo de mensaje: RREQ
        ByteField("flags", 0),
        IntField("hop_count", 0),
        IntField("request_id", 0),
        IPField("dest_addr", "0.0.0.0"),
        IntField("dest_seq", 0),
        IPField("orig_addr", "0.0.0.0"),
        IntField("orig_seq", 0),
    ]

class AODVRREP(Packet):
    name = "AODV RREP"
    fields_desc = [
        ByteField("type", 2),  # Tipo de mensaje: RREP
        ByteField("flags", 0),
        IntField("hop_count", 0),
        IPField("dest_addr", "0.0.0.0"),
        IntField("dest_seq", 0),
        IPField("orig_addr", "0.0.0.0"),
        IntField("lifetime", 0),
    ]

class AODVRERR(Packet):
    name = "AODV RERR"
    fields_desc = [
        ByteField("type", 3),  # Tipo de mensaje: RERR
        FieldLenField("num_unreachable", None, length_of="unreachable"),
        PacketListField("unreachable", [], IPField, count_from=lambda pkt: pkt.num_unreachable),
    ]

# Define AODV protocol
class AODV(Protocol):
    name = "AODV Protocol"
    fields_desc = []

    def guess_payload_class(self, payload):
        # Determinar el tipo de paquete basado en el campo 'type'
        if len(payload) > 0:
            msg_type = payload[0]
            if msg_type == 1:
                return AODVRREQ
            elif msg_type == 2:
                return AODVRREP
            elif msg_type == 3:
                return AODVRERR
        return Raw

# Bind AODV to Ethernet
bind_layers(Ether, AODV, type=0x1234)

# Routing table
routing_table = {}

def add_route(dest_addr, next_hop, dest_seq, hop_count):
    """Agregar una ruta a la tabla de enrutamiento."""
    routing_table[dest_addr] = {
        "next_hop": next_hop,
        "dest_seq": dest_seq,
        "hop_count": hop_count
    }

def handle_rreq(packet):
    """Procesar paquetes RREQ entrantes."""
    print(f"RREQ recibido de {packet[AODVRREQ].orig_addr}")
    add_route(
        packet[AODVRREQ].orig_addr,
        packet.src,
        packet[AODVRREQ].orig_seq,
        packet[AODVRREQ].hop_count + 1,
    )
    if packet[AODVRREQ].dest_addr == get_if_addr("bat0"):
        rrep = Ether(dst=packet.src) / AODV() / AODVRREP(
            dest_addr=packet[AODVRREQ].dest_addr,
            orig_addr=packet[AODVRREQ].orig_addr,
            dest_seq=packet[AODVRREQ].dest_seq,
            hop_count=0,
            lifetime=120
        )
        sendp(rrep, iface="bat0")
    else:
        packet[AODVRREQ].hop_count += 1
        sendp(packet, iface="bat0")

def handle_rrep(packet):
    """Procesar paquetes RREP entrantes."""
    print(f"RREP recibido para {packet[AODVRREP].dest_addr}")
    add_route(
        packet[AODVRREP].dest_addr,
        packet.src,
        packet[AODVRREP].dest_seq,
        packet[AODVRREP].hop_count + 1,
    )
    if packet[AODVRREP].orig_addr != get_if_addr("bat0"):
        packet[AODVRREP].hop_count += 1
        sendp(packet, iface="bat0")

def handle_rerr(packet):
    """Procesar paquetes RERR entrantes."""
    print(f"RERR recibido con {packet[AODVRERR].num_unreachable} destinos inalcanzables")
    for entry in packet[AODVRERR].unreachable:
        if entry in routing_table:
            del routing_table[entry]

def process_packet(packet):
    """Procesar paquetes entrantes."""
    if AODVRREQ in packet:
        handle_rreq(packet)
    elif AODVRREP in packet:
        handle_rrep(packet)
    elif AODVRERR in packet:
        handle_rerr(packet)

def start_sniffing():
    """Iniciar captura de paquetes en la interfaz de batman-adv."""
    sniff(iface="bat0", prn=process_packet, filter="ether proto 0x1234")

def send_rreq(dest_addr, orig_addr):
    """Falta ver si Ether o Dot11 es la manera correcta para entrar a batman""" 
    rreq = Ether(dst="ff:ff:ff:ff:ff:ff") / AODV() / AODVRREQ(
        dest_addr=dest_addr,
        orig_addr=orig_addr,
        request_id=1,
        dest_seq=0,
        orig_seq=1,
        hop_count=0
    )
    sendp(rreq, iface="bat0")


if __name__ == "__main__":
    print("Iniciando protocolo AODV sobre batman-adv")
    start_sniffing()
