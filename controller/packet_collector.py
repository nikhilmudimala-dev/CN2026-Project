import time

from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import tcp

from controller.detection_engine import TrafficRecord


class PacketCollector:

    def parse_packet(self, message):

        current_time = time.time()

        pkt = packet.Packet(message.data)

        # Extract Ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return None

        # Extract IPv4 header
        ip = pkt.get_protocol(ipv4.ipv4)

        if ip is None:
            return None

        # Extract TCP header
        tcp_header = pkt.get_protocol(tcp.tcp)

        if tcp_header is None:
            return None

        flags = tcp_header.bits

        # Identify TCP flags
        syn = bool(flags & tcp.TCP_SYN)
        ack = bool(flags & tcp.TCP_ACK)
        fin = bool(flags & tcp.TCP_FIN)
        rst = bool(flags & tcp.TCP_RST)

        # Build the standard traffic record
        traffic = TrafficRecord(
            timestamp=current_time,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol="TCP",

            src_port=tcp_header.src_port,
            dst_port=tcp_header.dst_port,

            tcp_syn=syn,
            tcp_ack=ack,
            tcp_fin=fin,
            tcp_rst=rst
        )

        return traffic
