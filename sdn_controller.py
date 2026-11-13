
import time

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls
)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import packet, ethernet

from controller.packet_collector import PacketCollector
from controller.pipeline import DetectionPipeline


class DynamicHostBlockingController(app_manager.OSKenApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    HOST_INGRESS_PORTS = {
        2: {2, 3, 4, 5},
        3: {2, 3, 4, 5},
        4: {2, 3, 4, 5}
    }

    def __init__(self, *args, **kwargs):

        super(DynamicHostBlockingController, self).__init__(
            *args, **kwargs
        )

        self.logger.info("Initializing Dynamic Host Blocking Controller")

        self.pipeline = DetectionPipeline()
        self.packet_collector = PacketCollector()

        self.datapaths = {}
        self.mac_to_port = {}

        self.logger.info("Controller initialization complete")

        self.window_finalizer = hub.spawn(self._window_finalizer)

    def _window_finalizer(self):

        while True:

            hub.sleep(1)

            try:

                results = self.pipeline.finalize_windows(
                    time.time(),
                    list(self.datapaths.values())
                )

                for result in results:

                    detection = result["detection"]

                    self.logger.warning(
                        "%s detected from %s: %s",
                        detection.rule_id,
                        detection.source_ip,
                        detection.reason
                    )

            except Exception:

                self.logger.exception(
                    "Error while finalizing detection windows"
                )

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER
    )
    def switch_features_handler(self, event):

        datapath = event.msg.datapath

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        self.logger.info("Switch connected: %s", datapath.id)

        self.install_table_miss(datapath)

        restored = self.pipeline.blocking_manager.restore_active_bans(
            list(self.datapaths.values())
        )

        if restored:
            self.logger.info("Restored active bans: %s", restored)

    def install_table_miss(self, datapath):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=match,
            instructions=instructions
        )

        datapath.send_msg(flow_mod)

        self.logger.info(
            "Table-miss rule installed on switch %s",
            datapath.id
        )

    def is_host_ingress(self, datapath_id, in_port):

        host_ports = self.HOST_INGRESS_PORTS.get(
            datapath_id,
            set()
        )

        return in_port in host_ports

    def forward_packet(self, message):

        datapath = message.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        in_port = message.match["in_port"]

        pkt = packet.Packet(message.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        if eth.ethertype == 0x88cc:
            return

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:

            out_port = self.mac_to_port[dpid][dst_mac]

            if out_port == in_port:
                return

        else:

            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        data = None

        if message.buffer_id == ofproto.OFP_NO_BUFFER:
            data = message.data

        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=message.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(packet_out)

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def packet_in_handler(self, event):

        message = event.msg
        datapath = message.datapath

        try:

            in_port = message.match["in_port"]

            if self.is_host_ingress(datapath.id, in_port):

                traffic = self.packet_collector.parse_packet(message)

                if traffic is not None:

                    results = self.pipeline.process_traffic(
                        traffic,
                        list(self.datapaths.values())
                    )

                    for result in results:

                        detection = result["detection"]

                        self.logger.warning(
                            "%s detected from %s: %s",
                            detection.rule_id,
                            detection.source_ip,
                            detection.reason
                        )

                    if self.pipeline.blocking_manager.is_blocked(
                        traffic.src_ip
                    ):
                        return

            self.forward_packet(message)

        except Exception as error:

            self.logger.exception(
                "Error processing packet from switch %s: %s",
                datapath.id,
                error
            )

    @set_ev_cls(
        ofp_event.EventOFPFlowRemoved,
        MAIN_DISPATCHER
    )
    def flow_removed_handler(self, event):

        message = event.msg

        result = self.pipeline.blocking_manager.handle_flow_removed(
            datapath_id=message.datapath.id,
            cookie=message.cookie
        )

        if result is not None:

            self.pipeline.event_manager.publish(
                event_type="BAN_EXPIRED",
                source_ip=result["source_ip"],
                rule_id=result["rule_id"],
                message="Temporary blocking period has ended"
            )

            self.logger.info(
                "Ban expired for host %s",
                result["source_ip"]
            )

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def switch_state_handler(self, event):

        datapath = event.datapath

        if event.state == MAIN_DISPATCHER:

            self.datapaths[datapath.id] = datapath
            self.mac_to_port.setdefault(datapath.id, {})

            self.logger.info(
                "Switch active: %s",
                datapath.id
            )

        elif event.state == DEAD_DISPATCHER:

            self.datapaths.pop(datapath.id, None)
            self.mac_to_port.pop(datapath.id, None)

            self.logger.warning(
                "Switch disconnected: %s",
                datapath.id
            )

