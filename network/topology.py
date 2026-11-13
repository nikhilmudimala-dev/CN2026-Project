
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from traffic.control_server import ControlServer


def create_topology():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        build=False
    )

    control_server = None

    try:
        info("*** Adding remote controller\n")
        net.addController(
            "c0",
            controller=RemoteController,
            ip="127.0.0.1",
            port=6653
        )

        info("*** Adding core switch\n")
        core = net.addSwitch("s1", protocols="OpenFlow13")

        info("*** Adding access switches\n")
        access_switches = []

        for i in range(2, 5):
            switch = net.addSwitch(f"s{i}", protocols="OpenFlow13")
            access_switches.append(switch)
            net.addLink(core, switch, bw=100)

        info("*** Adding 12 hosts\n")
        host_number = 1

        for switch in access_switches:
            for _ in range(4):
                host = net.addHost(
                    f"h{host_number}",
                    ip=f"10.0.0.{host_number}/24"
                )
                net.addLink(host, switch, bw=20)
                host_number += 1

        info("*** Building network\n")
        net.build()

        info("*** Starting controller connection\n")
        for controller in net.controllers:
            controller.start()

        info("*** Starting switches\n")
        for switch in net.switches:
            switch.start([net.controllers[0]])

        info("*** Starting traffic control server\n")
        control_server = ControlServer(net)
        control_server.start()

        info("*** Network started\n")
        info("*** Traffic control available on 127.0.0.1:8765\n")

        CLI(net)

    finally:
        info("*** Stopping traffic control server\n")

        if control_server:
            control_server.stop()

        info("*** Stopping network\n")
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    create_topology()

