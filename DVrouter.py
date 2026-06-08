####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

import json

from packet import Packet
from router import Router


class DVrouter(Router):
    """Distance vector routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.INFINITY = 10**9
        self.neighbors = {}
        self.endpoint_to_port = {}
        self.neighbor_vectors = {}
        self.distance_vector = {self.addr: 0}
        self.forwarding_table = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            out_port = self.forwarding_table.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
        else:
            try:
                received_vector = json.loads(packet.content)
            except (TypeError, ValueError):
                return

            received_vector = {
                destination: cost
                for destination, cost in received_vector.items()
                if isinstance(cost, (int, float))
            }

            if self.neighbor_vectors.get(packet.src_addr) != received_vector:
                self.neighbor_vectors[packet.src_addr] = received_vector
                if self._recompute_routes():
                    self._broadcast_distance_vector()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        old_endpoint = self.neighbors.get(port, (None, None))[0]
        if old_endpoint is not None and old_endpoint != endpoint:
            self.endpoint_to_port.pop(old_endpoint, None)
            self.neighbor_vectors.pop(old_endpoint, None)

        old_port = self.endpoint_to_port.get(endpoint)
        if old_port is not None and old_port != port:
            self.neighbors.pop(old_port, None)

        self.neighbors[port] = (endpoint, cost)
        self.endpoint_to_port[endpoint] = port
        self._recompute_routes()
        self._broadcast_distance_vector()

    def handle_remove_link(self, port):
        """Handle removed link."""
        endpoint, _ = self.neighbors.pop(port, (None, None))
        if endpoint is None:
            return

        self.endpoint_to_port.pop(endpoint, None)
        self.neighbor_vectors.pop(endpoint, None)
        self._recompute_routes()
        self._broadcast_distance_vector()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_distance_vector()

    def _recompute_routes(self):
        new_distance_vector = {self.addr: 0}
        new_forwarding_table = {}

        for port, (endpoint, cost) in self.neighbors.items():
            if endpoint == self.addr or cost >= self.INFINITY:
                continue
            new_distance_vector[endpoint] = cost
            new_forwarding_table[endpoint] = port

        for port, (neighbor, link_cost) in self.neighbors.items():
            if link_cost >= self.INFINITY:
                continue

            neighbor_vector = self.neighbor_vectors.get(neighbor, {})
            for destination, neighbor_cost in neighbor_vector.items():
                if destination == self.addr or neighbor_cost >= self.INFINITY:
                    continue

                total_cost = link_cost + neighbor_cost
                if total_cost >= self.INFINITY:
                    continue

                current_cost = new_distance_vector.get(destination)
                if current_cost is None or total_cost < current_cost:
                    new_distance_vector[destination] = total_cost
                    new_forwarding_table[destination] = port

        changed = (
            new_distance_vector != self.distance_vector
            or new_forwarding_table != self.forwarding_table
        )
        self.distance_vector = new_distance_vector
        self.forwarding_table = new_forwarding_table
        return changed

    def _broadcast_distance_vector(self):
        for port, (endpoint, _) in self.neighbors.items():
            self._send_distance_vector(port, endpoint)

    def _send_distance_vector(self, port, endpoint):
        advertised_vector = dict(self.distance_vector)
        for destination, out_port in self.forwarding_table.items():
            if out_port == port:
                advertised_vector[destination] = self.INFINITY

        content = json.dumps(advertised_vector)
        packet = Packet(Packet.ROUTING, self.addr, endpoint, content)
        self.send(port, packet)

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return (
            f"DVrouter(addr={self.addr}, "
            f"dv={self.distance_vector}, "
            f"forwarding={self.forwarding_table})"
        )
