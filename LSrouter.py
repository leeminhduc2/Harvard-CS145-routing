####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

import heapq
import json

from packet import Packet
from router import Router


class LinkStateRecord:
    """Stores one router's link state with its newest sequence number."""

    def __init__(self, sequence_number=-1, links=None):
        self.sequence_number = sequence_number
        self.links = dict(links or {})

    def update_if_newer(self, sequence_number, links):
        if sequence_number <= self.sequence_number:
            return False

        self.sequence_number = sequence_number
        self.links = dict(links)
        return True


class LSrouter(Router):
    """Link state routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.neighbors = {}
        self.endpoint_to_port = {}
        self.link_states = {}
        self.local_sequence_number = 0
        self.forwarding_table = {}
        self.link_states[self.addr] = LinkStateRecord(
            self.local_sequence_number, self._local_links()
        )

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            out_port = self.forwarding_table.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
        else:
            message = self._parse_link_state(packet.content)
            if message is None:
                return

            origin, sequence_number, links = message
            record = self.link_states.get(origin)
            if record is None:
                record = LinkStateRecord()
                self.link_states[origin] = record

            if record.update_if_newer(sequence_number, links):
                self._recompute_routes()
                self._flood_link_state(packet.content, port)

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        old_endpoint = self.neighbors.get(port, (None, None))[0]
        if old_endpoint is not None and old_endpoint != endpoint:
            self.endpoint_to_port.pop(old_endpoint, None)

        old_port = self.endpoint_to_port.get(endpoint)
        if old_port is not None and old_port != port:
            self.neighbors.pop(old_port, None)

        self.neighbors[port] = (endpoint, cost)
        self.endpoint_to_port[endpoint] = port
        self._refresh_own_link_state()
        self._recompute_routes()
        self._broadcast_own_link_state()

    def handle_remove_link(self, port):
        """Handle removed link."""
        endpoint, _ = self.neighbors.pop(port, (None, None))
        if endpoint is None:
            return

        self.endpoint_to_port.pop(endpoint, None)
        self._refresh_own_link_state()
        self._recompute_routes()
        self._broadcast_own_link_state()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_own_link_state()

    def _local_links(self):
        links = {}
        for endpoint, cost in self.neighbors.values():
            links[endpoint] = cost
        return links

    def _refresh_own_link_state(self):
        self.local_sequence_number += 1
        self.link_states[self.addr] = LinkStateRecord(
            self.local_sequence_number, self._local_links()
        )

    def _parse_link_state(self, content):
        try:
            message = json.loads(content)
        except (TypeError, ValueError):
            return None

        if not isinstance(message, dict):
            return None

        origin = message.get("origin")
        sequence_number = message.get("sequence_number")
        links = message.get("links")
        if origin is None or not isinstance(sequence_number, int):
            return None
        if not isinstance(links, dict):
            return None

        clean_links = {}
        for endpoint, cost in links.items():
            if isinstance(cost, (int, float)):
                clean_links[endpoint] = cost

        return origin, sequence_number, clean_links

    def _own_link_state_content(self):
        record = self.link_states[self.addr]
        message = {
            "origin": self.addr,
            "sequence_number": record.sequence_number,
            "links": record.links,
        }
        return json.dumps(message)

    def _broadcast_own_link_state(self):
        content = self._own_link_state_content()
        for port, (endpoint, _) in self.neighbors.items():
            packet = Packet(Packet.ROUTING, self.addr, endpoint, content)
            self.send(port, packet)

    def _flood_link_state(self, content, incoming_port):
        for port, (endpoint, _) in self.neighbors.items():
            if port == incoming_port:
                continue
            packet = Packet(Packet.ROUTING, self.addr, endpoint, content)
            self.send(port, packet)

    def _recompute_routes(self):
        graph = self._build_graph()
        distances = {self.addr: 0}
        first_hops = {}
        visited = set()
        heap = [(0, self.addr, None)]

        while heap:
            current_cost, node, first_hop = heapq.heappop(heap)
            if node in visited:
                continue

            visited.add(node)
            distances[node] = current_cost
            if first_hop is not None:
                first_hops[node] = first_hop

            for neighbor, link_cost in sorted(
                graph.get(node, {}).items(), key=lambda item: str(item[0])
            ):
                if neighbor in visited:
                    continue

                next_cost = current_cost + link_cost
                next_first_hop = neighbor if node == self.addr else first_hop
                old_cost = distances.get(neighbor)
                if old_cost is None or next_cost < old_cost:
                    distances[neighbor] = next_cost
                    heapq.heappush(
                        heap,
                        (next_cost, neighbor, next_first_hop),
                    )

        new_forwarding_table = {}
        for destination, first_hop in first_hops.items():
            if destination == self.addr:
                continue

            out_port = self.endpoint_to_port.get(first_hop)
            if out_port is not None:
                new_forwarding_table[destination] = out_port

        self.forwarding_table = new_forwarding_table

    def _build_graph(self):
        graph = {}
        for origin, record in self.link_states.items():
            graph.setdefault(origin, {})
            for endpoint, cost in record.links.items():
                graph.setdefault(endpoint, {})

                current_cost = graph[origin].get(endpoint)
                if current_cost is None or cost < current_cost:
                    graph[origin][endpoint] = cost
                    graph[endpoint][origin] = cost

        return graph

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return (
            f"LSrouter(addr={self.addr}, "
            f"seq={self.local_sequence_number}, "
            f"neighbors={self.neighbors}, "
            f"forwarding={self.forwarding_table})"
        )
