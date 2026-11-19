"""The real network: a Scapy send socket plus a background sniffer.
Scapy networking is imported inside functions, so plan mode and the tests never open a socket."""
import queue
import threading
from dataclasses import dataclass

from .engine import RealClock


class TransportError(RuntimeError):
    """The network could not be used (permissions, interface, capture)."""


@dataclass
class Session:
    transport: object
    clock: object
    source_ip: str
    scapy_version: str

    def close(self):
        if hasattr(self.transport, "close"):
            self.transport.close()


def preflight(interface, target):
    """Make sure the target is reached directly through the scoped interface. Returns our IP."""
    from scapy.all import conf, get_if_addr
    from scapy.interfaces import resolve_iface
    try:
        source_ip = get_if_addr(resolve_iface(interface))
        route_iface, _, gateway = conf.route.route(target)
    except Exception as error:
        raise TransportError(f"interface {interface!r} or route to {target} is not usable: {error}") from None
    if not source_ip or source_ip == "0.0.0.0":
        raise TransportError(f"interface {interface!r} has no IPv4 address")
    if getattr(route_iface, "name", str(route_iface)) != interface:
        raise TransportError(f"{target} is routed via {route_iface}, not {interface!r}; refusing to send")
    if gateway not in ("0.0.0.0", None, ""):
        raise TransportError(f"{target} is not directly on {interface!r} (gateway {gateway}); refusing to send")
    return source_ip


class ScapyTransport:
    def __init__(self, interface, target):
        from scapy.all import AsyncSniffer, conf
        self.packets = queue.Queue()
        ready = threading.Event()
        try:
            self.socket = conf.L3socket(iface=interface)
        except OSError as error:
            raise TransportError(f"cannot open raw send socket on {interface!r} (needs root/NET_RAW): {error}") from None
        # Keep TCP from the target, and any ICMP (the engine decides if it belongs to us).
        self.sniffer = AsyncSniffer(iface=interface, filter=f"(tcp and src host {target}) or icmp",
                                    store=False, prn=self.packets.put, started_callback=ready.set)
        try:
            self.sniffer.start()
        except Exception as error:
            self.socket.close()
            raise TransportError(f"cannot start packet capture on {interface!r}: {error}") from None
        if not ready.wait(5):
            self.close()
            raise TransportError("packet capture did not start within 5 seconds")

    def send(self, packet):
        try:
            self.socket.send(packet)
        except OSError as error:
            raise TransportError(f"transmit failed: {error}") from None

    def receive(self, timeout):
        """Next captured packet, or None if nothing arrives within `timeout` seconds."""
        try:
            return self.packets.get(timeout=timeout) if timeout > 0 else self.packets.get_nowait()
        except queue.Empty:
            if not self.sniffer.thread.is_alive():
                raise TransportError("packet capture stopped unexpectedly") from None
            return None

    def close(self):
        for stop in (self.sniffer.stop, self.socket.close):
            try:
                stop()
            except Exception:
                pass


def open_scapy_session(interface, target):
    import scapy
    source_ip = preflight(interface, target)
    return Session(ScapyTransport(interface, target), RealClock(), source_ip, scapy.__version__)
