"""
PacketInfo.py — Per-packet feature extractor.

Wraps a raw Scapy packet and exposes typed accessors used by Flow.py to
build CICFlowMeter-compatible network flow features.

Design notes
------------
- All flag parsing is done once in `_parse_tcp_flags()` rather than
  re-parsing the flags string six times (original had six identical loops).
- PID/process lookup is done once per packet in `_resolve_process()` rather
  than being duplicated across `setSrcPort` and `setDestPort`.
- `psutil.net_connections()` is called at most once per packet; the original
  called it twice (once in each port setter).
- Flow IDs are built lazily via `setFwdID()`/`setBwdID()` as before, but now
  use an f-string for clarity.
- `__slots__` reduces per-instance memory — PacketInfo is created for every
  captured packet, so this matters.
"""

from __future__ import annotations

import logging

import psutil
from scapy.layers.inet import IP, TCP, UDP

log = logging.getLogger(__name__)

# Scapy represents TCP flags as a string of single-character codes.
# Map each code to its human-readable name.
_FLAG_CHARS: dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
    "N": "",
}


def _parse_tcp_flags(p) -> frozenset[str]:
    """
    Return the set of flag names present in a TCP packet.
    Returns an empty frozenset for non-TCP packets.
    """
    if not p.haslayer(TCP):
        return frozenset()
    raw = p[TCP].flags  # e.g. "PA", "S", "FA"
    return frozenset(_FLAG_CHARS[c] for c in str(raw) if c in _FLAG_CHARS)


def _resolve_process(src_port: int, dest_port: int) -> tuple[int | None, str]:
    """
    Attempt to identify the local process that owns this connection by
    matching laddr.port against src_port or dest_port.

    Returns (pid, process_name) or (None, '') if not found.

    Note: `psutil.net_connections()` requires elevated privileges on some
    platforms.  Failures are caught and logged rather than crashing.
    """
    try:
        for conn in psutil.net_connections():
            if conn.laddr and conn.laddr.port in (src_port, dest_port):
                pid = conn.pid
                if pid is None:
                    continue
                try:
                    return pid, psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    except Exception as exc:
        log.debug("net_connections lookup failed: %s", exc)
    return None, ""


class PacketInfo:
    """
    Extracts and stores all per-packet features needed by the flow tracker.

    Typical usage (matching application.py's call pattern)::

        info = PacketInfo()
        for setter in (info.setDest, info.setSrc, info.setSrcPort, ...):
            setter(raw_packet)
        info.setFwdID()
        info.setBwdID()
    """

    __slots__ = (
        "src",
        "dest",
        "src_port",
        "dest_port",
        "protocol",
        "timestamp",
        "FIN_flag",
        "SYN_flag",
        "RST_flag",
        "PSH_flag",
        "ACK_flag",
        "URG_flag",
        "payload_bytes",
        "header_bytes",
        "packet_size",
        "win_bytes",
        "fwd_id",
        "bwd_id",
        "pid",
        "p_name",
        "_flags",  # cached parsed flag set
        "_ports_resolved",  # guard: resolve process only once
    )

    def __init__(self) -> None:
        self.src: str = ""
        self.dest: str = ""
        self.src_port: int = 0
        self.dest_port: int = 0
        self.protocol: str = ""
        self.timestamp: float = 0.0

        self.FIN_flag: bool = False
        self.SYN_flag: bool = False
        self.RST_flag: bool = False
        self.PSH_flag: bool = False
        self.ACK_flag: bool = False
        self.URG_flag: bool = False

        self.payload_bytes: int = 0
        self.header_bytes: int = 0
        self.packet_size: int = 0
        self.win_bytes: int = 0

        self.fwd_id: str = ""
        self.bwd_id: str = ""

        self.pid: int | None = None
        self.p_name: str = ""

        self._flags: frozenset[str] | None = None
        self._ports_resolved: bool = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_flags(self, p) -> frozenset[str]:
        """Parse TCP flags once and cache the result."""
        if self._flags is None:
            self._flags = _parse_tcp_flags(p)
        return self._flags

    def _maybe_resolve_process(self) -> None:
        """Look up the owning process once both ports are known."""
        if not self._ports_resolved and self.pid is None:
            self._ports_resolved = True
            self.pid, self.p_name = _resolve_process(self.src_port, self.dest_port)

    # ------------------------------------------------------------------
    # Network address setters
    # ------------------------------------------------------------------

    def setSrc(self, p) -> None:
        self.src = p.getlayer(IP).src

    def setDest(self, p) -> None:
        self.dest = p.getlayer(IP).dst

    def setSrcPort(self, p) -> None:
        if p.haslayer(TCP):
            self.src_port = p[TCP].sport
        elif p.haslayer(UDP):
            self.src_port = p[UDP].sport
        self._maybe_resolve_process()

    def setDestPort(self, p) -> None:
        if p.haslayer(TCP):
            self.dest_port = p[TCP].dport
        elif p.haslayer(UDP):
            self.dest_port = p[UDP].dport
        self._maybe_resolve_process()

    def setProtocol(self, p) -> None:
        if p.haslayer(TCP):
            self.protocol = "TCP"
        elif p.haslayer(UDP):
            self.protocol = "UDP"

    def setTimestamp(self, p) -> None:
        self.timestamp = float(p.time)

    # ------------------------------------------------------------------
    # TCP flag setters — all delegate to the single cached parse
    # ------------------------------------------------------------------

    def setPSHFlag(self, p) -> None:
        self.PSH_flag = "PSH" in self._get_flags(p)

    def setFINFlag(self, p) -> None:
        self.FIN_flag = "FIN" in self._get_flags(p)

    def setSYNFlag(self, p) -> None:
        self.SYN_flag = "SYN" in self._get_flags(p)

    def setACKFlag(self, p) -> None:
        self.ACK_flag = "ACK" in self._get_flags(p)

    def setURGFlag(self, p) -> None:
        self.URG_flag = "URG" in self._get_flags(p)

    def setRSTFlag(self, p) -> None:
        self.RST_flag = "RST" in self._get_flags(p)

    # ------------------------------------------------------------------
    # Byte / size setters
    # ------------------------------------------------------------------

    def setPayloadBytes(self, p) -> None:
        if p.haslayer(TCP):
            self.payload_bytes = len(p[TCP].payload)
        elif p.haslayer(UDP):
            self.payload_bytes = len(p[UDP].payload)

    def setHeaderBytes(self, p) -> None:
        if p.haslayer(TCP):
            self.header_bytes = len(p[TCP]) - len(p[TCP].payload)
        elif p.haslayer(UDP):
            self.header_bytes = len(p[UDP]) - len(p[UDP].payload)

    def setPacketSize(self, p) -> None:
        if p.haslayer(TCP):
            self.packet_size = len(p[TCP])
        elif p.haslayer(UDP):
            self.packet_size = len(p[UDP])

    def setWinBytes(self, p) -> None:
        if p.haslayer(TCP):
            self.win_bytes = p[TCP].window

    # ------------------------------------------------------------------
    # Flow ID setters
    # ------------------------------------------------------------------

    def setFwdID(self) -> None:
        self.fwd_id = (
            f"{self.src}-{self.dest}-{self.src_port}-{self.dest_port}-{self.protocol}"
        )

    def setBwdID(self) -> None:
        self.bwd_id = (
            f"{self.dest}-{self.src}-{self.dest_port}-{self.src_port}-{self.protocol}"
        )

    # ------------------------------------------------------------------
    # Getters
    # ------------------------------------------------------------------

    def getSrc(self) -> str:
        return self.src

    def getDest(self) -> str:
        return self.dest

    def getSrcPort(self) -> int:
        return self.src_port

    def getDestPort(self) -> int:
        return self.dest_port

    def getProtocol(self) -> str:
        return self.protocol

    def getTimestamp(self) -> float:
        return self.timestamp

    def getPSHFlag(self) -> bool:
        return self.PSH_flag

    def getFINFlag(self) -> bool:
        return self.FIN_flag

    def getSYNFlag(self) -> bool:
        return self.SYN_flag

    def getACKFlag(self) -> bool:
        return self.ACK_flag

    def getURGFlag(self) -> bool:
        return self.URG_flag

    def getRSTFlag(self) -> bool:
        return self.RST_flag

    def getPayloadBytes(self) -> int:
        return self.payload_bytes

    def getHeaderBytes(self) -> int:
        return self.header_bytes

    def getPacketSize(self) -> int:
        return self.packet_size

    def getWinBytes(self) -> int:
        return self.win_bytes

    def getFwdID(self) -> str:
        return self.fwd_id

    def getBwdID(self) -> str:
        return self.bwd_id

    def getPID(self) -> int | None:
        return self.pid

    def getPName(self) -> str:
        return self.p_name
