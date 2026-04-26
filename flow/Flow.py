"""
Flow.py — Network flow tracker.

Accumulates per-packet statistics incrementally, then computes aggregate
features when the flow is terminated.  All timing values are stored in
microseconds (µs) to match CICFlowMeter conventions.
"""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any

from flow.FlowFeature import FlowFeatures

# A flow is considered "idle" if the gap between consecutive packets
# exceeds this threshold (seconds).
IDLE_THRESHOLD: float = 5.0

# Conversion factor: seconds → microseconds
_US = 1_000_000


class Flow:
    """
    Represents a single bidirectional network flow.

    A flow is identified by its (src_ip, src_port, dst_ip, dst_port, proto)
    5-tuple.  The first packet always belongs to the forward direction; any
    packet arriving on the reverse 5-tuple is classified as backward.

    Usage::

        flow = Flow(first_packet)
        for pkt in subsequent_packets:
            flow.new(pkt, direction)   # direction: "fwd" | "bwd"
        features = flow.terminated()
    """

    __slots__ = (
        "features",
        "_all_packets",
        "_fwd_packets",
        "_bwd_packets",
        "_flow_iat",
        "_fwd_iat",
        "_bwd_iat",
        "_flow_active",
        "_flow_idle",
        "_flow_last_seen",
        "_flow_start_time",
        "_fwd_last_seen",
        "_bwd_last_seen",
        "_start_active_time",
        "_end_active_time",
        "_pkt_count",
        "_fwd_count",
        "_bwd_count",
    )

    def __init__(self, packet) -> None:
        ts = packet.getTimestamp()

        # --- FlowFeatures object ---
        self.features = FlowFeatures()
        f = self.features  # local alias for brevity

        f.setDestPort(packet.getDestPort())
        f.setSrc(packet.getSrc())
        f.setDest(packet.getDest())
        f.setSrcPort(packet.getSrcPort())
        f.setProtocol(packet.getProtocol())
        f.setPID(packet.getPID())
        f.setPName(packet.getPName())

        # Flag initialisation — forward direction only for first packet
        # NOTE: original code used getURGFlag() for FwdPSHFlags; preserved.
        f.setFwdPSHFlags(1 if packet.getURGFlag() else 0)
        f.setFINFlagCount(1 if packet.getFINFlag() else 0)
        f.setSYNFlagCount(1 if packet.getSYNFlag() else 0)
        f.setPSHFlagCount(1 if packet.getPSHFlag() else 0)
        f.setACKFlagCount(1 if packet.getACKFlag() else 0)
        f.setURGFlagCount(1 if packet.getURGFlag() else 0)

        payload = packet.getPayloadBytes()
        f.setMaxPacketLen(payload)
        f.setPacketLenMean(payload)
        f.setAvgPacketSize(packet.getPacketSize())
        f.setInitBytesFwd(packet.getWinBytes())

        # --- Timing state ---
        self._flow_start_time: float = ts
        self._flow_last_seen: float = ts
        self._fwd_last_seen: float = ts
        self._bwd_last_seen: float = 0.0
        self._start_active_time: float = ts
        self._end_active_time: float = ts

        # --- Packet lists (used for aggregate stats at termination) ---
        self._all_packets = [packet]
        self._fwd_packets = [packet]
        self._bwd_packets: list = []

        # --- Inter-arrival time accumulators (µs) ---
        self._flow_iat: list[float] = []
        self._fwd_iat: list[float] = []
        self._bwd_iat: list[float] = []

        # --- Active/idle period accumulators (seconds) ---
        self._flow_active: list[float] = []
        self._flow_idle: list[float] = []

        # --- Counters ---
        self._pkt_count: int = 1
        self._fwd_count: int = 1
        self._bwd_count: int = 0

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def getFlowLastSeen(self) -> float:
        return self._flow_last_seen

    def getFlowStartTime(self) -> float:
        return self._flow_start_time

    # ------------------------------------------------------------------
    # Incremental update
    # ------------------------------------------------------------------

    def new(self, packet, direction: str) -> None:
        """
        Incorporate a new packet into the flow.

        Parameters
        ----------
        packet:    PacketInfo instance
        direction: "fwd" (same direction as initiator) or "bwd" (reverse)
        """
        ts = packet.getTimestamp()
        payload = packet.getPayloadBytes()
        f = self.features

        # ---- Direction-specific bookkeeping ----
        if direction == "bwd":
            self._bwd_packets.append(packet)
            if self._bwd_count == 0:
                # First backward packet — initialise bwd-only features
                f.setBwdPacketLenMax(payload)
                f.setBwdPacketLenMin(payload)
                f.setInitWinBytesBwd(packet.getWinBytes())
            else:
                f.setBwdPacketLenMax(max(f.bwd_packet_len_max, payload))
                f.setBwdPacketLenMin(min(f.bwd_packet_len_min, payload))
                self._bwd_iat.append((ts - self._bwd_last_seen) * _US)
            self._bwd_count += 1
            self._bwd_last_seen = ts

        else:  # "fwd"
            self._fwd_packets.append(packet)
            self._fwd_iat.append((ts - self._fwd_last_seen) * _US)
            # FwdPSHFlags = max(current, new) — stays 1 once set
            if packet.getURGFlag():
                f.setFwdPSHFlags(1)
            self._fwd_count += 1
            self._fwd_last_seen = ts

        # ---- Shared per-packet updates ----
        f.setMaxPacketLen(max(f.getMaxPacketLen(), payload))

        # Flag counts: set to 1 if seen at least once (idempotent)
        if packet.getFINFlag():
            f.setFINFlagCount(1)
        if packet.getSYNFlag():
            f.setSYNFlagCount(1)
        if packet.getPSHFlag():
            f.setPSHFlagCount(1)
        if packet.getACKFlag():
            f.setACKFlagCount(1)
        if packet.getURGFlag():
            f.setURGFlagCount(1)

        # ---- Active / idle period tracking ----
        gap = ts - self._end_active_time
        if gap > IDLE_THRESHOLD:
            active_duration = self._end_active_time - self._start_active_time
            if active_duration > 0:
                self._flow_active.append(active_duration)
            self._flow_idle.append(gap)
            self._start_active_time = ts
            self._end_active_time = ts
        else:
            self._end_active_time = ts

        # ---- Flow-level IAT ----
        self._flow_iat.append((ts - self._flow_last_seen) * _US)
        self._flow_last_seen = ts

        self._all_packets.append(packet)
        self._pkt_count += 1

    # ------------------------------------------------------------------
    # Termination — compute aggregate features and return feature vector
    # ------------------------------------------------------------------

    def terminated(self) -> list[Any]:
        """
        Finalise the flow and return a flat feature vector.

        The first 39 elements are numeric ML features (matching AE_FEATURES
        order); elements 40+ are metadata strings / timestamps.
        """
        f = self.features
        duration = (self._flow_last_seen - self._flow_start_time) * _US
        f.setFlowDuration(duration)

        # ---- Backward packet length stats ----
        bwd_payloads = [p.getPayloadBytes() for p in self._bwd_packets]
        if bwd_payloads:
            f.setBwdPacketLenMean(statistics.mean(bwd_payloads))
            if len(bwd_payloads) > 1:
                f.setBwdPacketLenStd(statistics.stdev(bwd_payloads))

        # ---- Flow IAT stats ----
        _set_iat_stats(
            f.setFlowIATMean,
            f.setFlowIATStd,
            f.setFlowIATMax,
            f.setFlowIATMin,
            f.setFwdIATTotal,  # unused param — handled separately
            self._flow_iat,
            total=False,
        )

        # ---- Forward IAT stats ----
        if self._fwd_iat:
            f.setFwdIATTotal(sum(self._fwd_iat))
            f.setFwdIATMean(statistics.mean(self._fwd_iat))
            f.setFwdIATMax(max(self._fwd_iat))
            f.setFwdIATMin(min(self._fwd_iat))
            if len(self._fwd_iat) > 1:
                f.setFwdIATStd(statistics.stdev(self._fwd_iat))

        # ---- Backward IAT stats ----
        if self._bwd_iat:
            f.setBwdIATTotal(sum(self._bwd_iat))
            f.setBwdIATMean(statistics.mean(self._bwd_iat))
            f.setBwdIATMax(max(self._bwd_iat))
            f.setBwdIATMin(min(self._bwd_iat))
            if len(self._bwd_iat) > 1:
                f.setBwdIATStd(statistics.stdev(self._bwd_iat))

        # ---- Packets-per-second (forward) ----
        duration_s = duration / _US
        f.setFwdPackets_s(0.0 if duration_s == 0 else self._fwd_count / duration_s)

        # ---- All-packet length stats ----
        all_payloads = [p.getPayloadBytes() for p in self._all_packets]
        if all_payloads:
            f.setPacketLenMean(statistics.mean(all_payloads))
            if len(all_payloads) > 1:
                f.setPacketLenStd(statistics.stdev(all_payloads))
                f.setPacketLenVar(statistics.variance(all_payloads))

        # ---- Packet size averages ----
        all_sizes = [p.getPacketSize() for p in self._all_packets]
        f.setAvgPacketSize(sum(all_sizes) / self._pkt_count)

        if self._bwd_count and bwd_payloads:
            f.setAvgBwdSegmentSize(sum(bwd_payloads) / self._bwd_count)

        # ---- Active / idle stats ----
        if self._flow_active:
            f.setActiveMin(min(self._flow_active))

        if self._flow_idle:
            f.setIdleMean(statistics.mean(self._flow_idle))
            f.setIdleMax(max(self._flow_idle))
            f.setIdleMin(min(self._flow_idle))
            if len(self._flow_idle) > 1:
                f.setIdleStd(statistics.stdev(self._flow_idle))

        # ------------------------------------------------------------------
        # Return flat feature vector
        # ------------------------------------------------------------------
        return [
            # ---- Numeric ML features (indices 0–38) ----
            f.getFlowDuration(),
            f.getBwdPacketLenMax(),
            f.getBwdPacketLenMin(),
            f.getBwdPacketLenMean(),
            f.getBwdPacketLenStd(),
            f.getFlowIATMean(),
            f.getFlowIATStd(),
            f.getFlowIATMax(),
            f.getFlowIATMin(),
            f.getFwdIATTotal(),
            f.getFwdIATMean(),
            f.getFwdIATStd(),
            f.getFwdIATMax(),
            f.getFwdIATMin(),
            f.getBwdIATTotal(),
            f.getBwdIATMean(),
            f.getBwdIATStd(),
            f.getBwdIATMax(),
            f.getBwdIATMin(),
            f.getFwdPSHFlags(),
            f.getFwdPackets_s(),
            f.getMaxPacketLen(),
            f.getPacketLenMean(),
            f.getPacketLenStd(),
            f.getPacketLenVar(),
            f.getFINFlagCount(),
            f.getSYNFlagCount(),
            f.getPSHFlagCount(),
            f.getACKFlagCount(),
            f.getURGFlagCount(),
            f.getAvgPacketSize(),
            f.getAvgBwdSegmentSize(),
            f.getInitWinBytesFwd(),
            f.getInitWinBytesBwd(),
            f.getActiveMin(),
            f.getIdleMean(),
            f.getIdleStd(),
            f.getIdleMax(),
            f.getIdleMin(),
            # ---- Metadata (indices 39–47) ----
            f.getSrc(),
            f.getSrcPort(),
            f.getDest(),
            f.getDestPort(),
            f.getProtocol(),
            datetime.fromtimestamp(self._flow_start_time),
            datetime.fromtimestamp(self._flow_last_seen),
            f.getPName(),
            f.getPID(),
        ]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _set_iat_stats(
    set_mean,
    set_std,
    set_max,
    set_min,
    _unused_total,
    values: list[float],
    total: bool = True,
) -> None:
    """Set mean/std/max/min on a FlowFeatures object from a list of IAT values."""
    if not values:
        return
    set_mean(statistics.mean(values))
    set_max(max(values))
    set_min(min(values))
    if len(values) > 1:
        set_std(statistics.stdev(values))
