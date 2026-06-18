"""
ShieldNet Packet Capture Module
Runs Scapy sniffing in a background daemon thread and feeds each packet
through: feature extraction → ML prediction → callback delivery.

The callback (on_result) is always invoked on the asyncio event loop
so callers can safely do async work (e.g. WebSocket broadcast) inside it.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Callable, Coroutine, Optional

from backend.network.feature_extractor import FeatureExtractor
from backend.ml.predict import predict

logger = logging.getLogger("shieldnet.capture")


class PacketCapture:
    """
    Background Scapy capture thread.

    Parameters
    ----------
    on_result : async callable  (result_dict) -> None
        Called on the asyncio event loop for every processed packet.
        result_dict keys: src_ip, dst_ip, src_port, dst_port, protocol,
        status, attack_type, risk_score, confidence, severity, reason,
        packet_size, flow_duration.
    iface : str | None
        Network interface name.  None = Scapy default (all interfaces).
    """

    def __init__(
        self,
        on_result: Callable[[dict], Coroutine],
        iface: Optional[str] = None,
    ) -> None:
        self._on_result  = on_result
        self._iface      = iface
        self._extractor  = FeatureExtractor()
        self._thread:    Optional[threading.Thread] = None
        self._loop:      Optional[asyncio.AbstractEventLoop] = None
        self._running    = False

    # ── Public API ───────────────────────────────────────────────

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """Start the capture daemon thread.  Pass the running event loop explicitly."""
        if self._running:
            logger.warning("PacketCapture already running — ignoring start()")
            return
        # Prefer explicit loop; fall back to getting the current running loop.
        # Never use the deprecated get_event_loop() without a running loop.
        try:
            self._loop = loop or asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — caller must pass one explicitly for async delivery
            self._loop = loop
        self._running = True
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="shieldnet-capture"
        )
        self._thread.start()
        logger.info("Packet capture started (iface=%s)", self._iface or "default")

    def stop(self) -> None:
        """Signal the capture thread to stop at the next packet."""
        self._running = False
        logger.info("Packet capture stop requested")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Internal ─────────────────────────────────────────────────

    def _run(self) -> None:
        """Entry point for the daemon thread."""
        try:
            from scapy.all import sniff
            sniff(
                prn=self._handle_packet,
                store=False,
                iface=self._iface,
                filter="not port 8000 and not port 3000",
                stop_filter=lambda _: not self._running,
            )
        except Exception as exc:
            logger.error("Scapy sniff error: %s", exc)
        finally:
            self._running = False

    def _handle_packet(self, pkt) -> None:
        """Called by Scapy for every captured packet (runs in capture thread)."""
        try:
            feat = self._extractor.extract(pkt)
            if feat is None:
                return

            # Separate metadata from ML features
            meta     = {k: v for k, v in feat.items() if k.startswith("_")}
            ml_input = {k: v for k, v in feat.items() if not k.startswith("_")}

            result = predict(ml_input)
            result.update(
                src_ip       = meta.get("_src_ip",  "0.0.0.0"),
                dst_ip       = meta.get("_dst_ip",  "0.0.0.0"),
                src_port     = meta.get("_sport",   0),
                dst_port     = meta.get("_dport",   0),
                protocol     = meta.get("_proto",   "UNKNOWN"),
                packet_size  = int(feat.get("Max Packet Length", 0)),
                flow_duration = float(feat.get("Flow Duration", 0)),
            )

            # Schedule the async callback on the event loop from this thread
            if self._loop and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    self._on_result(result), self._loop
                )

        except Exception as exc:
            logger.debug("Packet handling error: %s", exc)
