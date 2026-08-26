#!/usr/bin/env python3
"""Bounded durable reconciliation loop for team approvals; exposes no listener."""
import signal
import threading

from tools import RECONCILE_INTERVAL_SECONDS, _reconcile_once

stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
signal.signal(signal.SIGINT, lambda *_: stop.set())

while not stop.is_set():
    _reconcile_once()
    stop.wait(RECONCILE_INTERVAL_SECONDS)
