"""
OneInfinity Mobile Correlation Engine
====================================
Correlates UI interactions, Frida instrumentation events, and network traffic
into a semantic "Execution Chain" for deep analysis.
"""

import time
import logging
from typing import Dict, List, Optional, Any
from collections import deque

log = logging.getLogger("oneinfinity.mobile.correlation")

# Event Buffer - stores recent events for correlation (sliding window)
# device_id -> deque of events
event_buffer: Dict[str, deque] = {}
MAX_BUFFER_SIZE = 1000
CORRELATION_WINDOW_SEC = 5.0

class CorrelationEvent:
    def __init__(self, type: str, data: dict, timestamp: float = None):
        self.type = type # "ui", "frida", "network"
        self.data = data
        self.timestamp = timestamp or time.time()

def ingest_event(device_id: str, event_type: str, data: dict):
    """Buffer a new event for correlation."""
    if device_id not in event_buffer:
        event_buffer[device_id] = deque(maxlen=MAX_BUFFER_SIZE)
    
    event = CorrelationEvent(event_type, data)
    event_buffer[device_id].append(event)
    
    # If it's a network event, trigger correlation immediately
    if event_type == "network":
        correlate_for_network_event(device_id, event)

def correlate_for_network_event(device_id: str, network_event: CorrelationEvent):
    """Find preceding UI and Frida events for this network request."""
    window_start = network_event.timestamp - CORRELATION_WINDOW_SEC
    buffer = event_buffer.get(device_id, [])
    
    chain = {
        "network": network_event.data,
        "preceding_ui": [],
        "preceding_frida": []
    }
    
    for event in reversed(buffer):
        if event == network_event: continue
        if event.timestamp < window_start: break
        
        if event.type == "ui":
            chain["preceding_ui"].append(event.data)
        elif event.type == "frida":
            chain["preceding_frida"].append(event.data)
            
    # Attach chain to the network event data so it's persisted/returned
    network_event.data["correlation_chain"] = chain

async def get_correlation_chain(device_id: str, traffic_id: str) -> Optional[dict]:
    """Retrieve the correlation chain for a specific traffic entry."""
    # This would normally query the database where traffic is stored.
    # For now, we'll return what we have in the buffer if still there.
    buffer = event_buffer.get(device_id, [])
    for event in buffer:
        if event.type == "network" and event.data.get("id") == traffic_id:
            return event.data.get("correlation_chain")
    return None
