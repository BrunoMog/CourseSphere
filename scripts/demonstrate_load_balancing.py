#!/usr/bin/env python3
"""
Demonstration script for CourseSphere Load Balancing & SRE Concurrency.
Tests round-robin distribution across backend replicas through the Nginx Gateway.
"""

import http.client
from urllib.parse import urlparse
import time
import sys

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost/health"
NUM_REQUESTS = int(sys.argv[2]) if len(sys.argv) > 2 else 10


def test_distribution():
    parsed = urlparse(TARGET_URL)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/health"

    print(f"[*] Dispatching {NUM_REQUESTS} requests to {host}:{port}{path}...\n")
    print(f"{'Req #':<8} | {'Status':<8} | {'X-Served-By':<20} | {'X-Upstream-Backend':<22} | {'Latency (ms)':<12}")
    print("-" * 80)

    distribution = {}

    for i in range(1, NUM_REQUESTS + 1):
        start = time.time()
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", path, headers={"User-Agent": "LoadBalancer-Auditor/1.0"})
            response = conn.getresponse()
            response.read()
            latency = (time.time() - start) * 1000
            status = response.status
            served_by = response.getheader("X-Served-By", "unknown")
            upstream = response.getheader("X-Upstream-Backend", "unknown")
            conn.close()

            distribution[served_by] = distribution.get(served_by, 0) + 1
            print(f"{i:<8} | {status:<8} | {served_by:<20} | {upstream:<22} | {latency:<12.2f}")
        except Exception as e:
            print(f"{i:<8} | ERROR    | {str(e):<44} | -")
        time.sleep(0.1)

    print("-" * 80)
    print("\n[+] Distribution Summary:")
    for instance, count in distribution.items():
        percentage = (count / NUM_REQUESTS) * 100
        print(f"  - Instance '{instance}': {count} requests ({percentage:.1f}%)")


if __name__ == "__main__":
    test_distribution()
