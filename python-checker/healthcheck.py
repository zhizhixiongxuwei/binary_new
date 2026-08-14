"""BinaryScan Python checker healthcheck (stdlib only)."""

import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"

try:
    with urllib.request.urlopen(BASE + "/healthz", timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
        if response.status == 200 and payload.get("status") == "ok":
            sys.exit(0)
        sys.exit(1)
except Exception:
    sys.exit(1)
