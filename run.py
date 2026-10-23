#!/usr/bin/env python3
"""
Entry point: `python run.py` starts the ByteENDE web panel + API.

Cross-platform (Linux / macOS / Windows) - uses only the standard library
and os.environ, no OS-specific paths. See run.sh / run.bat for convenience
launchers that also set up a virtual environment.

Which address ByteENDE listens on, in order of priority:
  1. The BYTEENDE_HOST environment variable, if set.
  2. The "Listen address" saved on the Network page (data/network.json).
  3. 127.0.0.1 (localhost only), if neither of the above is set.

The socket can only be (re)bound at process start, so a change made on the
Network page while ByteENDE is already running takes effect on the next
restart - the Network page says so.

Env vars:
  BYTEENDE_HOST          overrides the saved listen address (0.0.0.0 exposes it on the network)
  BYTEENDE_PORT          default 8800
  BYTEENDE_FORCE_HTTPS   set to 1 if served behind a TLS-terminating proxy,
                         so the session cookie gets the Secure flag
"""
import os

from web.app import app
from web import network_acl

if __name__ == '__main__':
    host = os.environ.get('BYTEENDE_HOST') or network_acl.get_settings().get('bind_host', '127.0.0.1')
    port = int(os.environ.get('BYTEENDE_PORT', '8800'))
    app.run(host=host, port=port, debug=False)
