"""Run the service: python -m app.main [port]"""
from __future__ import annotations

import sys

import uvicorn

from . import config, db

if __name__ == "__main__":
    raw = sys.argv[1] if len(sys.argv) > 1 and str(sys.argv[1]).isdigit() else "8090"
    db.init_db()
    uvicorn.run(
        "app.web:app",
        host="127.0.0.1",
        port=int(raw),
        workers=1,
        log_level="warning",
        access_log=False,
        server_header=False,
        date_header=False,
        timeout_keep_alive=15,
        h11_max_incomplete_event_size=8192,
    )
