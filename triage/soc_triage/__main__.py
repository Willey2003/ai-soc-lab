"""Entry point.

    python -m soc_triage                 # run the service (API + alerts.json tailer)
    python -m soc_triage replay FILE     # triage a JSONL file of Wazuh alerts and print results
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading

from .app import Service, create_app
from .config import Settings


def main(argv: list[str]) -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = Settings()
    service = Service(settings)

    if len(argv) >= 2 and argv[0] == "replay":
        with open(argv[1], encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    result = service.process(json.loads(line), force=True)
                    print(json.dumps(result, indent=2))
        return 0

    if settings.tail_enabled:
        threading.Thread(target=service.run_tailer, name="tailer", daemon=True).start()

    from waitress import serve

    logging.getLogger(__name__).info("API on %s:%d", settings.bind_host, settings.bind_port)
    serve(create_app(service), host=settings.bind_host, port=settings.bind_port, threads=4)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
