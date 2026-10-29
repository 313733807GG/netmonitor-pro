"""Bounded local diagnostics. No API secrets or subscription content is logged."""
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import unicodedata

LOG = logging.getLogger("netmonitor")


def setup_logging():
    if LOG.handlers:
        return
    directory = Path(os.environ.get("NETMONITOR_LOG_DIR") or
                     Path(os.environ.get("LOCALAPPDATA", ".")) / "NetMonitorPro" / "logs")
    try:
        directory.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(directory / "diagnostic.log", maxBytes=2*1024*1024,
                                      backupCount=3, encoding="utf-8", errors="backslashreplace")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        LOG.addHandler(handler)
        LOG.setLevel(logging.INFO)
        LOG.info("NetMonitor v22 starting python=%s", sys.version.split()[0])
    except OSError:
        LOG.addHandler(logging.NullHandler())


def display_text(value):
    """Render remote/user strings literally; remove controls, not Chinese/emoji."""
    text = str(value or "")
    clean = "".join(ch if ch in "\n\t" or unicodedata.category(ch) not in ("Cc", "Cs")
                    else "\ufffd" for ch in text)
    # Direction overrides can make domains/paths appear to have a different name.
    clean = "".join(ch for ch in clean if ch not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
    if clean != text or "\ufffd" in text:
        # Escaped samples only; bound both volume and fields, never dump config.
        key = hash(text)
        if key not in _reported:
            if len(_reported) >= 128:
                _reported.clear()
            _reported.add(key)
            LOG.warning("display text anomaly sample=%s", ascii(text[:160]))
    return clean


_reported = set()
