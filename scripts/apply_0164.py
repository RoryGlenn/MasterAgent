#!/usr/bin/env python3
"""Apply the issue #164 patch from a compressed branch-local payload."""

from __future__ import annotations

import base64
import zlib
from pathlib import Path

payload_root = Path(__file__).resolve().parent / ".apply_0164_payload"
payload = "".join(
    path.read_text(encoding="ascii")
    for path in sorted(payload_root.glob("part*.txt"))
)
source = zlib.decompress(base64.b64decode(payload))
exec(compile(source, __file__, "exec"))
