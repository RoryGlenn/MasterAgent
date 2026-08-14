"""Master Agent test package."""

from __future__ import annotations

import os

if os.name == "posix":
    os.umask(0o077)
