"""File-based kill switch.

Fail-closed: if the switch file EXISTS the agent must stop (deny everything).
If the file's state cannot be determined (OSError), treat the switch as ACTIVE.
"""
from __future__ import annotations

import os
from typing import Optional


class KillSwitch:
    def __init__(self, path: str):
        self.path = path

    def is_active(self) -> bool:
        """True => agent must halt / deny. Fail-closed on any FS error."""
        try:
            os.stat(self.path)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            return True  # cannot determine state => assume active (fail-closed)

    @staticmethod
    def any_active(paths: Optional[list]) -> bool:
        if not paths:
            return False
        return any(KillSwitch(p).is_active() for p in paths)
