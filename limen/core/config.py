"""Per-guard on/off/shadow/enforce configuration."""
from __future__ import annotations

from dataclasses import dataclass, field

from .guard import Guard
from .types import Mode


@dataclass
class EngineConfig:
    """Which mode each guard runs in. A guard not named here uses its own ``default_mode``, so the safe
    ones default to ENFORCE and the noisy ones (e.g. sequence-anomaly) default to SHADOW until you opt in."""

    modes: dict[str, Mode] = field(default_factory=dict)

    def mode_for(self, guard: Guard) -> Mode:
        return self.modes.get(guard.name, guard.default_mode)

    @classmethod
    def from_dict(cls, raw: dict[str, Mode | str] | None) -> "EngineConfig":
        """Build from ``{guard_name: Mode | "off"|"shadow"|"enforce"}`` (strings accepted for convenience)."""
        modes: dict[str, Mode] = {}
        for name, m in (raw or {}).items():
            modes[name] = m if isinstance(m, Mode) else Mode(str(m).lower())
        return cls(modes=modes)
