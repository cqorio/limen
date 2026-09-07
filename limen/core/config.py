"""Per-guard on/off/shadow/enforce configuration, plus optional score-threshold aggregation.

    >>> from limen.core.config import EngineConfig
    >>> from limen.core.types import Action
    >>> cfg = EngineConfig(score_thresholds=((15, Action.CHALLENGE), (5, Action.ALERT)))
    >>> cfg.action_for_score(18).name    # many weak signals summing past 15 → CHALLENGE
    'CHALLENGE'
    >>> cfg.action_for_score(6).name
    'ALERT'
    >>> cfg.action_for_score(2).name     # below every threshold
    'ALLOW'
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .guard import Guard
from .types import Action, Mode


@dataclass
class EngineConfig:
    """Which mode each guard runs in. A guard not named here uses its own ``default_mode``, so the safe
    ones default to ENFORCE and the noisy ones (e.g. sequence-anomaly) default to SHADOW until you opt in.

    ``score_thresholds`` turns the summed ENFORCE-mode scores into an action (the "risk spine"): many weak
    signals can combine to a CHALLENGE that none alone would raise. Give ``(min_score, action)`` pairs; the
    engine picks the most severe action whose ``min_score`` the total meets, and the final action is the max
    of that and any single guard's own action. Empty (the default) = scores are ignored, actions aggregate by
    ``max`` exactly as before.
    """

    modes: dict[str, Mode] = field(default_factory=dict)
    score_thresholds: tuple[tuple[float, Action], ...] = ()

    def mode_for(self, guard: Guard) -> Mode:
        return self.modes.get(guard.name, guard.default_mode)

    def action_for_score(self, total: float) -> Action:
        """The most severe action whose ``min_score`` ``total`` reaches (ALLOW if none / no thresholds set)."""
        best = Action.ALLOW
        for min_score, action in self.score_thresholds:
            if total >= min_score and action > best:
                best = action
        return best

    @classmethod
    def from_dict(cls, raw: dict[str, Mode | str] | None) -> "EngineConfig":
        """Build from ``{guard_name: Mode | "off"|"shadow"|"enforce"}`` (strings accepted for convenience)."""
        modes: dict[str, Mode] = {}
        for name, m in (raw or {}).items():
            modes[name] = m if isinstance(m, Mode) else Mode(str(m).lower())
        return cls(modes=modes)
