"""Write your own guard in a few lines and plug it in. Run: python examples/custom_guard.py"""
from limen import REGISTRY, Action, Guard, Limen, Mode, RequestContext, Signal, register
from limen.adapters import MemoryStore


@register
class NoReferer(Guard):
    """Toy guard: a request that claims to be a browser session but carries no Referer is suspicious."""

    name = "no_referer"
    default_mode = Mode.ENFORCE

    def evaluate(self, ctx, store):
        if ctx.auth_kind == "session" and not ctx.referer:
            return Signal(Action.CHALLENGE, self.name, "session request with no referer")
        return None


limen = Limen(MemoryStore())
d = limen.evaluate(RequestContext(method="GET", path="/api/me", auth_kind="session", referer=None))
print("no-referer session ->", d.action.name, d.reasons)
print("registered guards  ->", REGISTRY.names())

assert d.action is Action.CHALLENGE
