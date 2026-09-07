from limen import Limen, Mode, RequestContext
from limen.core.types import Action
from limen.adapters import MemoryStore


def test_config_dict_with_string_modes():
    limen = Limen(MemoryStore(), config={"sequence_anomaly": "enforce", "denylist": "off"})
    d = limen.evaluate(RequestContext(method="GET", path="/api/me", account_id="u1", auth_kind="session"))
    assert d.action is Action.ALLOW  # a single request trips nothing


def test_record_feeds_state_and_evaluate_enforces_next():
    limen = Limen(MemoryStore(), config={"enumeration": Mode.ENFORCE})
    ip = "9.9.9.9"
    for _ in range(25):  # default enumeration limit is 20
        limen.record(RequestContext(method="GET", path="/api/reports/x", status=404, ip=ip))
    d = limen.evaluate(RequestContext(method="GET", path="/api/me", ip=ip))
    assert d.blocked and d.action is Action.BLOCK
