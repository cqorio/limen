from limen.adapters.memory_store import MemoryStore


def test_basic_counter_and_kv():
    s = MemoryStore()
    assert s.incr("a", 60) == 1
    assert s.incr("a", 60) == 2
    assert s.get("a") == 2
    s.set_str("k", "v", 60)
    assert s.get_str("k") == "v"


def test_expired_keys_are_purged_so_growth_is_bounded():
    """Fan out over many distinct short-lived keys; the periodic sweep must keep live keys bounded (the
    guard against an authenticated attacker exhausting memory via attacker-influenced keys)."""
    s = MemoryStore()
    for i in range(MemoryStore._PURGE_EVERY + 5):
        s.incr(f"k{i}", 0)  # window 0 → each key is already expired the moment after it is written
    # after the sweep fires (every _PURGE_EVERY ops), essentially nothing live should remain
    assert len(s._counters) < 50
