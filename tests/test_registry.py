import pathlib

import pytest

from limen import REGISTRY, Guard, Mode, Registry


def test_core_guards_are_registered_with_unique_names():
    names = REGISTRY.names()
    assert len(names) == len(set(names)), "guard names must be unique"
    for expected in ("enumeration", "account_budget", "sequence_anomaly"):
        assert expected in names


def test_every_registered_guard_has_a_test_file():
    """A guard cannot ship untested: each registered name needs tests/guards/test_<name>.py."""
    guards_tests = pathlib.Path(__file__).parent / "guards"
    for name in REGISTRY.names():
        assert (guards_tests / f"test_{name}.py").exists(), \
            f"guard {name!r} is missing tests/guards/test_{name}.py"


def test_duplicate_name_is_rejected():
    class Dup(Guard):
        name = "dup"
        default_mode = Mode.OFF

        def evaluate(self, ctx, store):
            return None

    reg = Registry()
    reg.register(Dup())
    with pytest.raises(ValueError):
        reg.register(Dup())


def test_nameless_guard_is_rejected():
    class Nameless(Guard):
        def evaluate(self, ctx, store):
            return None

    with pytest.raises(ValueError):
        Registry().register(Nameless())
