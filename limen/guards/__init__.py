"""The bundled guards. Importing this package registers each one into the default REGISTRY (via @register).

Add a guard: drop a module here, subclass ``Guard`` + ``@register``, import it below, and add its test at
``tests/guards/test_<name>.py`` (the registry-integrity test requires the test file to exist).
"""
from . import (  # noqa: F401
    denylist,
    enumeration,
    honeytoken,
    impossible_travel,
    rate_limit,
    sec_fetch,
    sequence_anomaly,
    step_up,
    timing,
    watermark,
)
