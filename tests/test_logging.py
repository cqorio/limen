import io
import logging

import limen


def test_limen_logger_is_silent_by_default():
    """Library-logging rule: a NullHandler is attached and no real (stream) handler is added on import."""
    logger = logging.getLogger("limen")
    assert any(isinstance(h, logging.NullHandler) for h in logger.handlers)
    assert not any(
        isinstance(h, logging.StreamHandler) and not getattr(h, "_limen_dev_handler", False)
        for h in logger.handlers
    )


def test_enable_logging_is_idempotent_and_scoped():
    logger = logging.getLogger("limen")
    before = list(logger.handlers)
    propagate_before = logger.propagate
    try:
        limen.enable_logging(stream=io.StringIO())
        limen.enable_logging(stream=io.StringIO())  # twice
        dev = [h for h in logger.handlers if getattr(h, "_limen_dev_handler", False)]
        assert len(dev) == 1  # not stacked
        assert logger.propagate is False  # scoped to our logger, won't double-log through root
    finally:  # restore global logger state so other tests are unaffected
        for h in list(logger.handlers):
            if getattr(h, "_limen_dev_handler", False):
                logger.removeHandler(h)
        logger.handlers[:] = before
        logger.propagate = propagate_before
