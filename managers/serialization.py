"""Serialize complete remote read/modify/write operations on a pooled SSH session."""

from contextlib import nullcontext
from functools import wraps


def serialized_manager(cls):
    """Keep one manager operation atomic, including nested command/SFTP calls.

    The SSH lock is reentrant and shared by managers for the same node. Different
    nodes still run concurrently. Fake transports used by tests need no lock.
    """

    def wrap(method):
        @wraps(method)
        def call(self, *args, **kwargs):
            with vars(self.ssh).get("_exec_lock", nullcontext()):
                return method(self, *args, **kwargs)

        return call

    for name, value in list(vars(cls).items()):
        if (
            not name.startswith("_")
            and callable(value)
            and not isinstance(value, (staticmethod, classmethod))
        ):
            setattr(cls, name, wrap(value))
    return cls
