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
                # Status snapshots may be stale when a native client or another
                # process changes the node. Mutations always read current state.
                if method.__name__ in {
                    'add_client', 'edit_client', 'toggle_client', 'remove_client',
                    'rename_client', 'set_speed_limit', 'update_awg_settings',
                    'save_client_config', 'save_server_config', 'install_protocol',
                    'remove_container', 'restore_recovery_state',
                }:
                    if '_awg_batch' in vars(self.ssh):
                        self.ssh._awg_batch = None
                    cache = vars(self).get('_server_config_cache')
                    if cache is not None:
                        cache.clear()
                if method.__name__ in {'install_protocol', 'remove_container', 'restore_recovery_state'}:
                    if '_docker_ps_cache' in vars(self.ssh):
                        self.ssh._docker_ps_cache = None
                depth = vars(self).get('_operation_depth', 0)
                before = getattr(type(self), '_recovery_before_operation', None)
                if before and depth == 0:
                    before(self, method.__name__, args, kwargs)
                self._operation_depth = depth + 1
                try:
                    result = method(self, *args, **kwargs)
                finally:
                    self._operation_depth = depth
                hook = getattr(type(self), '_recovery_after_operation', None)
                if hook and depth == 0:
                    hook(self, method.__name__, args, kwargs, result)
                return result

        return call

    for name, value in list(vars(cls).items()):
        if (
            not name.startswith("_")
            and callable(value)
            and not isinstance(value, (staticmethod, classmethod))
        ):
            setattr(cls, name, wrap(value))
    return cls
