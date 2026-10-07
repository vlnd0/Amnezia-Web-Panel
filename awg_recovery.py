"""Panel-owned AWG state, independent of the disposable VPN node."""

import base64
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


PROTOCOL_RE = re.compile(r'^(awg|awg2|awg3|awg_legacy)(__[2-9][0-9]*|__1[0-9]+)?$')
ROOT = '/opt/amnezia/awg/'
ALLOWED_FILES = {
    ROOT + name for name in (
        'awg0.conf', 'wg0.conf', 'clientsTable', 'wireguard_server_private_key.key',
        'wireguard_server_public_key.key', 'wireguard_psk.key', 'bwlimits',
        'exit/exit0.conf', 'exit/exit_private.key',
    )
} | {'/opt/amnezia/start.sh'}
MAX_STATE_BYTES = 32 * 1024 * 1024


class AwgRecoveryError(RuntimeError):
    """Messages intentionally exclude configuration and secret values."""


def config_values(config, section='Interface'):
    values = {}
    active = None
    for raw in config.splitlines():
        line = raw.strip()
        if line.startswith('[') and line.endswith(']'):
            active = line[1:-1]
        elif active == section and '=' in line and not line.startswith(('#', ';')):
            key, value = line.split('=', 1)
            values.setdefault(key.strip(), []).append(value.strip())
    return values


def public_key(private_key):
    try:
        raw = base64.b64decode(private_key, validate=True)
        key = X25519PrivateKey.from_private_bytes(raw)
        return base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )).decode('ascii')
    except (ValueError, TypeError) as exc:
        raise AwgRecoveryError('Invalid server private key in recovery state') from exc


def validate_state(state, protocol=None):
    if not isinstance(state, dict) or state.get('version') != 1:
        raise AwgRecoveryError('Unsupported AWG recovery state')
    proto = state.get('protocol', '')
    if not PROTOCOL_RE.fullmatch(proto) or (protocol and proto != protocol):
        raise AwgRecoveryError('Recovery state belongs to another protocol instance')
    files = state.get('files')
    if not isinstance(files, dict) or not set(files).issubset(ALLOWED_FILES):
        raise AwgRecoveryError('Invalid recovery file paths')
    if any(not isinstance(v, str) for v in files.values()):
        raise AwgRecoveryError('Invalid recovery file content')
    if len(json.dumps(state).encode()) > MAX_STATE_BYTES:
        raise AwgRecoveryError('AWG recovery state is too large')
    path = state.get('config_path')
    if path not in (ROOT + 'awg0.conf', ROOT + 'wg0.conf') or path not in files:
        raise AwgRecoveryError('Server configuration is missing from recovery state')
    values = config_values(files[path])
    if len(values.get('PrivateKey', [])) != 1:
        raise AwgRecoveryError('Recovery state needs exactly one server private key')
    derived = public_key(values['PrivateKey'][0])
    if derived != state.get('server_public_key'):
        raise AwgRecoveryError('Server key identity does not match recovery state')
    for filename, expected in (
        ('wireguard_server_private_key.key', values['PrivateKey'][0]),
        ('wireguard_server_public_key.key', derived),
    ):
        if files.get(ROOT + filename, '').strip() != expected:
            raise AwgRecoveryError('Recovery key files do not match server configuration')
    try:
        listen = values['ListenPort']
        if len(listen) != 1 or not 1 <= int(listen[0]) <= 65535:
            raise ValueError()
        if int(state.get('listen_port', 0)) != int(listen[0]):
            raise ValueError()
        addresses = values['Address']
        for value in addresses:
            for address in value.split(','):
                ipaddress.ip_interface(address.strip())
        clients = json.loads(files[ROOT + 'clientsTable'])
        if not isinstance(clients, list) or any(not isinstance(c, dict) for c in clients):
            raise ValueError()
        psk = base64.b64decode(files[ROOT + 'wireguard_psk.key'].strip(), validate=True)
        if len(psk) != 32:
            raise ValueError()
    except (ValueError, TypeError, KeyError) as exc:
        raise AwgRecoveryError('Incomplete AWG addresses, clients, port or PSK') from exc
    if not files.get('/opt/amnezia/start.sh', '').startswith('#!'):
        raise AwgRecoveryError('AWG startup script is missing')
    bindings = state.get('port_bindings')
    if not isinstance(bindings, dict) or not bindings:
        raise AwgRecoveryError('Published UDP ports are missing')
    try:
        for container_port, hosts in bindings.items():
            if not re.fullmatch(r'[0-9]+/udp', container_port):
                raise ValueError()
            if not 1 <= int(container_port.split('/')[0]) <= 65535 or not hosts:
                raise ValueError()
            for host in hosts:
                if not 1 <= int(host['HostPort']) <= 65535:
                    raise ValueError()
                if host.get('HostIp'):
                    ipaddress.ip_address(host['HostIp'])
    except (ValueError, TypeError, KeyError) as exc:
        raise AwgRecoveryError('Invalid published UDP ports') from exc
    return state


def state_summary(state):
    if state is None:
        return {'available': False}
    return {
        'available': not state.get('_sync_pending', False),
        'sync_pending': state.get('_sync_pending', False),
        'captured_at': state['captured_at'],
        'clients_count': len(json.loads(state['files'][ROOT + 'clientsTable'])),
        'identity_fingerprint': hashlib.sha256(state['server_public_key'].encode()).hexdigest()[:16],
    }


class AwgRecoveryStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()

    @contextmanager
    def _connect(self):
        directory = os.path.dirname(self.path)
        os.makedirs(directory, exist_ok=True)
        # Keep the state DB in its own private directory on the panel volume.
        os.chmod(directory, 0o700)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        db = sqlite3.connect(self.path, timeout=30)
        db.execute('CREATE TABLE IF NOT EXISTS awg_state ('
                   'server_uid TEXT NOT NULL, protocol TEXT NOT NULL, state TEXT NOT NULL, '
                   'dirty INTEGER NOT NULL DEFAULT 0, '
                   'PRIMARY KEY (server_uid, protocol))')
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, server_uid, state):
        validate_state(state)
        if not server_uid:
            raise AwgRecoveryError('Server identity is missing')
        state = dict(state, captured_at=datetime.now(timezone.utc).isoformat())
        with self._lock, self._connect() as db:
            previous = db.execute('SELECT state FROM awg_state WHERE server_uid=? AND protocol=?',
                                  (server_uid, state['protocol'])).fetchone()
            if previous and json.loads(previous[0]).get('server_public_key') != state['server_public_key']:
                raise AwgRecoveryError('Node server identity changed; saved identity was retained for recovery')
            db.execute('INSERT INTO awg_state (server_uid, protocol, state, dirty) VALUES (?, ?, ?, 0) '
                       'ON CONFLICT(server_uid, protocol) DO UPDATE SET state=excluded.state, dirty=0',
                       (server_uid, state['protocol'], json.dumps(state)))
        return state_summary(state)

    def load(self, server_uid, protocol, allow_pending=False):
        if not os.path.exists(self.path):
            return None
        with self._lock, self._connect() as db:
            row = db.execute('SELECT state, dirty FROM awg_state WHERE server_uid=? AND protocol=?',
                             (server_uid, protocol)).fetchone()
        if row is None:
            return None
        try:
            state = validate_state(json.loads(row[0]), protocol)
        except (ValueError, TypeError) as exc:
            raise AwgRecoveryError('Stored AWG recovery state is unreadable') from exc
        if row[1]:
            if not allow_pending:
                raise AwgRecoveryError('AWG state has unsynchronized changes; synchronize before recovery')
            state['_sync_pending'] = True
        return state

    def mark_pending(self, server_uid, protocol):
        with self._lock, self._connect() as db:
            db.execute('UPDATE awg_state SET dirty=1 WHERE server_uid=? AND protocol=?',
                       (server_uid, protocol))

    def protocols(self, server_uid):
        if not os.path.exists(self.path):
            return []
        with self._lock, self._connect() as db:
            return [row[0] for row in db.execute(
                'SELECT protocol FROM awg_state WHERE server_uid=? ORDER BY protocol',
                (server_uid,))]
