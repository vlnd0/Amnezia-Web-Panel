"""Unit tests for AWG tunnel on-link widening (return-path fix on legacy /24
nodes). Uses a fake SSH transport — no live server needed.

Run:
    python3 -m pytest tests/test_awg_onlink.py -v
    # or, without pytest installed:
    python3 tests/test_awg_onlink.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from managers.awg_manager import AWGManager

PROTO = 'awg2'
CONFIG_PATH = '/opt/amnezia/awg/awg0.conf'


def _config(prefix):
    return (
        "[Interface]\n"
        "PrivateKey = SERVERPRIVKEY\n"
        f"Address = 10.8.1.1/{prefix}\n"
        "ListenPort = 433\n"
        "Jc = 9\n"
        "\n"
        "[Peer]\n"
        "PublicKey = CLIENTPUBKEY\n"
        "AllowedIPs = 10.8.0.12/32\n"
    )


class FakeSSH:
    """Records commands, serves a canned server config, and simulates that the
    widened address is present on the interface after an `ip addr add`."""

    def __init__(self, config_text):
        self.config_text = config_text
        self.commands = []
        self.uploads = {}
        # `ip -o -4 addr show` output AFTER the add: the /16 is present.
        self.addr_show = "7: awg0    inet 10.8.1.1/16 brd 10.8.255.255 scope global awg0"

    def run_sudo_command(self, command, timeout=60):
        self.commands.append(command)
        if 'for p in' in command:                 # _resolve_config_path
            return CONFIG_PATH, '', 0
        if ' cat ' in command:                    # _get_server_config
            return self.config_text, '', 0
        if 'ip -o -4 addr show' in command:
            return self.addr_show, '', 0
        return '', '', 0

    def run_command(self, command, timeout=60):
        self.commands.append(command)
        return '', '', 0

    def upload_file(self, content, remote_path):
        self.uploads[remote_path] = content

    def _has(self, needle):
        return any(needle in c for c in self.commands)


def test_widen_24_to_16_persists_and_applies_live():
    ssh = FakeSSH(_config(24))
    mgr = AWGManager(ssh)

    res = mgr.heal_tunnel_onlink(PROTO, apply=True)

    assert res == {'status': 'widened', 'ip': '10.8.1.1', 'from': 24, 'to': 16}, res

    # (a) persisted: the rewritten config flips /24 -> /16
    pushed = ssh.uploads.get('/tmp/_amnz_onlink.conf')
    assert pushed is not None, "config was not rewritten"
    assert 'Address = 10.8.1.1/16' in pushed
    assert '10.8.1.1/24' not in pushed
    assert ssh._has(f'docker cp /tmp/_amnz_onlink.conf amnezia-awg2:{CONFIG_PATH}')

    # (b) applied live: add-before-del, narrow address dropped only after confirm
    assert ssh._has('ip addr add 10.8.1.1/16 dev awg0')
    assert ssh._has('ip addr del 10.8.1.1/24 dev awg0')
    add_idx = next(i for i, c in enumerate(ssh.commands) if 'ip addr add 10.8.1.1/16' in c)
    del_idx = next(i for i, c in enumerate(ssh.commands) if 'ip addr del 10.8.1.1/24' in c)
    assert add_idx < del_idx, "must add the wide address before deleting the narrow one"


def test_noop_when_already_16():
    ssh = FakeSSH(_config(16))
    mgr = AWGManager(ssh)

    res = mgr.heal_tunnel_onlink(PROTO, apply=True)

    assert res['status'] == 'noop', res
    assert ssh.uploads == {}, "config must not be rewritten when already wide"
    assert not ssh._has('ip addr add'), "no live address change when already /16"
    assert not ssh._has('ip addr del')


def test_dry_run_reports_without_changing():
    ssh = FakeSSH(_config(24))
    mgr = AWGManager(ssh)

    res = mgr.heal_tunnel_onlink(PROTO, apply=False)

    assert res == {'status': 'widen', 'ip': '10.8.1.1', 'from': 24, 'to': 16}, res
    assert ssh.uploads == {}, "dry-run must not write anything"
    assert not ssh._has('ip addr add')
    assert not ssh._has('ip addr del')
    assert not ssh._has('docker cp')


def test_unknown_when_no_address():
    ssh = FakeSSH("[Interface]\nPrivateKey = X\nListenPort = 433\n")
    mgr = AWGManager(ssh)

    res = mgr.heal_tunnel_onlink(PROTO, apply=True)

    assert res == {'status': 'unknown'}, res
    assert ssh.uploads == {}
    assert not ssh._has('ip addr add')


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
