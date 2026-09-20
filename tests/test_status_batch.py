import time
import unittest

from managers.awg_manager import AWGManager
from managers.ssh_manager import SSHManager


class FakeSSH:
    """Records commands and serves canned docker answers."""

    def __init__(self):
        self.commands = []
        self.ps_output = "amnezia-awg2\trunning\namnezia-awg3\texited\n"
        self.batch_output = (
            "@@CONTAINER@@ amnezia-awg2\n"
            "[Interface]\nPrivateKey = SRV\nListenPort = 55424\n"
            "@@CLIENTS@@\n"
            '[{"clientId": "PEER_A", "userData": {"clientName": "alice"}}]\n'
        )

    def run_sudo_command(self, cmd, timeout=60):
        self.commands.append(cmd)
        if cmd.startswith('docker ps -a --format'):
            return self.ps_output, '', 0
        if cmd.startswith('for c in '):
            return self.batch_output, '', 0
        if 'cat /opt/amnezia/awg/awg0.conf' in cmd and 'docker exec' in cmd:
            return '[Interface]\nListenPort = 55424\n', '', 0
        if 'clientsTable' in cmd:
            return '[]', '', 0
        return '', '', 0

    # Mirror the real SSHManager snapshot API against the canned output.
    def docker_ps_snapshot(self):
        now = time.time()
        cached = getattr(self, '_docker_ps_cache', None)
        if cached and now - cached[0] < SSHManager.DOCKER_PS_TTL:
            return cached[1]
        states = {}
        out, _, code = self.run_sudo_command(
            "docker ps -a --format '{{.Names}}\t{{.State}}'")
        if code == 0:
            for line in out.splitlines():
                parts = line.split('\t')
                if len(parts) == 2 and parts[0]:
                    states[parts[0]] = parts[1]
        self._docker_ps_cache = (now, states)
        return states

    def docker_container_state(self, name):
        try:
            states = self.docker_ps_snapshot()
        except Exception:
            return None
        return (name in states, states.get(name) == 'running')

    def docker_ps_invalidate(self):
        self._docker_ps_cache = None


class DockerPsSnapshotTest(unittest.TestCase):
    def test_snapshot_answers_all_container_queries_with_one_command(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)

        exists_a = mgr.check_protocol_installed('awg2')
        running_a = mgr.check_container_running('awg2')
        exists_b = mgr.check_protocol_installed('awg3')
        running_b = mgr.check_container_running('awg3')
        exists_c = mgr.check_protocol_installed('xray')

        self.assertTrue(exists_a)
        self.assertTrue(running_a)
        self.assertTrue(exists_b)
        self.assertFalse(running_b)
        self.assertFalse(exists_c)

        ps_cmds = [c for c in ssh.commands if c.startswith('docker ps')]
        self.assertEqual(len(ps_cmds), 1, f"snapshot must be a single command, got: {ps_cmds}")

    def test_invalidate_forces_refetch(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)
        mgr.check_protocol_installed('awg2')
        ssh.docker_ps_invalidate()
        mgr.check_protocol_installed('awg2')
        ps_cmds = [c for c in ssh.commands if c.startswith('docker ps')]
        self.assertEqual(len(ps_cmds), 2)


class PrefetchAwgStateTest(unittest.TestCase):
    def test_prefetch_feeds_config_and_clients_from_one_command(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)

        mgr.prefetch_awg_state(['awg2', 'awg3', 'awg2__2'])
        batch_cmds = [c for c in ssh.commands if c.startswith('for c in ')]
        self.assertEqual(len(batch_cmds), 1)
        # only the running container is dumped
        self.assertIn('amnezia-awg2', batch_cmds[0])
        self.assertNotIn('amnezia-awg3', batch_cmds[0])

        config = mgr._get_server_config('awg2')
        clients = mgr._get_clients_table('awg2')

        self.assertIn('ListenPort = 55424', config)
        self.assertEqual(clients[0]['clientId'], 'PEER_A')

        exec_cmds = [c for c in ssh.commands
                     if 'docker exec' in c and not c.startswith('for c in ')]
        self.assertEqual(exec_cmds, [], f"no per-container exec expected after prefetch: {exec_cmds}")

    def test_batch_cache_expires(self):
        ssh = FakeSSH()
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        ssh._awg_batch['_ts'] = time.time() - 100  # force stale
        self.assertIsNone(mgr._batch_entry('amnezia-awg2'))

    def test_no_running_containers_means_no_batch_command(self):
        ssh = FakeSSH()
        ssh.ps_output = "amnezia-awg2\texited\n"
        mgr = AWGManager(ssh)
        mgr.prefetch_awg_state(['awg2'])
        batch_cmds = [c for c in ssh.commands if c.startswith('for c in ')]
        self.assertEqual(batch_cmds, [])
        self.assertEqual(mgr._get_clients_table('awg2'), [])


if __name__ == '__main__':
    unittest.main()
