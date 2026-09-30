"""Verify authentication boundaries through a separate HTTP client."""
import base64
import json
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

import app as panel


class HttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.user = {'id': 'owner', 'username': 'owner', 'role': 'user', 'enabled': True}
        self.state = {
            'users': [self.user],
            'servers': [{'host': 'example.invalid', 'protocols': {'awg2': {'port': '443'}}}],
            'user_connections': [{'user_id': 'owner', 'server_id': 0,
                                  'client_id': 'synthetic-peer', 'protocol': 'awg2'}],
        }
        middleware = next(m for m in panel.app.user_middleware
                          if m.cls.__name__ == 'SessionMiddleware')
        cookie = TimestampSigner(str(middleware.kwargs['secret_key'])).sign(
            base64.b64encode(json.dumps({'user_id': 'owner'}).encode())).decode()
        self.client = TestClient(panel.app)
        self.addCleanup(self.client.close)
        self.client.cookies.set('session', cookie)

    def test_existing_cookie_is_rejected_immediately_after_disable(self):
        with patch.object(panel, 'load_data', return_value=self.state), patch.object(
            panel, 'get_ssh', return_value=Mock()
        ), patch.object(panel, '_manager_call', return_value='synthetic config') as call:
            payload = {'protocol': 'awg2', 'client_id': 'synthetic-peer'}
            self.assertEqual(self.client.post('/api/servers/0/connections/config', json=payload).status_code, 200)
            self.user['enabled'] = False
            self.assertEqual(self.client.post('/api/servers/0/connections/config', json=payload).status_code, 403)
            self.assertEqual(call.call_count, 1)

    def test_http_client_cannot_download_same_id_from_another_protocol(self):
        with patch.object(panel, 'load_data', return_value=self.state), patch.object(panel, 'get_ssh') as ssh:
            response = self.client.post('/api/servers/0/connections/config',
                                        json={'protocol': 'awg3', 'client_id': 'synthetic-peer'})
            self.assertEqual(response.status_code, 403)
            ssh.assert_not_called()

