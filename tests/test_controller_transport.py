import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from controller_transport import config_endpoints, decode_http, PIPE_PREFIX
from pipe_client import MihomoPipe


class ControllerTests(unittest.TestCase):
    def test_reads_dynamic_pipe_and_secret_without_full_yaml_dependency(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "test.yaml"
            path.write_text("external-controller-pipe: '" + PIPE_PREFIX + "verge-mihomo-sidecar-release-abc'\n"
                            "secret: 'a:b#c'\nexternal-controller: 127.0.0.1:9999\n"
                            "proxies:\n  - secret: unrelated\n", encoding="utf-8-sig")
            endpoints = config_endpoints([path])
            self.assertEqual(endpoints[0], ('pipe', PIPE_PREFIX + 'verge-mihomo-sidecar-release-abc', 'a:b#c'))
            self.assertEqual(endpoints[1], ('tcp', 9999, 'a:b#c'))

    def test_remote_controller_never_receives_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'test.yaml'
            path.write_text('external-controller: remote.example:9090\nsecret: private\n')
            self.assertEqual(config_endpoints([path]), [])

    def test_missing_config_is_normal(self):
        self.assertEqual(config_endpoints([Path('missing-controller.yaml')]), [])

    def test_content_length_is_byte_length_for_chinese(self):
        body = json.dumps({'node':'美国家宽🚀'},ensure_ascii=False).encode('utf-8')
        response = b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        self.assertIsNone(decode_http(response[:-1]))
        self.assertEqual(json.loads(decode_http(response)[1]), {'node':'美国家宽🚀'})

    def test_chunk_boundaries_inside_utf8_are_safe(self):
        body = '{"node":"美国🚀"}'.encode()
        chunks = [body[:10], body[10:12], body[12:]]
        raw = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
        for chunk in chunks:
            raw += hex(len(chunk))[2:].encode()+b';extension=yes\r\n'+chunk+b'\r\n'
        self.assertIsNone(decode_http(raw))
        self.assertEqual(decode_http(raw+b'0\r\n\r\n'), (200,body))

    def test_status_and_truncated_response(self):
        self.assertEqual(decode_http(b'HTTP/1.1 504 Timeout\r\nContent-Length: 0\r\n\r\n'),(504,b''))
        self.assertIsNone(decode_http(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n{}',eof=True))

    def test_delay_failure_does_not_disconnect_controller(self):
        pipe = MihomoPipe(); pipe._chan = ('pipe','fake','secret')
        with patch.object(pipe,'_exchange',return_value=(504,b'{}')):
            self.assertIsNone(pipe.node_delay('Node'))
        self.assertIsNotNone(pipe._chan)
        with patch.object(pipe,'_exchange',side_effect=TimeoutError):
            self.assertIsNone(pipe.node_delay('Node'))
        self.assertIsNotNone(pipe._chan)

    def test_auth_failure_forces_rediscovery(self):
        pipe = MihomoPipe(); pipe._chan = ('pipe','fake','secret')
        with patch.object(pipe,'_exchange',return_value=(401,b'{}')):
            self.assertIsNone(pipe.get('/configs'))
        self.assertIsNone(pipe._chan)

    def test_bad_json_does_not_get_rendered(self):
        pipe = MihomoPipe(); pipe._chan = ('pipe','fake','secret')
        with patch.object(pipe,'_exchange',return_value=(200,b'{"node":"\xff"}')):
            self.assertIsNone(pipe.get('/connections'))
        self.assertIsNone(pipe._chan)

    def test_service_pipe_discovery_uses_configured_auth(self):
        pipe = MihomoPipe()
        configured = [('pipe',PIPE_PREFIX+'verge-mihomo-sidecar-release-abc','configured-secret')]
        def exchange(channel,path,timeout):
            if channel == ('pipe',PIPE_PREFIX+'verge-mihomo-production-abc','configured-secret'):
                return 200,b'{"version":"v1.19.31"}'
            raise OSError('not found')
        with patch('controller_transport.config_endpoints',return_value=configured), \
             patch('controller_transport.os.listdir',return_value=['verge-mihomo-production-abc']), \
             patch.object(pipe,'_exchange',side_effect=exchange):
            self.assertTrue(pipe._detect())
        self.assertEqual(pipe.version,'v1.19.31')

    def test_old_failed_request_cannot_disconnect_new_channel(self):
        pipe = MihomoPipe(); pipe._chan = ('pipe','new','s')
        pipe.mark_dead(('pipe','old','s'))
        self.assertEqual(pipe._chan[1], 'new')

    def test_invalid_delay_not_displayed_as_zero(self):
        for value in ('invalid',None,-1,True):
            pipe = MihomoPipe()
            with patch.object(pipe,'get',return_value={'delay':value}):
                self.assertIsNone(pipe.node_delay('Node'))

