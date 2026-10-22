from __future__ import annotations

import json
import socket
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

from srcguard.docker_proxy import (
    DockerMutationProxy,
    DockerProxyConfig,
    mutate_create,
)


class MutateCreateTests(unittest.TestCase):
    def test_drops_net_admin_keeps_net_raw(self) -> None:
        payload = {"HostConfig": {"CapAdd": ["NET_ADMIN", "NET_RAW"]}}
        out, changes, reject = mutate_create(payload)
        self.assertIsNone(reject)
        self.assertEqual(out["HostConfig"]["CapAdd"], ["NET_RAW"])
        self.assertIn("dropped CapAdd NET_ADMIN", changes)

    def test_rejects_privileged_and_host_namespaces(self) -> None:
        for host in (
            {"Privileged": True},
            {"NetworkMode": "host"},
            {"NetworkMode": "container:abc"},
            {"PidMode": "host"},
            {"IpcMode": "host"},
            {"UTSMode": "host"},
            {"UsernsMode": "host"},
            {"CapAdd": ["ALL"]},
        ):
            _out, _changes, reject = mutate_create({"HostConfig": host})
            self.assertIsNotNone(reject, host)

    def test_forces_dns_server(self) -> None:
        payload = {"HostConfig": {"Dns": ["9.9.9.9"], "DnsSearch": ["corp"]}}
        out, changes, reject = mutate_create(payload, dns_server="172.17.0.1")
        self.assertIsNone(reject)
        self.assertEqual(out["HostConfig"]["Dns"], ["172.17.0.1"])
        self.assertEqual(out["HostConfig"]["DnsSearch"], [])
        self.assertIn("Dns -> 172.17.0.1", changes)

    def test_mounts_outside_workspace_become_readonly(self) -> None:
        payload = {
            "HostConfig": {
                "Mounts": [
                    {"Type": "bind", "Source": "/host/repo", "Target": "/workspace/repo"},
                    {"Type": "bind", "Source": "/host/run", "Target": "/workspace"},
                    {"Type": "bind", "Source": "/host/tmp", "Target": "/tmp/x"},
                ],
                "Binds": ["/host/repo:/workspace/repo:rw", "/host/run:/workspace:rw"],
            }
        }
        out, changes, reject = mutate_create(payload)
        self.assertIsNone(reject)
        mounts = out["HostConfig"]["Mounts"]
        self.assertTrue(mounts[0]["ReadOnly"])
        self.assertNotIn("ReadOnly", mounts[1])
        self.assertNotIn("ReadOnly", mounts[2])
        self.assertIn("/host/repo:/workspace/repo:ro", out["HostConfig"]["Binds"])
        self.assertIn("/host/run:/workspace:rw", out["HostConfig"]["Binds"])
        self.assertTrue(any("/workspace/repo" in item for item in changes))


class FakeDocker(socketserver.UnixStreamServer):
    def __init__(self, path: str) -> None:
        super().__init__(path, FakeHandler)
        self.requests: list[tuple[str, bytes]] = []


class FakeHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(65536)
            if not chunk:
                return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            headers[name.decode().lower()] = value.decode().strip()
        length = int(headers.get("content-length", "0"))
        while len(rest) < length:
            chunk = self.request.recv(65536)
            if not chunk:
                break
            rest += chunk
        self.server.requests.append((head.decode("latin-1"), rest[:length]))
        body = json.dumps({"ok": True}).encode()
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
        )


class ProxyForwardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.sock_path = str(Path(self.tmp.name) / "docker.sock")
        self.fake = FakeDocker(self.sock_path)
        self.thread = threading.Thread(target=self.fake.serve_forever, daemon=True)
        self.thread.start()
        self.proxy = DockerMutationProxy(
            DockerProxyConfig(
                socket_path=self.sock_path,
                audit_path=Path(self.tmp.name) / "docker.jsonl",
            )
        )
        self.proxy.start()

    def tearDown(self) -> None:
        self.proxy.stop()
        self.fake.shutdown()
        self.fake.server_close()
        self.tmp.cleanup()

    def _request(self, payload: dict) -> tuple[int, bytes]:
        raw = json.dumps(payload).encode()
        request = (
            b"POST /v1.43/containers/create HTTP/1.1\r\nHost: docker\r\n"
            b"Content-Type: application/json\r\nContent-Length: "
            + str(len(raw)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + raw
        )
        with socket.create_connection(("127.0.0.1", self.proxy.port), timeout=5) as sock:
            sock.sendall(request)
            chunks = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
        response = b"".join(chunks)
        status = int(response.split(b" ", 2)[1])
        return status, response

    def test_forwards_mutated_create(self) -> None:
        status, _response = self._request(
            {"HostConfig": {"CapAdd": ["NET_ADMIN", "NET_RAW"]}}
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(self.fake.requests), 1)
        _head, body = self.fake.requests[0]
        sent = json.loads(body)
        self.assertEqual(sent["HostConfig"]["CapAdd"], ["NET_RAW"])

    def test_rejects_privileged_without_forwarding(self) -> None:
        status, response = self._request({"HostConfig": {"Privileged": True}})
        self.assertEqual(status, 403)
        self.assertIn(b"privileged", response)
        self.assertEqual(self.fake.requests, [])


if __name__ == "__main__":
    unittest.main()
