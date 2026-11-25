"""Opt-in FreeRADIUS checks for reply semantics that JSON tests cannot exercise."""

import json
import os
import re
import selectors
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import skipUnless
from uuid import uuid4

from django.test import SimpleTestCase, tag

FREERADIUS_IMAGE = (
    "freeradius/freeradius-server:3.2.9@"
    "sha256:193fccc990eaceeb41d79d04780968f5683dd5ea2c5fefb0c0ccf27c505e0150"
)


@tag("no_parallel")
@skipUnless(os.getenv("FREERADIUS_POLICY_TEST") == "1", "Requires opt-in Docker test")
class TestSessionTimeoutPolicy(SimpleTestCase):
    def test_rest_replies_produce_one_minimum_session_timeout(self):
        self.assertIsNotNone(shutil.which("docker"), "This test requires Docker.")
        self.assertIsNotNone(shutil.which("radclient"), "This test requires radclient.")
        reply_attributes = {}

        class ReplyHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                body = json.dumps(reply_attributes).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        # rlm_rest can preconnect before sending its request, so an idle
        # connection must not block the response handler.
        server = ThreadingHTTPServer(("127.0.0.1", 0), ReplyHandler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        directory_manager = tempfile.TemporaryDirectory()
        self.addCleanup(directory_manager.cleanup)
        directory = Path(directory_manager.name)
        root = Path(__file__).resolve().parents[2]
        fixture_directory = root / "tests" / "freeradius"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as radius_socket:
            radius_socket.bind(("127.0.0.1", 0))
            radius_port = radius_socket.getsockname()[1]
        configuration = (fixture_directory / "radiusd.conf").read_text()
        configuration = configuration.replace(
            "__REST_PORT__", str(server.server_port)
        ).replace("__RADIUS_PORT__", str(radius_port))
        (directory / "radiusd.conf").write_text(configuration)
        shutil.copyfile(fixture_directory / "dictionary", directory / "dictionary")
        shutil.copyfile(
            root / "docs" / "deploy" / "freeradius-session-timeout.conf",
            directory / "normalize_session_timeout",
        )
        name = f"openwisp-radius-policy-{uuid4().hex}"
        output = []
        process = subprocess.Popen(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                name,
                "--network",
                "host",
                "--mount",
                f"type=bind,src={directory},dst=/probe,readonly",
                "--entrypoint",
                "freeradius",
                FREERADIUS_IMAGE,
                "-X",
                "-d",
                "/probe",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        drainer = None

        def stop_radius():
            subprocess.run(
                ["docker", "stop", "--time", "1", name],
                capture_output=True,
                timeout=20,
            )
            process.wait(timeout=20)
            if drainer is not None:
                drainer.join(timeout=5)
            process.stdout.close()

        self.addCleanup(stop_radius)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if not selector.select(timeout=1):
                    continue
                line = process.stdout.readline().decode(errors="replace")
                output.append(line)
                if "Ready to process requests" in line:
                    break
                if not line and process.poll() is not None:
                    self.fail("".join(output))
            else:
                self.fail("FreeRADIUS did not start:\n" + "".join(output))

        def drain_output():
            for line in process.stdout:
                output.append(line.decode(errors="replace"))

        drainer = threading.Thread(target=drain_output, daemon=True)
        drainer.start()

        def authorize(attributes, existing_timeout=None):
            reply_attributes.clear()
            reply_attributes.update(attributes)
            request = (
                'User-Name = "policy-test"\n'
                'User-Password = "policy-test"\n'
                "Message-Authenticator = 0x00000000000000000000000000000000\n"
            )
            if existing_timeout is not None:
                request += f"NAS-Port = {existing_timeout}\n"
            result = subprocess.run(
                [
                    "radclient",
                    "-x",
                    f"127.0.0.1:{radius_port}",
                    "auth",
                    "local-policy-test",
                ],
                input=request,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr + "".join(output))
            self.assertIn("Received Access-Accept", result.stdout, "".join(output))
            return [
                int(value)
                for value in re.findall(r"Session-Timeout = (\d+)", result.stdout)
            ]

        with self.subTest("existing policy is shorter than default retention"):
            self.assertEqual(
                authorize(
                    {"Session-Timeout": {"op": "<=", "value": 86400}},
                    existing_timeout=1200,
                ),
                [1200],
            )

        with self.subTest("legacy expression is shorter than retention"):
            self.assertEqual(
                authorize(
                    {
                        "Session-Timeout": {
                            "op": "<=",
                            "value": ["%{expr:3600 - 60}", 86400],
                        }
                    }
                ),
                [3540],
            )

        with self.subTest("legacy expression exceeds retention"):
            self.assertEqual(
                authorize(
                    {
                        "Session-Timeout": {
                            "op": "<=",
                            "value": ["%{expr:100000}", 86400],
                        }
                    }
                ),
                [86400],
            )

        with self.subTest("equivalent reply names and server policy use one minimum"):
            self.assertEqual(
                authorize(
                    {
                        "Session-Timeout": {"op": "<=", "value": 3600},
                        "reply:Session-Timeout": {
                            "op": "<=",
                            "value": ["%{expr:1800 - 60}", 86400],
                        },
                    },
                    existing_timeout=1200,
                ),
                [1200],
            )

        with self.subTest("zero timeout remains a valid minimum"):
            self.assertEqual(
                authorize({"Session-Timeout": {"op": "<=", "value": [0, 86400]}}),
                [0],
            )

        with self.subTest("maximum RADIUS timeout remains valid"):
            self.assertEqual(
                authorize({"Session-Timeout": {"op": "<=", "value": 2**32 - 1}}),
                [2**32 - 1],
            )

        with self.subTest("no timeout remains absent"):
            self.assertEqual(authorize({}), [])
