#!/usr/bin/env python3
"""Controller ownership tests; no Docker daemon or service is started."""

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import transport_fixtures as controller


class FakeDocker:
    def __init__(self):
        self.objects = {}
        self.commands = []
        self.keep_after_remove = set()

    def inspect(self, reference):
        for identifier, value in self.objects.items():
            if reference in (identifier, value["Name"]):
                return value
        return None

    def run(self, *arguments, timeout=30, input_text=None):
        self.commands.append(arguments)
        if arguments[0] == "logs":
            return "fixture logs"
        if arguments[:3] != ("rm", "--force", "--volumes"):
            raise AssertionError(f"unexpected Docker action: {arguments}")
        identifier = arguments[3]
        if not controller.CONTAINER_ID.fullmatch(identifier):
            raise AssertionError("cleanup used a name or a partial container ID")
        if identifier not in self.keep_after_remove:
            self.objects.pop(identifier)
        return identifier


class FakeStartingDocker(FakeDocker):
    def __init__(self):
        super().__init__()
        self.inputs = []

    def run(self, *arguments, timeout=30, input_text=None):
        if input_text is not None:
            self.inputs.append(input_text)
        if arguments[0] in ("logs", "rm"):
            return super().run(*arguments, timeout=timeout)
        self.commands.append(arguments)
        if arguments[0] == "pull":
            return "image available"
        if arguments[0] == "create":
            identifier = chr(ord("a") + len(self.objects)) * 64
            label = arguments[arguments.index("--label") + 1]
            label_name, label_value = label.split("=", 1)
            self.objects[identifier] = {
                "Id": identifier, "Name": arguments[arguments.index("--name") + 1],
                "Config": {"Labels": {label_name: label_value}, "User": "999:999"}, "State": {"Running": False},
                "HostConfig": {"ReadonlyRootfs": True, "NetworkMode": "none", "PortBindings": {}},
                "Image": "sha256:" + "c" * 64,
            }
            return identifier
        if arguments[0] == "start":
            self.objects[arguments[1]]["State"]["Running"] = True
            return arguments[1]
        if arguments[0] == "exec":
            if arguments[2:] == ("cat", "/proc/1/comm"):
                return "mysqld" if "-mysql-" in self.objects[arguments[1]]["Name"] else "postgres"
            if arguments[2] == "pg_isready":
                return "accepting connections"
            if arguments[2] == "redis-cli":
                return "PONG"
            if arguments[2:] == ("id", "-u"):
                return "999"
            if arguments[2:] == ("cat", "/proc/1/status"):
                return "Uid:\t999\t999\t999\t999\n"
            if arguments[1] == "-i" and arguments[3] == "mysql":
                return {"SELECT 1;": "1", "SELECT VERSION();": "8.4.fixture"}.get(input_text, "")
        raise AssertionError(f"unexpected Docker action: {arguments}")


class FixtureCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="rabbit-fixture-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.docker = FakeDocker()
        self.fixtures = controller.Fixtures(self.root, self.docker)

    def add_container(self, character, role, owned=True, record_id=True):
        identifier = character * 64
        name = f"rabbit-fixture-{role}-{self.fixtures.owner}"
        self.docker.objects[identifier] = {
            "Id": identifier, "Name": name,
            "Config": {"Labels": {controller.OWNER_LABEL: self.fixtures.owner if owned else "someone-else"}},
        }
        self.fixtures.containers.append({"role": role, "name": name, "id": identifier if record_id else None})
        return identifier

    def test_removes_only_exact_owned_ids_and_verifies_absence(self):
        first = self.add_container("a", "pg")
        second = self.add_container("b", "redis")
        unrelated = "c" * 64
        self.docker.objects[unrelated] = {"Id": unrelated, "Name": "unrelated-service", "Config": {"Labels": {}}}
        self.fixtures.cleanup()
        self.assertEqual(set(self.docker.objects), {unrelated})
        removes = [call for call in self.docker.commands if call[0] == "rm"]
        self.assertEqual(removes, [("rm", "--force", "--volumes", second), ("rm", "--force", "--volumes", first)])
        receipt = json.loads((self.root / "cleanup.json").read_text())
        self.assertTrue(receipt["complete"])

    def test_recovers_id_after_interrupted_create_without_removing_by_name(self):
        identifier = self.add_container("d", "pg", record_id=False)
        self.fixtures.cleanup()
        self.assertIn(("rm", "--force", "--volumes", identifier), self.docker.commands)

    def test_foreign_ownership_is_left_untouched_and_reported(self):
        identifier = self.add_container("e", "pg", owned=False)
        with self.assertRaises(controller.FixtureError):
            self.fixtures.cleanup()
        self.assertIn(identifier, self.docker.objects)
        self.assertFalse(any(call[0] == "rm" for call in self.docker.commands))
        self.assertFalse(json.loads((self.root / "cleanup.json").read_text())["complete"])

    def test_cleanup_failure_does_not_skip_other_owned_container(self):
        first = self.add_container("a", "pg")
        second = self.add_container("b", "redis")
        self.docker.keep_after_remove.add(second)
        with self.assertRaises(controller.FixtureError):
            self.fixtures.cleanup()
        self.assertIn(second, self.docker.objects)
        self.assertNotIn(first, self.docker.objects)

    def test_repeated_cleanup_does_not_remove_other_resources(self):
        self.add_container("a", "pg")
        self.fixtures.cleanup()
        first_commands = list(self.docker.commands)
        self.fixtures.cleanup()
        self.assertEqual(self.docker.commands, first_commands)

    def test_root_rejects_nonempty_directory_and_symlink(self):
        (self.root / "existing").write_text("keep")
        with self.assertRaises(controller.FixtureError):
            controller.prepare_root(self.root)
        link = self.root / "alias"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(controller.FixtureError):
            controller.prepare_root(link)
        self.assertEqual((self.root / "existing").read_text(), "keep")

    def test_startup_uses_default_postgres_socket_without_conflicting_tmpfs(self):
        controller.prepare_root(self.root)
        docker = FakeStartingDocker()
        fixtures = controller.Fixtures(self.root, docker)
        fixtures.start(threading.Event(), time.monotonic() + 60)
        creates = [call for call in docker.commands if call[0] == "create"]
        self.assertEqual(len(creates), 2)
        postgres = creates[0]
        self.assertIn(f"type=bind,source={self.root / 'pg'},target=/var/run/postgresql", postgres)
        self.assertIn("unix_socket_directories=/var/run/postgresql", postgres)
        self.assertFalse(any(value.startswith("/var/run/postgresql:") for value in postgres))
        for create in creates:
            self.assertEqual(create[create.index("--user") + 1], "999:999")
            self.assertEqual(create[create.index("--cap-drop") + 1], "ALL")
            self.assertEqual(create[create.index("--network") + 1], "none")
            self.assertNotIn("--publish", create)
            self.assertIn("--read-only", create)
        environment = json.loads((self.root / "fixtures.json").read_text())
        self.assertEqual(set(environment), {"SECURITY_TEST_DATABASE_URL", "RABBIT_TRANSPORT_DATABASE_URL", "RABBIT_TRANSPORT_REDIS_URL"})
        fixtures.cleanup()

    def test_optional_mysql_is_socket_only_tls_and_select_only(self):
        controller.prepare_root(self.root)
        docker = FakeStartingDocker()
        fixtures = controller.Fixtures(self.root, docker, mysql=True)
        def certificate(argv, **kwargs):
            self.assertEqual(argv[0], "openssl")
            Path(argv[argv.index("-keyout")+1]).write_text("generated fixture key")
            Path(argv[argv.index("-out")+1]).write_text("generated fixture CA")
            return SimpleNamespace(returncode=0)
        with patch.object(controller.subprocess, "run", side_effect=certificate):
            fixtures.start(threading.Event(), time.monotonic()+60)
        creates = [call for call in docker.commands if call[0] == "create"]
        self.assertEqual(len(creates), 3)
        mysql = creates[-1]
        self.assertIn(controller.MYSQL_IMAGE, mysql)
        self.assertEqual(mysql[mysql.index("--network")+1], "none")
        self.assertEqual(mysql[mysql.index("--memory")+1], "768m")
        self.assertIn("--skip-networking", mysql)
        self.assertIn("--require-secure-transport=ON", mysql)
        self.assertIn("--tls-version=TLSv1.3", mysql)
        self.assertNotIn("--publish", mysql)
        self.assertIn("--read-only", mysql)
        environment = json.loads((self.root/"fixtures.json").read_text())
        password = environment["RABBIT_TRANSPORT_MYSQL_PASSWORD"]
        self.assertRegex(password, r"^[0-9a-f]{64}$")
        self.assertFalse(any(password in argument for call in docker.commands for argument in call))
        schema = next(value for value in docker.inputs if "CREATE USER" in value)
        self.assertIn("REQUIRE SSL", schema)
        self.assertIn("GRANT SELECT ON rabbit_native.*", schema)
        self.assertNotIn("GRANT ALL", schema)
        proof = json.loads((self.root/"mysql-qualification.json").read_text())
        self.assertEqual(proof["uid"], 999)
        self.assertEqual(proof["server_version"], "8.4.fixture")
        fixtures.cleanup()
        self.assertEqual(docker.objects, {})


if __name__ == "__main__":
    unittest.main()
