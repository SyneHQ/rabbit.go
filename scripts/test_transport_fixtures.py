#!/usr/bin/env python3
"""Controller ownership tests; no Docker daemon or service is started."""

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

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

    def run(self, *arguments, timeout=30):
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
    def run(self, *arguments, timeout=30):
        if arguments[0] in ("logs", "rm"):
            return super().run(*arguments, timeout=timeout)
        self.commands.append(arguments)
        if arguments[0] == "pull":
            return "image available"
        if arguments[0] == "create":
            identifier = ("a" if not self.objects else "b") * 64
            label = arguments[arguments.index("--label") + 1]
            label_name, label_value = label.split("=", 1)
            self.objects[identifier] = {
                "Id": identifier, "Name": arguments[arguments.index("--name") + 1],
                "Config": {"Labels": {label_name: label_value}}, "State": {"Running": False},
            }
            return identifier
        if arguments[0] == "start":
            self.objects[arguments[1]]["State"]["Running"] = True
            return arguments[1]
        if arguments[0] == "exec":
            if arguments[2:] == ("cat", "/proc/1/comm"):
                return "postgres"
            if arguments[2] == "pg_isready":
                return "accepting connections"
            if arguments[2] == "redis-cli":
                return "PONG"
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


if __name__ == "__main__":
    unittest.main()
