#!/usr/bin/env python3
"""Run disposable, socket-only PostgreSQL/Redis fixtures for Rabbit tests.

    python3 scripts/transport_fixtures.py serve /tmp/rabbit-fixtures --max-seconds 2700

Wait for fixtures.json, load its environment entries, then SIGTERM this process
and wait for it. cleanup.json must report complete=true before accepting a run.
Only this invocation's ownership-checked container IDs are removed. Images and
the private evidence directory are retained. Docker access is required.
"""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import quote, urlencode
import uuid


POSTGRES_IMAGE = "postgres@sha256:65b16a8b326e0cfbdf33fa7e783f2a0cb352a61448616ccccfd616ef42aa0f65"
REDIS_IMAGE = "redis@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499"
OWNER_LABEL = "io.synehq.rabbit.fixture-owner"
CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")


class FixtureError(RuntimeError):
    pass


class Docker:
    def __init__(self, sudo=False):
        self.prefix = ["sudo", "-n", "docker"] if sudo else ["docker"]

    def run(self, *arguments, timeout=30):
        try:
            result = subprocess.run(
                [*self.prefix, *arguments], capture_output=True, text=True,
                timeout=timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise FixtureError(f"Docker {arguments[0]} did not complete") from error
        if result.returncode:
            raise FixtureError(result.stderr.strip()[:4096] or f"Docker {arguments[0]} failed")
        output = result.stdout + (result.stderr if arguments[0] == "logs" else "")
        return output.strip()

    def inspect(self, reference):
        try:
            value = self.run("inspect", "--type", "container", reference)
        except FixtureError as error:
            if "No such object:" in str(error) or "No such container:" in str(error):
                return None
            raise
        objects = json.loads(value)
        if len(objects) != 1 or not CONTAINER_ID.fullmatch(objects[0].get("Id", "")):
            raise FixtureError("Docker returned an invalid container inspection")
        return objects[0]


def write_json(path, value):
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_root(path):
    path = Path(os.path.abspath(path))
    if path.is_symlink():
        raise FixtureError("fixture root must not be a symlink")
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or any(path.iterdir()):
        raise FixtureError("fixture root must be an empty directory owned by this user")
    path.chmod(0o700)
    # Unix-domain socket addresses have a small, platform-defined size limit.
    if len(os.fsencode(path / "pg" / ".s.PGSQL.5432")) >= 104:
        raise FixtureError("fixture root path is too long for Unix sockets; use /tmp")
    for child in ("pg", "redis"):
        directory = path / child
        directory.mkdir(mode=0o777)
        # Different container UIDs can create sockets; the enclosing 0700 root
        # restricts host access. Nothing is exposed on a TCP port or Docker network.
        directory.chmod(0o777)
    return path


class Fixtures:
    def __init__(self, root, docker=None):
        self.root = Path(root)
        self.docker = docker or Docker()
        self.owner = uuid.uuid4().hex
        self.containers = []

    def receipt(self):
        write_json(self.root / "receipt.json", {"owner": self.owner, "containers": self.containers})

    def create(self, role, image, options, command, deadline, stopped):
        if stopped.is_set() or time.monotonic() >= deadline:
            raise FixtureError("fixture startup interrupted")
        name = f"rabbit-fixture-{role}-{self.owner}"
        record = {"role": role, "name": name, "image": image, "id": None}
        self.containers.append(record)
        self.receipt()
        arguments = [
            "create", "--name", name, "--cidfile", str(self.root / f"{role}.cid"),
            "--label", f"{OWNER_LABEL}={self.owner}", "--network", "none",
            "--restart", "no", "--read-only", "--security-opt", "no-new-privileges:true",
            "--user", "999:999", "--cap-drop", "ALL", "--pids-limit", "128", *options, image, *command,
        ]
        identifier = self.docker.run(*arguments, timeout=max(0.1, min(120, deadline - time.monotonic())))
        if not CONTAINER_ID.fullmatch(identifier):
            raise FixtureError("Docker create did not return an exact container ID")
        record["id"] = identifier
        self.receipt()
        if stopped.is_set() or time.monotonic() >= deadline:
            raise FixtureError("fixture startup interrupted")
        self.docker.run("start", identifier, timeout=max(0.1, min(30, deadline - time.monotonic())))
        return identifier

    def start(self, stopped, deadline):
        # Pull immutable digests before creating either container. No source,
        # credentials or host services are mounted into a fixture.
        for image in (POSTGRES_IMAGE, REDIS_IMAGE):
            if stopped.is_set() or time.monotonic() >= deadline:
                raise FixtureError("fixture startup interrupted")
            self.docker.run("pull", image, timeout=min(300, max(1, deadline - time.monotonic())))
        postgres = self.create("pg", POSTGRES_IMAGE, [
            "--cpus", "0.5", "--memory", "512m", "--memory-swap", "512m",
            "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,uid=999,gid=999,mode=0755,size=402653184",
            "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,nodev,uid=999,gid=999,mode=0700,size=402653184",
            "--tmpfs", "/tmp:rw,nosuid,nodev,uid=999,gid=999,mode=1777,size=16777216",
            "--mount", f"type=bind,source={self.root / 'pg'},target=/var/run/postgresql",
            "--env", "PGDATA=/var/lib/postgresql/data",
            "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
            "--env", "POSTGRES_USER=postgres", "--env", "POSTGRES_DB=postgres",
        ], ["postgres", "-c", "listen_addresses=", "-c", "unix_socket_directories=/var/run/postgresql",
            "-c", "unix_socket_permissions=0777", "-c", "shared_buffers=32MB",
            "-c", "max_connections=32", "-c", "max_wal_size=128MB", "-c", "min_wal_size=32MB"], deadline, stopped)
        redis = self.create("redis", REDIS_IMAGE, [
            "--cpus", "0.25", "--memory", "128m", "--memory-swap", "128m",
            "--tmpfs", "/data:rw,nosuid,nodev,uid=999,gid=999,mode=0700,size=16777216",
            "--mount", f"type=bind,source={self.root / 'redis'},target=/run/rabbit-redis",
        ], ["redis-server", "--port", "0", "--unixsocket", "/run/rabbit-redis/redis.sock",
            "--unixsocketperm", "777", "--save", "", "--appendonly", "no",
            "--maxmemory", "64mb", "--maxmemory-policy", "noeviction"], deadline, stopped)
        ready_by = min(deadline, time.monotonic() + 120)
        while not stopped.is_set() and time.monotonic() < ready_by:
            for identifier in (postgres, redis):
                details = self.docker.inspect(identifier)
                if details is None or not details["State"]["Running"]:
                    raise FixtureError("fixture container exited before readiness")
            try:
                # The temporary initdb server may accept connections before the
                # image entrypoint completes. Wait for the final postgres PID 1.
                if self.docker.run("exec", postgres, "cat", "/proc/1/comm", timeout=5) != "postgres":
                    raise FixtureError("PostgreSQL initialization has not finished")
                self.docker.run("exec", postgres, "pg_isready", "-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres", timeout=5)
                if self.docker.run("exec", redis, "redis-cli", "-s", "/run/rabbit-redis/redis.sock", "PING", timeout=5) != "PONG":
                    raise FixtureError("Redis fixture did not answer PING")
                break
            except FixtureError:
                stopped.wait(0.25)
        else:
            raise FixtureError("fixture readiness timed out or was interrupted")
        postgres_url = "postgresql://postgres@/postgres?" + urlencode({"host": str(self.root / "pg"), "sslmode": "disable"})
        environment = {
            "SECURITY_TEST_DATABASE_URL": postgres_url,
            "RABBIT_TRANSPORT_DATABASE_URL": postgres_url,
            "RABBIT_TRANSPORT_REDIS_URL": "unix://" + quote(str(self.root / "redis" / "redis.sock"), safe="/") + "?db=0",
        }
        write_json(self.root / "fixtures.json", environment)

    def cleanup(self):
        errors, removed = [], []
        for record in reversed(self.containers):
            try:
                # Recovery after an interrupted create discovers an ID but never
                # removes by name. The random ownership label must still match.
                reference = record["id"] or record["name"]
                details = self.docker.inspect(reference)
                if details is None:
                    continue
                identifier = details["Id"]
                if details.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) != self.owner:
                    raise FixtureError("container ownership mismatch; left untouched")
                if record["id"] is not None and identifier != record["id"]:
                    raise FixtureError("container identity mismatch; left untouched")
                record["id"] = identifier
                self.receipt()
                try:
                    logs = self.docker.run("logs", "--tail", "80", identifier, timeout=10)
                    (self.root / f"{record['role']}.log").write_text(logs[-32768:], encoding="utf-8")
                except FixtureError:
                    pass
                self.docker.run("rm", "--force", "--volumes", identifier)
                if self.docker.inspect(identifier) is not None:
                    raise FixtureError("owned container remains after cleanup")
                removed.append(identifier)
            except (FixtureError, OSError, ValueError) as error:
                errors.append(f"{record['role']}: {error}")
        write_json(self.root / "cleanup.json", {"complete": not errors, "removed": removed, "errors": errors})
        if errors:
            raise FixtureError("fixture cleanup incomplete; inspect cleanup.json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("root")
    serve.add_argument("--max-seconds", type=int, default=2700)
    serve.add_argument("--sudo-docker", action="store_true", help="use sudo -n only for Docker; keep fixture files owned by this user")
    arguments = parser.parse_args(argv)
    if not 1 <= arguments.max_seconds <= 3600:
        parser.error("--max-seconds must be between 1 and 3600")
    stopped = threading.Event()
    for event in (signal.SIGTERM, signal.SIGINT):
        signal.signal(event, lambda _signal, _frame: stopped.set())
    os.umask(0o077)
    fixtures = None
    result = 0
    try:
        root = prepare_root(arguments.root)
        fixtures = Fixtures(root, Docker(sudo=arguments.sudo_docker))
        deadline = time.monotonic() + arguments.max_seconds
        fixtures.start(stopped, deadline)
        print(f"Fixtures ready: {root / 'fixtures.json'}", flush=True)
        remaining = max(0, deadline - time.monotonic())
        if not stopped.wait(remaining):
            print("Fixture lifetime limit reached", file=sys.stderr)
            result = 2
    except (FixtureError, OSError, ValueError) as error:
        print(f"Fixture failure: {error}", file=sys.stderr)
        result = 1
    finally:
        if fixtures is not None:
            try:
                fixtures.cleanup()
            except (FixtureError, OSError) as error:
                print(str(error), file=sys.stderr)
                result = 3
    return result


if __name__ == "__main__":
    raise SystemExit(main())
