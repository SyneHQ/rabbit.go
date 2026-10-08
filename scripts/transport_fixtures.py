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
import secrets
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
MYSQL_IMAGE = "mysql@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"
OWNER_LABEL = "io.synehq.rabbit.fixture-owner"
CONTAINER_ID = re.compile(r"^[a-f0-9]{64}$")


class FixtureError(RuntimeError):
    pass


class Docker:
    def __init__(self, sudo=False):
        self.prefix = ["sudo", "-n", "docker"] if sudo else ["docker"]

    def run(self, *arguments, timeout=30, input_text=None):
        try:
            result = subprocess.run(
                [*self.prefix, *arguments], capture_output=True, text=True,
                timeout=timeout, check=False, input=input_text,
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
    def __init__(self, root, docker=None, mysql=False):
        self.root = Path(root)
        self.docker = docker or Docker()
        self.owner = uuid.uuid4().hex
        self.containers = []
        self.mysql = mysql

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
        for image in (POSTGRES_IMAGE, REDIS_IMAGE, *([MYSQL_IMAGE] if self.mysql else [])):
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
        if self.mysql:
            environment.update(self.start_mysql(stopped, deadline))
        write_json(self.root / "fixtures.json", environment)

    def start_mysql(self, stopped, deadline):
        socket = self.root / "mysql"
        socket.mkdir(mode=0o777)
        socket.chmod(0o777)
        certs = self.root / "mysql-certs"
        certs.mkdir(mode=0o700)
        key, ca = certs / "server.key", certs / "ca.pem"
        try:
            result = subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout", str(key), "-out", str(ca),
            ], capture_output=True, timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise FixtureError("cannot generate MySQL source TLS fixture") from error
        if result.returncode:
            raise FixtureError("cannot generate MySQL source TLS fixture")
        # Only this 0700 fixture root is traversable on the host. Inside the
        # read-only certificate mount, the unprivileged server must read its key.
        certs.chmod(0o755)
        key.chmod(0o644)
        ca.chmod(0o644)
        identifier = self.create("mysql", MYSQL_IMAGE, [
            "--cpus", "0.5", "--memory", "768m", "--memory-swap", "768m",
            "--tmpfs", "/var/lib/mysql:rw,nosuid,nodev,uid=999,gid=999,mode=0700,size=536870912",
            "--tmpfs", "/tmp:rw,nosuid,nodev,uid=999,gid=999,mode=1777,size=16777216",
            "--mount", f"type=bind,source={socket},target=/run/rabbit-mysql",
            "--mount", f"type=bind,source={certs},target=/fixture-certs,readonly",
            "--env", "MYSQL_ALLOW_EMPTY_PASSWORD=1", "--env", "MYSQL_DATABASE=rabbit_native",
        ], ["mysqld", "--skip-networking", "--mysqlx=OFF", "--skip-log-bin", "--performance-schema=OFF",
            "--socket=/run/rabbit-mysql/mysql.sock", "--pid-file=/tmp/mysql.pid", "--innodb-buffer-pool-size=64M",
            "--innodb-redo-log-capacity=32M", "--max-connections=16", "--max-execution-time=25000",
            "--require-secure-transport=ON", "--tls-version=TLSv1.3", "--ssl-ca=/fixture-certs/ca.pem",
            "--ssl-cert=/fixture-certs/ca.pem", "--ssl-key=/fixture-certs/server.key"], deadline, stopped)
        ready_by = min(deadline, time.monotonic() + 180)
        client = ["exec", "-i", identifier, "mysql", "--protocol=SOCKET", "--socket=/run/rabbit-mysql/mysql.sock", "-uroot", "--batch", "--silent"]
        while not stopped.is_set() and time.monotonic() < ready_by:
            details = self.docker.inspect(identifier)
            if details is None or not details["State"]["Running"]:
                raise FixtureError("MySQL fixture exited before readiness")
            try:
                if self.docker.run("exec", identifier, "cat", "/proc/1/comm", timeout=5) != "mysqld":
                    raise FixtureError("MySQL initialization has not finished")
                if self.docker.run(*client, input_text="SELECT 1;", timeout=5) != "1":
                    raise FixtureError("MySQL fixture did not answer its readiness query")
                break
            except FixtureError:
                stopped.wait(0.25)
        else:
            raise FixtureError("MySQL fixture readiness timed out or was interrupted")
        password = secrets.token_hex(32)
        sql = """USE rabbit_native;
CREATE TABLE private_connect_rows(id BIGINT PRIMARY KEY, category INT NOT NULL, note TEXT NULL);
INSERT INTO private_connect_rows
WITH digits AS (SELECT 0 AS n UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4
 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9),
numbers AS (SELECT 1+a.n+10*b.n+100*c.n+1000*d.n+10000*e.n AS id
 FROM digits a CROSS JOIN digits b CROSS JOIN digits c CROSS JOIN digits d CROSS JOIN digits e)
SELECT id,MOD(id,17),IF(MOD(id,13)=0,NULL,CONCAT('row-',id)) FROM numbers;
CREATE USER 'kelvo_reader'@'localhost' IDENTIFIED BY '""" + password + """' REQUIRE SSL;
GRANT SELECT ON rabbit_native.* TO 'kelvo_reader'@'localhost';
"""
        try:
            self.docker.run(*client, input_text=sql, timeout=min(90, max(1, deadline-time.monotonic())))
        except FixtureError as error:
            raise FixtureError("MySQL fixture schema or SELECT-only account creation failed") from error
        details = self.docker.inspect(identifier)
        uid = self.docker.run("exec", identifier, "id", "-u", timeout=5)
        status = self.docker.run("exec", identifier, "cat", "/proc/1/status", timeout=5)
        pid_uids = next((line.split()[1:] for line in status.splitlines() if line.startswith("Uid:")), [])
        version = self.docker.run(*client, input_text="SELECT VERSION();", timeout=5)
        if details is None or uid != "999" or pid_uids != ["999"]*4 or details.get("Config", {}).get("User") != "999:999" or \
                details.get("HostConfig", {}).get("ReadonlyRootfs") is not True or \
                details.get("HostConfig", {}).get("NetworkMode") != "none" or \
                details.get("HostConfig", {}).get("PortBindings"):
            raise FixtureError("MySQL fixture isolation did not match its required bounds")
        proof = {"image": MYSQL_IMAGE, "image_id": details.get("Image"), "container_id": identifier,
                 "uid": 999, "pid1_uid": 999, "readonly_root": True, "network": "none", "published_ports": False,
                 "server_version": version}
        write_json(self.root / "mysql-qualification.json", proof)
        print("MySQL fixture identity: " + json.dumps(proof, sort_keys=True), flush=True)
        return {
            "RABBIT_TRANSPORT_MYSQL_SOCKET": str(socket / "mysql.sock"),
            "RABBIT_TRANSPORT_MYSQL_CA": str(ca),
            "RABBIT_TRANSPORT_MYSQL_PASSWORD": password,
        }

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
    serve.add_argument("--mysql", action="store_true", help="also provision a TLS MySQL source with a SELECT-only account")
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
        fixtures = Fixtures(root, Docker(sudo=arguments.sudo_docker), mysql=arguments.mysql)
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
