#!/usr/bin/env python3
"""Validate actual Kelvo Arrow results from direct and Rabbit PostgreSQL paths."""

import argparse
import datetime as dt
import decimal
import hashlib
import json
from pathlib import Path
import struct

import pyarrow as pa
import pyarrow.ipc as ipc

ROWS = 1_000_000
BASE_DAY = dt.date(2024, 1, 1)
EPOCH = dt.date(1970, 1, 1)
EOS = b"\xff\xff\xff\xff\x00\x00\x00\x00"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_schema(schema, names, types, native_types):
    require(schema.names == names, f"column names changed: {schema.names}")
    for field, expected, native in zip(schema, types, native_types):
        require(field.type == expected, f"{field.name}: expected {expected}, got {field.type}")
        metadata = field.metadata or {}
        require(metadata.get(b"source_type") == b"postgres", f"{field.name}: source metadata changed")
        require(metadata.get(b"native_type") == native.encode(), f"{field.name}: native metadata changed")


def open_result(path):
    path = Path(path)
    require(path.stat().st_size <= 256 * 1024 * 1024, "Arrow output exceeds fixture byte bound")
    with path.open("rb") as handle:
        handle.seek(-len(EOS), 2)
        require(handle.read() == EOS, "Arrow output has no complete end marker")
    return pa.memory_map(str(path), "r")


def check_rows(path):
    count = nulls = batches = 0
    digest = hashlib.sha256()
    with open_result(path) as source:
        reader = ipc.open_stream(source)
        schema = reader.schema
        check_schema(
            schema,
            ["id", "category", "note", "active", "amount", "day"],
            [pa.int64(), pa.int32(), pa.string(), pa.bool_(), pa.decimal128(18, 2), pa.date32()],
            ["INT8", "INT4", "TEXT", "BOOL", "NUMERIC", "DATE"],
        )
        require(schema.field("note").nullable, "nullable text became non-nullable")
        for batch in reader:
            batches += 1
            require(batch.num_rows <= 65536, "unexpected unbounded Arrow batch")
            columns = [column.to_pylist() for column in batch.columns]
            for identifier, category, note, active, amount, day in zip(*columns):
                count += 1
                require(identifier == count, f"row {count}: ID missing, reordered or changed")
                require(category == identifier % 97, f"row {count}: category changed")
                require(active is (identifier % 2 == 0), f"row {count}: boolean changed")
                require(amount == decimal.Decimal(identifier).scaleb(-2), f"row {count}: decimal changed")
                require(day == BASE_DAY + dt.timedelta(days=identifier % 365), f"row {count}: date changed")
                expected_note = None if identifier % 17 == 0 else f"value-{identifier:07d}"
                require(note == expected_note, f"row {count}: text or NULL changed")
                digest.update(struct.pack("<qi?qi", identifier, category, active, int(amount * 100), (day - EPOCH).days))
                if note is None:
                    nulls += 1
                    digest.update(b"\x00")
                else:
                    encoded = note.encode()
                    digest.update(b"\x01" + struct.pack("<I", len(encoded)) + encoded)
        require(source.tell() == source.size(), "unexpected data after Arrow end marker")
    require(count == ROWS, f"expected {ROWS} rows, got {count}")
    require(nulls == ROWS // 17, "NULL count changed")
    return {"rows": count, "nulls": nulls, "batches": batches, "canonical_sha256": digest.hexdigest()}, schema


def expected_cte():
    groups = []
    for category in range(97):
        first = category or 97
        identifiers = range(first, ROWS + 1, 97)
        cents = sum(identifiers)
        groups.append({
            "category": category,
            "trips": len(identifiers),
            "non_null_notes": sum(identifier % 17 != 0 for identifier in identifiers),
            "revenue": decimal.Decimal(cents).scaleb(-2),
            "first_day": BASE_DAY,
            "last_day": BASE_DAY + dt.timedelta(days=364),
            "segment": None if category % 5 == 0 else f"segment-{category}",
            "read_only": "on",
        })
    for rank, group in enumerate(sorted(groups, key=lambda row: (-row["revenue"], row["category"])), 1):
        group["revenue_rank"] = rank
    return groups


def check_cte(path):
    expected = expected_cte()
    result = []
    with open_result(path) as source:
        reader = ipc.open_stream(source)
        schema = reader.schema
        check_schema(
            schema,
            ["category", "trips", "non_null_notes", "revenue", "first_day", "last_day", "revenue_rank", "segment", "read_only"],
            [pa.int32(), pa.int64(), pa.int64(), pa.decimal128(24, 2), pa.date32(), pa.date32(), pa.int64(), pa.string(), pa.string()],
            ["INT4", "INT8", "INT8", "NUMERIC", "DATE", "DATE", "INT8", "TEXT", "TEXT"],
        )
        for batch in reader:
            require(len(result) + batch.num_rows <= 97, "CTE returned unexpected rows")
            result.extend(batch.to_pylist())
        require(source.tell() == source.size(), "unexpected data after Arrow end marker")
    require(result == expected, "CTE aggregation, window rank, exact decimal, date or nullable segment changed")
    encoded = json.dumps(result, default=str, sort_keys=True, separators=(",", ":")).encode()
    return {"rows": len(result), "canonical_sha256": hashlib.sha256(encoded).hexdigest()}, schema


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("direct-cte", "rabbit-cte", "direct-rows", "rabbit-rows"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    report = {"pyarrow_version": pa.__version__, "all_values_checked": True, "complete_eos_checked": True}
    for workflow, checker in (("cte", check_cte), ("rows", check_rows)):
        direct, direct_schema = checker(getattr(args, "direct_" + workflow))
        rabbit, rabbit_schema = checker(getattr(args, "rabbit_" + workflow))
        require(direct_schema.equals(rabbit_schema, check_metadata=True), f"{workflow}: direct/Rabbit schemas differ")
        require(direct["canonical_sha256"] == rabbit["canonical_sha256"], f"{workflow}: direct/Rabbit values differ")
        report[workflow] = {"direct": direct, "rabbit": rabbit, "equal": True}
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
