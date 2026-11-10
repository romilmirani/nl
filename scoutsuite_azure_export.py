#!/usr/bin/env python3
"""Export flagged items from ScoutSuite Azure 5.x JS or JSON results."""

import argparse
import csv
import json
import re
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    import ijson
except ImportError:
    ijson = None


JS_HEADER = re.compile(rb"^(?:(?:var|let|const)\s+)?scoutsuite_results\s*=\s*")
SUBSCRIPTION = re.compile(r"(?:\.subscriptions\.|/subscriptions/)([^./]+)", re.I)


def result_files(inputs):
    files = set()
    for path in inputs:
        if path.is_dir():
            matches = {
                file.resolve()
                for extension in ("js", "json")
                for file in path.rglob(f"scoutsuite_results*.{extension}")
                if file.is_file()
            }
            if not matches:
                raise ValueError(f"No ScoutSuite results found in {path}")
            files.update(matches)
        elif path.is_file():
            files.add(path.resolve())
        else:
            raise ValueError(f"Input does not exist: {path}")
    return sorted(files)


class JSONPayload:
    """Expose the JSON bytes inside a ScoutSuite JS file without copying them."""

    def __init__(self, file):
        self.file = file
        header = file.read(4096)
        if header.startswith(b"\xef\xbb\xbf"):
            header = header[3:]
            offset = 3
        else:
            offset = 0
        leading = len(header) - len(header.lstrip())
        match = JS_HEADER.match(header.lstrip())
        start = offset + leading + (match.end() if match else 0)

        end = file.seek(0, 2)
        while end > start:
            block_start = max(start, end - 4096)
            file.seek(block_start)
            block = file.read(end - block_start).rstrip()
            if block:
                end = block_start + len(block) - int(block.endswith(b";"))
                break
            end = block_start
        self.end = end
        file.seek(start)

    def read(self, size):
        return self.file.read(max(0, min(size, self.end - self.file.tell())))


def stream_nodes(path):
    """Yield real JSON paths, preserving dots inside individual object keys."""
    with path.open("rb") as file:
        stack = []
        for event, value in ijson.basic_parse(JSONPayload(file)):
            if event == "map_key":
                stack[-1][1] = value
            elif event in ("end_map", "end_array"):
                stack.pop()
            else:
                if stack:
                    parent, key = stack[-1]
                    parts = (*parent, key)
                    if isinstance(key, int):
                        stack[-1][1] += 1
                else:
                    parts = ()
                if event == "start_map":
                    stack.append([parts, None])
                elif event == "start_array":
                    stack.append([parts, 0])
                yield parts, event, value


def create_index(db):
    db.executescript("""
        PRAGMA cache_size = -8192;
        PRAGMA temp_store = FILE;
        CREATE TABLE rules (
            service TEXT, rule TEXT, description TEXT, template TEXT, flagged INTEGER,
            PRIMARY KEY (service, rule)
        );
        CREATE TABLE items (
            service TEXT, rule TEXT, path TEXT, PRIMARY KEY (service, rule, path)
        );
        CREATE TABLE wanted (path TEXT PRIMARY KEY);
        CREATE TABLE nodes (path TEXT PRIMARY KEY, kind TEXT, fields TEXT DEFAULT '{}');
        CREATE TABLE output (
            tenant TEXT, service TEXT, rule TEXT, subscription TEXT, target TEXT,
            title TEXT, asset TEXT,
            PRIMARY KEY (tenant, service, rule, subscription, target)
        );
    """)


def index_findings(db, path):
    provider = tenant = None
    has_services = False
    rule_fields = {
        "description": ("description", "string"),
        "path": ("template", "string"),
        "flagged_items": ("flagged", "number"),
    }
    for parts, event, value in stream_nodes(path):
        if parts == ("provider_code",):
            provider = value
        elif parts == ("account_id",):
            tenant = value
        elif parts == ("services",):
            has_services = event == "start_map"
        elif len(parts) >= 3 and parts[0] == "services" and parts[2] == "findings":
            service = parts[1]
            if len(parts) == 3:
                if event != "start_map":
                    raise ValueError(f"{service} has an invalid findings object")
                continue
            rule = parts[3]
            if len(parts) == 4:
                if event != "start_map":
                    raise ValueError(f"{service}/{rule} has an invalid finding object")
                db.execute("INSERT INTO rules (service, rule) VALUES (?, ?)", (service, rule))
            elif len(parts) == 5:
                field = parts[4]
                if field in rule_fields:
                    column, expected = rule_fields[field]
                    if event == expected:
                        db.execute(f"UPDATE rules SET {column} = ? WHERE service = ? AND rule = ?",
                                   (value, service, rule))
                    elif event != "null":
                        raise ValueError(f"{service}/{rule} has an invalid {field}")
                elif field == "items" and event != "start_array":
                    raise ValueError(f"{service}/{rule} has invalid finding items")
            elif len(parts) == 6 and parts[4] == "items":
                if event != "string" or not value:
                    raise ValueError(f"{service}/{rule} has invalid finding items")
                item = value.removeprefix("services.")
                db.execute("INSERT OR IGNORE INTO items VALUES (?, ?, ?)", (service, rule, item))

    if not has_services or provider != "azure":
        raise ValueError("Expected an Azure ScoutSuite report with a services object")
    missing = db.execute("""
        SELECT service, rule FROM rules r WHERE flagged > 0 AND NOT EXISTS (
            SELECT 1 FROM items i WHERE i.service = r.service AND i.rule = r.rule
        ) LIMIT 1
    """).fetchone()
    if missing:
        raise ValueError(f"{missing[0]}/{missing[1]} has a flagged count but no item paths")

    for (item,) in db.execute("SELECT DISTINCT path FROM items"):
        parts = item.split(".")
        db.executemany("INSERT OR IGNORE INTO wanted VALUES (?)",
                       ((".".join(parts[:size]),) for size in range(1, len(parts) + 1)))
    return tenant if isinstance(tenant, str) else ""


ASSET_FIELDS = {
    "resource_id", "id", "name", "display_name", "displayName"
}


def index_resources(db, path):
    # A path and its metadata stay in memory only while its JSON subtree is open.
    active = {}
    for parts, event, value in stream_nodes(path):
        if not parts or parts[0] != "services" or len(parts) < 2:
            continue
        parts = parts[1:]
        while active:
            last = next(reversed(active))
            if last == parts[:len(last)]:
                break
            key, (kind, fields) = active.popitem()
            db.execute("INSERT INTO nodes VALUES (?, ?, ?)",
                       (json.dumps(key), kind, json.dumps(fields)))
        parent = active.get(parts[:-1])
        if parent and event == "string" and parts[-1] in ASSET_FIELDS:
            parent[1][parts[-1]] = value
        if len(parts) > 1 and parts[:-1] not in active:
            continue
        dotted = ".".join(map(str, parts))
        if db.execute("SELECT 1 FROM wanted WHERE path = ?", (dotted,)).fetchone():
            active[parts] = (event, {})

    for key, (kind, fields) in active.items():
        db.execute("INSERT INTO nodes VALUES (?, ?, ?)", (json.dumps(key), kind, json.dumps(fields)))


def matching_nodes(db, parts, template, key=(), kind="start_map", fields=None):
    """Return indexed ancestors up to the rule target, excluding UI suffixes."""
    node = fields, key
    if not template:
        return [node]
    if not parts:
        return None

    field, *remaining = template
    if kind == "start_array":
        candidates = [(int(parts[0]), 1, template)] if parts[0].isascii() and parts[0].isdecimal() else []
    elif kind == "start_map" and field == "id":
        candidates = [(".".join(parts[:size]), size, remaining)
                      for size in range(len(parts) - len(remaining), 0, -1)]
    elif kind == "start_map" and parts[0] == field:
        candidates = [(field, 1, remaining)]
    else:
        candidates = []

    for name, size, rest in candidates:
        child_key = (*key, name)
        child = db.execute("SELECT kind, fields FROM nodes WHERE path = ?",
                           (json.dumps(child_key),)).fetchone()
        if child:
            result = matching_nodes(db, parts[size:], rest, child_key, child[0],
                                    json.loads(child[1]) if child[0] == "start_map" else None)
            if result is not None:
                return [node] + result
    return None


def label(node):
    if isinstance(node, dict):
        for key in ("name", "display_name", "displayName", "resource_id", "id"):
            value = node.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            if value.startswith("/"):
                parts = value.strip("/").split("/")
                if len(parts) > 2 and "providers" in (part.lower() for part in parts):
                    return parts[-1]
            elif key in ("name", "display_name", "displayName"):
                return value.strip()
    return ""


CONFIGURATION_CHILDREN = {
    "blob_services", "firewall_rules", "postgresql_firewall_rules",
    "security_rules", "default_security_rules",
}


def asset_for(db, service, template, path):
    rule_path = template.removeprefix("services.").split(".")
    nodes = matching_nodes(db, path.split("."), rule_path)
    match = SUBSCRIPTION.search(path) if path.startswith(f"{service}.subscriptions.") else None
    subscription = match.group(1) if match else ""

    if not subscription:
        subscription = "Tenant-wide" if service == "aad" else "Unknown"

    if nodes is None:
        return subscription, "Name unavailable", path

    # These child objects describe settings on their owning Azure resource.
    for index, field in enumerate(rule_path):
        if field in CONFIGURATION_CHILDREN:
            nodes = nodes[:index + 1]
            break

    fields, key = nodes[-1]
    name = label(fields)
    if not name and key and isinstance(key[-1], str):
        name = label({"id": key[-1]})
    return subscription, name or "Name unavailable", json.dumps(key)


def process_report(db, path):
    tenant = index_findings(db, path)
    if db.execute("SELECT 1 FROM items LIMIT 1").fetchone():
        index_resources(db, path)

    for service, rule, item, description, template in db.execute("""
        SELECT i.service, i.rule, i.path, r.description, r.template
        FROM items i JOIN rules r USING (service, rule)
    """):
        subscription, asset, target = asset_for(db, service, template or "", item)
        db.execute("INSERT OR REPLACE INTO output VALUES (?, ?, ?, ?, ?, ?, ?)", (
            tenant, service, rule, subscription, target, description or rule,
            asset,
        ))
    db.executescript("DELETE FROM rules; DELETE FROM items; DELETE FROM wanted; DELETE FROM nodes;")


def csv_cell(value):
    # Prevent formula evaluation when a report field is opened in a spreadsheet.
    if value.startswith(("\t", "\r", "\n")) or value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def export(rows, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_name = "azure_findings.csv"
    txt_name = "azure_findings.txt"
    with TemporaryDirectory(dir=output_dir) as directory:
        staging = Path(directory)
        with (staging / csv_name).open("w", encoding="utf-8-sig", newline="") as csv_file, (
            staging / txt_name
        ).open("w", encoding="utf-8") as txt_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Finding", "Affected Asset"])
            previous = None
            for title, asset in rows:
                writer.writerow([csv_cell(title), csv_cell(asset)])
                if title != previous:
                    if previous is not None:
                        txt_file.write("\n")
                    txt_file.write(f"Finding: {title}\n")
                    previous = title
                txt_file.write(f"{asset}\n")
            if previous is None:
                txt_file.write("No flagged findings.\n")
            else:
                txt_file.write("\n")
        for name in (csv_name, txt_name):
            (staging / name).replace(output_dir / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="Results files or directories to scan recursively")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("azure_export"),
                        help="Destination for both exports (default: azure_export)")
    args = parser.parse_args()

    if ijson is None:
        parser.exit(1, "Missing ijson. On Kali, install it with sudo apt install python3-ijson.\n")

    try:
        files = result_files(args.inputs)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=args.output_dir) as directory, closing(
            sqlite3.connect(Path(directory) / "index.sqlite")
        ) as db:
            create_index(db)
            for path in files:
                print(f"Processing {path}", file=sys.stderr, flush=True)
                try:
                    process_report(db, path)
                except (OSError, ValueError, ijson.JSONError, sqlite3.Error) as exc:
                    raise ValueError(f"{path}: {exc}") from exc
            count = db.execute("SELECT count(*) FROM output").fetchone()[0]
            export(db.execute("""
                SELECT title, asset FROM output
                ORDER BY title COLLATE NOCASE, title, asset COLLATE NOCASE, asset
            """), args.output_dir)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Exported {count} finding/asset rows from {len(files)} result file(s) to {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
