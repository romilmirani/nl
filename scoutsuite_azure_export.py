#!/usr/bin/env python3
"""Export flagged items from ScoutSuite Azure 5.x JS or JSON results."""

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory


JS_HEADER = re.compile(r"^(?:(?:var|let|const)\s+)?scoutsuite_results\s*=\s*")
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


def load_report(path):
    payload = path.read_text(encoding="utf-8-sig").strip()
    payload = JS_HEADER.sub("", payload, count=1).removesuffix(";")
    report = json.loads(payload)
    if not isinstance(report, dict) or not isinstance(report.get("services"), dict):
        raise ValueError("Expected a ScoutSuite report with a services object")
    if report.get("provider_code") != "azure":
        raise ValueError("Expected an Azure report with provider_code set to azure")
    return report


def matching_nodes(node, parts, template):
    """Return objects at the flagged resource path, excluding report UI suffixes."""
    if not template:
        return [(node, parts)]
    if not parts:
        return None

    field, *remaining = template
    if isinstance(node, list):
        index = parts[0]
        if index.isascii() and index.isdecimal() and int(index) < len(node):
            child = matching_nodes(node[int(index)], parts[1:], template)
            if child is not None:
                return [(node, parts)] + child

    if isinstance(node, dict):
        # Some resource keys contain dots, for example a firewall rule ARM ID.
        lengths = range(len(parts) - len(remaining), 0, -1) if field == "id" else (1,)
        for size in lengths:
            key = ".".join(parts[:size])
            if key in node and (field == "id" or key == field):
                child = matching_nodes(node[key], parts[size:], remaining)
                if child is not None:
                    return [(node, parts)] + child
    return None


def label(node):
    if isinstance(node, dict):
        for key in ("resource_id", "id", "name", "display_name", "displayName"):
            value = node.get(key)
            if isinstance(value, str) and value.startswith("/"):
                return value
        for key in ("name", "display_name", "displayName", "id"):
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return ""


def asset_for(services, service, finding, item):
    path = item.removeprefix("services.")
    template = finding.get("path", "").removeprefix("services.").split(".")
    nodes = matching_nodes(services, path.split("."), template)
    match = SUBSCRIPTION.search(path) if path.startswith(f"{service}.subscriptions.") else None
    subscription = match.group(1) if match else ""

    if not subscription:
        subscription = "Tenant-wide" if service == "aad" else "Unknown"

    if nodes is None:
        return subscription, path, path

    # Include ancestor names for child resources whose names are only locally unique.
    names = []
    resource_group = ""
    for node, _ in nodes:
        name = label(node)
        if name and name != subscription and (not names or name != names[-1]):
            names.append(name)
        if isinstance(node, dict) and isinstance(node.get("resource_group_name"), str):
            resource_group = node["resource_group_name"]

    resource, suffix = nodes[-1]
    target = path
    if suffix:
        target = ".".join(path.split(".")[:-len(suffix)])
    if not label(resource) and len(nodes) > 1:
        # Keep the exact child key when ScoutSuite supplies no resource name.
        child_parts = nodes[-2][1]
        key_size = len(child_parts) - len(suffix)
        names.append(".".join(child_parts[:key_size]))
    asset = " / ".join(names) if names else target
    if resource_group and not any(name.startswith("/") for name in names):
        asset = f"{asset} (Resource group: {resource_group})"
    return subscription, asset, target


def report_rows(report):
    services = report["services"]
    for service, config in services.items():
        if not isinstance(config, dict):
            continue
        findings = config.get("findings", {})
        if not isinstance(findings, dict):
            raise ValueError(f"{service} has an invalid findings object")
        for rule_id, finding in findings.items():
            if not isinstance(finding, dict) or not isinstance(finding.get("path", ""), str):
                raise ValueError(f"{service}/{rule_id} has an invalid finding object")
            items = finding.get("items", [])
            if not isinstance(items, list) or any(not isinstance(item, str) or not item for item in items):
                raise ValueError(f"{service}/{rule_id} has invalid finding items")
            if not items and finding.get("flagged_items", 0):
                raise ValueError(f"{service}/{rule_id} has a flagged count but no item paths")
            title = finding.get("description") or rule_id
            if not isinstance(title, str):
                raise ValueError(f"{service}/{rule_id} has an invalid description")
            for item in items:
                subscription, asset, target = asset_for(services, service, finding, item)
                identity = (report.get("account_id"), service, rule_id, subscription, target)
                yield identity, title, f"Subscription ID: {subscription} Affected Asset: {asset}"


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
            grouped = defaultdict(list)
            for title, asset in sorted(rows, key=lambda row: (row[0].casefold(), row[1].casefold(), row)):
                writer.writerow([csv_cell(title), csv_cell(asset)])
                grouped[title].append(asset)
            for title, assets in grouped.items():
                txt_file.write(f"Finding: {title}\n")
                txt_file.writelines(f"{asset}\n" for asset in assets)
                txt_file.write("\n")
            if not grouped:
                txt_file.write("No flagged findings.\n")
        for name in (csv_name, txt_name):
            (staging / name).replace(output_dir / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="Results files or directories to scan recursively")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("azure_export"),
                        help="Destination for both exports (default: azure_export)")
    args = parser.parse_args()

    try:
        files = result_files(args.inputs)
        findings = {}
        for path in files:
            try:
                for identity, title, asset in report_rows(load_report(path)):
                    findings[identity] = (title, asset)
            except (OSError, ValueError) as exc:
                raise ValueError(f"{path}: {exc}") from exc
        export(findings.values(), args.output_dir)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Exported {len(findings)} finding/asset rows from {len(files)} result file(s) to {args.output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
