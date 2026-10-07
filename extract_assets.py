import json
import sys
import os
import glob
import csv
from collections import defaultdict


def load_scoutsuite(filename):
    """
    Load a ScoutSuite JavaScript results file.

    ScoutSuite files normally contain:
        scoutsuite_results = {...}

    This function extracts the JSON portion without modifying
    the original file.
    """

    with open(filename, "r", encoding="utf-8") as f:
        content = f.read().strip()

    first_brace = content.find("{")

    if first_brace == -1:
        raise ValueError("Could not locate JSON data in file")

    content = content[first_brace:].rstrip()

    # Remove trailing semicolon if present
    if content.endswith(";"):
        content = content[:-1]

    return json.loads(content)


def resolve_path(data, item_path):
    """
    Resolve a ScoutSuite finding item path.

    Example:
        computeengine.projects.project1.firewalls.12345.allowed_traffic...

    Returns:
        The deepest successfully resolved dictionary.
    """

    parts = item_path.split(".")
    current = data.get("services", {})

    deepest_object = None

    for part in parts:

        if isinstance(current, dict) and part in current:
            current = current[part]

            if isinstance(current, dict):
                deepest_object = current

        else:
            break

    return deepest_object


def recursive_find_resource(obj, resource_id):
    """
    Recursively search ScoutSuite data for a dictionary stored
    under resource_id.

    This is useful when an item path contains an internal
    ScoutSuite/GCP resource ID but the human-readable name
    exists elsewhere in the result structure.
    """

    if isinstance(obj, dict):

        if resource_id in obj:
            candidate = obj[resource_id]

            if isinstance(candidate, dict):
                return candidate

        for value in obj.values():

            if isinstance(value, (dict, list)):
                result = recursive_find_resource(value, resource_id)

                if result is not None:
                    return result

    elif isinstance(obj, list):

        for value in obj:

            if isinstance(value, (dict, list)):
                result = recursive_find_resource(value, resource_id)

                if result is not None:
                    return result

    return None


def extract_name_from_object(obj):
    """
    Extract a useful human-readable asset identifier
    from a ScoutSuite resource object.
    """

    if not isinstance(obj, dict):
        return None

    preferred_fields = [
        "name",
        "display_name",
        "instance_name",
        "bucket_name",
        "database_id",
        "cluster_name",
        "topic_name",
        "subscription_name",
        "email",
        "username",
        "role",
        "id"
    ]

    for field in preferred_fields:

        value = obj.get(field)

        if value is not None and value != "":
            return str(value)

    return None


def get_candidate_resource_ids(item_path):
    """
    Extract likely resource identifiers from a ScoutSuite
    item path.

    Example:

        computeengine.projects.project1.firewalls.12345.allowed_traffic

    Candidate resource ID:
        12345
    """

    parts = item_path.split(".")

    resource_collections = {
        "firewalls",
        "instances",
        "networks",
        "subnetworks",
        "snapshots",
        "managed_zones",
        "buckets",
        "databases",
        "clusters",
        "topics",
        "subscriptions",
        "service_accounts",
        "users",
        "roles",
        "keys",
        "global_forwarding_rules",
        "forwarding_rules",
        "addresses",
        "disks",
        "images",
        "functions",
        "datasets",
        "tables",
        "secrets",
        "repositories"
    }

    candidates = []

    for index, part in enumerate(parts):

        if (
            part in resource_collections
            and index + 1 < len(parts)
        ):
            candidates.append(parts[index + 1])

    return candidates


def get_asset_name(data, item_path):
    """
    Determine the human-readable affected asset for a
    ScoutSuite finding.
    """

    # -----------------------------------------------------
    # Method 1:
    # Follow the exact ScoutSuite path.
    # -----------------------------------------------------

    resolved_object = resolve_path(data, item_path)

    name = extract_name_from_object(resolved_object)

    if name:
        return name

    # -----------------------------------------------------
    # Method 2:
    # Find resource IDs in the item path and locate the
    # corresponding resource object elsewhere in the data.
    #
    # Work backwards so the most specific resource wins.
    # -----------------------------------------------------

    candidates = get_candidate_resource_ids(item_path)

    for resource_id in reversed(candidates):

        resource = recursive_find_resource(
            data.get("services", {}),
            resource_id
        )

        name = extract_name_from_object(resource)

        if name:
            return name

    # -----------------------------------------------------
    # Method 3:
    # If the resource object cannot be resolved, return the
    # most specific resource identifier from the path.
    # -----------------------------------------------------

    if candidates:
        return candidates[-1]

    # -----------------------------------------------------
    # Final fallback:
    # Keep the original ScoutSuite path so that evidence
    # isn't silently discarded.
    # -----------------------------------------------------

    return item_path


def process_file(filename, findings):
    """
    Process one ScoutSuite result file.
    """

    try:
        data = load_scoutsuite(filename)

    except Exception as e:
        print(f"[!] Failed to process:")
        print(f"    {filename}")
        print(f"    Reason: {e}")
        print()
        return

    project_id = data.get(
        "account_id",
        "UNKNOWN_PROJECT"
    )

    print(f"[+] Processing: {project_id}")

    services = data.get("services", {})

    if not isinstance(services, dict):
        return

    for service_name, service_data in services.items():

        if not isinstance(service_data, dict):
            continue

        service_findings = service_data.get(
            "findings",
            {}
        )

        if not isinstance(service_findings, dict):
            continue

        for finding_id, finding in service_findings.items():

            if not isinstance(finding, dict):
                continue

            flagged_items = finding.get(
                "flagged_items",
                0
            )

            try:
                if int(flagged_items) <= 0:
                    continue
            except (ValueError, TypeError):
                continue

            description = finding.get(
                "description",
                finding_id
            )

            items = finding.get("items", [])

            if not isinstance(items, list):
                continue

            for item in items:

                if not isinstance(item, str):
                    continue

                asset = get_asset_name(
                    data,
                    item
                )

                record = (
                    project_id,
                    asset
                )

                findings[description].add(record)


def write_txt(findings, filename):
    """
    Generate human-readable TXT report.
    """

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as f:

        for description in sorted(
            findings,
            key=str.lower
        ):

            f.write("=" * 100 + "\n")
            f.write(
                f"Finding: {description}\n"
            )
            f.write("=" * 100 + "\n")

            records = sorted(
                findings[description],
                key=lambda x: (
                    str(x[0]).lower(),
                    str(x[1]).lower()
                )
            )

            for project_id, asset in records:

                f.write(
                    f"Project_ID: {project_id}    "
                    f"Affected_Asset: {asset}\n"
                )

            f.write("\n")


def write_csv(findings, filename):
    """
    Generate CSV report suitable for Excel.
    """

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Finding",
            "Project_ID",
            "Affected_Asset"
        ])

        for description in sorted(
            findings,
            key=str.lower
        ):

            records = sorted(
                findings[description],
                key=lambda x: (
                    str(x[0]).lower(),
                    str(x[1]).lower()
                )
            )

            for project_id, asset in records:

                writer.writerow([
                    description,
                    project_id,
                    asset
                ])


def main():

    if len(sys.argv) != 2:

        print()
        print("ScoutSuite GCP Findings Consolidator")
        print()
        print("Usage:")
        print(
            "  python extract_all_assets.py "
            "<scoutsuite-results-directory>"
        )
        print()

        sys.exit(1)

    results_directory = os.path.abspath(
        sys.argv[1]
    )

    if not os.path.isdir(results_directory):

        print(
            f"[!] Directory does not exist: "
            f"{results_directory}"
        )

        sys.exit(1)

    # Search for all GCP ScoutSuite JS result files
    pattern = os.path.join(
        results_directory,
        "scoutsuite_results_gcp-*.js"
    )

    files = glob.glob(pattern)

    # If none are directly inside the supplied directory,
    # perform a recursive search as a fallback.
    if not files:

        recursive_pattern = os.path.join(
            results_directory,
            "**",
            "scoutsuite_results_gcp-*.js"
        )

        files = glob.glob(
            recursive_pattern,
            recursive=True
        )

    if not files:

        print()
        print(
            "[!] No ScoutSuite GCP result files "
            "were found."
        )
        print(
            f"[!] Searched: {results_directory}"
        )
        print()

        sys.exit(1)

    files = sorted(set(files))

    print()
    print(
        f"[+] Found {len(files)} "
        "ScoutSuite result file(s)."
    )
    print()

    findings = defaultdict(set)

    for filename in files:
        process_file(
            filename,
            findings
        )

    # Put output files in the directory from which
    # the script was executed.
    output_directory = os.getcwd()

    txt_output = os.path.join(
        output_directory,
        "consolidated_findings.txt"
    )

    csv_output = os.path.join(
        output_directory,
        "consolidated_findings.csv"
    )

    write_txt(
        findings,
        txt_output
    )

    write_csv(
        findings,
        csv_output
    )

    total_records = sum(
        len(records)
        for records in findings.values()
    )

    print()
    print("=" * 70)
    print("[+] Processing complete")
    print(
        f"[+] Findings: "
        f"{len(findings)}"
    )
    print(
        f"[+] Project/Asset records: "
        f"{total_records}"
    )
    print()
    print(
        f"[+] TXT: {txt_output}"
    )
    print(
        f"[+] CSV: {csv_output}"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()
