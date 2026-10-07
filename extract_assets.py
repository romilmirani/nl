import json
import sys


def load_scoutsuite(filename):
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read().strip()

    # Remove ScoutSuite JS variable assignment
    first_brace = content.find("{")
    if first_brace == -1:
        raise ValueError("Could not find JSON data in ScoutSuite file")

    content = content[first_brace:]

    # Remove trailing semicolon if present
    content = content.rstrip()
    if content.endswith(";"):
        content = content[:-1]

    return json.loads(content)


def resolve_path(data, item_path):
    """
    Follow a ScoutSuite finding item path and return the
    deepest dictionary reached along that path.
    """

    parts = item_path.split(".")

    # Finding paths normally start at services:
    # computeengine.projects....
    current = data.get("services", {})

    deepest_object = None
    deepest_path = []

    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]

            if isinstance(current, dict):
                deepest_object = current
                deepest_path.append(part)
        else:
            break

    return deepest_object


def get_asset_name(data, item_path):
    obj = resolve_path(data, item_path)

    if isinstance(obj, dict):
        # Preferred ScoutSuite/GCP identifiers
        for field in [
            "name",
            "display_name",
            "instance_name",
            "bucket_name",
            "database_id",
            "id"
        ]:
            value = obj.get(field)
            if value:
                return str(value)

    # Fallback: extract a useful identifier from the ScoutSuite path
    parts = item_path.split(".")

    # Try to return the value immediately after a known resource collection
    resource_types = {
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
        "keys",
        "global_forwarding_rules"
    }

    for i in range(len(parts) - 1, -1, -1):
        if parts[i] in resource_types and i + 1 < len(parts):
            return parts[i + 1]

    return item_path


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 extract_assets.py <scoutsuite_results.js>")
        sys.exit(1)

    filename = sys.argv[1]

    data = load_scoutsuite(filename)

    project_id = data.get("account_id", "UNKNOWN_PROJECT")

    services = data.get("services", {})

    for service_name, service_data in services.items():

        findings = service_data.get("findings", {})

        for finding_id, finding in findings.items():

            if finding.get("flagged_items", 0) <= 0:
                continue

            description = finding.get("description", finding_id)
            items = finding.get("items", [])

            if not items:
                continue

            print("=" * 100)
            print(f"Finding: {description}")
            print("=" * 100)

            seen = set()

            for item in items:
                asset = get_asset_name(data, item)

                result = (
                    f"Project_ID: {project_id} | "
                    f"Affected_Asset: {asset}"
                )

                if result not in seen:
                    print(result)
                    seen.add(result)

            print()


if __name__ == "__main__":
    main()
