#!/usr/bin/env python3
"""
Author: Magnus Glantz, sudo @ redhat.com, 2026

Identify orphan configuration items in Ansible Automation Platform 2.4.

Read-only. Queries the controller API, classifies configuration items as
orphan (unused or unreferenced) and emits a CSV listing them. Does NOT
delete or modify anything.

Designed as a pre-migration cleanup helper: shows you what cruft is worth
purging before the database is carried through a 2.4 → 2.6 upgrade.

Entity types covered:
  - credential              not referenced by any project, JT, inventory
                            source, or workflow node
  - notification_template   not attached to any JT, project, workflow, or org
  - project                 not referenced by any JT (project field), workflow
                            node / schedule (UJT-level reference), or
                            inventory source (source_project)
  - job_template            unreferenced (not in any workflow or schedule)
                            AND last run is older than --stale-days, or
                            never run if --include-never-run is set
  - workflow_job_template   unreferenced (not in any workflow or schedule)
                            AND last run is older than --stale-days, or
                            never run if --include-never-run is set

Auth: bearer token in CONTROLLER_TOKEN env var (or --token).
Host: CONTROLLER_HOST env var (or --host), e.g. https://controller.example.com

Tested against AAP 2.4 controller API (/api/v2/...). For AAP 2.6 through the
platform gateway, pass --api-prefix /api/controller/v2.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Iterator

import requests
import urllib3


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------

def iter_endpoint(session: requests.Session, base_url: str, api_prefix: str,
                  endpoint: str, query: str = "") -> Iterator[dict]:
    """Yield every record from a paginated AAP list endpoint."""
    suffix = "?page_size=200&order_by=id"
    if query:
        suffix += f"&{query}"
    url = f"{base_url}{api_prefix}/{endpoint}/{suffix}"
    while url:
        r = session.get(url, timeout=30)
        r.raise_for_status()
        payload = r.json()
        for item in payload.get("results", []):
            yield item
        next_path = payload.get("next")
        url = f"{base_url}{next_path}" if next_path else None


def fetch_all(session: requests.Session, base_url: str, api_prefix: str,
              endpoint: str, query: str = "") -> list[dict]:
    return list(iter_endpoint(session, base_url, api_prefix, endpoint, query))


def org_name(record: dict) -> str:
    return (record.get("summary_fields", {})
                  .get("organization", {})
                  .get("name") or "(no organization)")


def parse_iso8601(value: str | None) -> datetime | None:
    """Parse an AAP ISO-8601 timestamp; return None if missing/unparseable."""
    if not value:
        return None
    try:
        # AAP emits e.g. '2024-08-21T14:23:01.234567Z'
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Build usage sets (reverse-reference index across all cached entities)
# ---------------------------------------------------------------------------

def build_usage_sets(caches: dict[str, list[dict]]) -> dict[str, set[int]]:
    """Walk every cached entity, build per-type sets of referenced IDs.

    AAP's UnifiedJobTemplate base class means JobTemplate, WorkflowJobTemplate,
    Project, and InventorySource all share the same ID space. Workflow nodes
    and schedules can reference any of them via 'unified_job_template'. We
    populate both used['unified_job_template'] (for the JT/WFJT orphan checks)
    and used['project'] (for the project orphan check) from those references,
    which is safe because the IDs are unique across all UJT subtypes.
    """
    used = {
        "credential": set(),
        "project": set(),
        "unified_job_template": set(),
        "notification_template": set(),
    }

    NT_FIELDS = (
        "notification_templates_started",
        "notification_templates_success",
        "notification_templates_error",
        "notification_templates_approvals",
    )

    # Projects -> credentials, notification_templates
    for p in caches.get("projects", []):
        if p.get("credential"):
            used["credential"].add(p["credential"])
        for fld in NT_FIELDS:
            for nt_id in p.get(fld) or []:
                used["notification_template"].add(nt_id)

    # Job templates -> credentials, projects, notification_templates
    for jt in caches.get("job_templates", []):
        if jt.get("project"):
            used["project"].add(jt["project"])
        for cred in jt.get("summary_fields", {}).get("credentials") or []:
            if cred.get("id"):
                used["credential"].add(cred["id"])
        for fld in NT_FIELDS:
            for nt_id in jt.get(fld) or []:
                used["notification_template"].add(nt_id)

    # Workflow job templates -> notification_templates
    for wf in caches.get("workflow_job_templates", []):
        for fld in NT_FIELDS:
            for nt_id in wf.get(fld) or []:
                used["notification_template"].add(nt_id)

    # Inventory sources -> credentials, projects (via source_project),
    # notification_templates
    for s in caches.get("inventory_sources", []):
        if s.get("credential"):
            used["credential"].add(s["credential"])
        if s.get("source_project"):
            used["project"].add(s["source_project"])
        for fld in NT_FIELDS:
            for nt_id in s.get(fld) or []:
                used["notification_template"].add(nt_id)

    # Workflow nodes -> any UJT (could be JT, WFJT, project, inv source),
    # plus credentials
    for wn in caches.get("workflow_job_template_nodes", []):
        ujt = wn.get("unified_job_template")
        if ujt:
            used["unified_job_template"].add(ujt)
            # Same ID may belong to a project — populate that set too so the
            # project orphan check sees the workflow-level reference.
            used["project"].add(ujt)
        for cred in wn.get("summary_fields", {}).get("credentials") or []:
            if cred.get("id"):
                used["credential"].add(cred["id"])

    # Schedules can target a JT, WFJT, project, or inventory source via UJT
    for s in caches.get("schedules", []):
        ujt = s.get("unified_job_template")
        if ujt:
            used["unified_job_template"].add(ujt)
            used["project"].add(ujt)

    # Organizations -> notification_templates
    for o in caches.get("organizations", []):
        for fld in NT_FIELDS:
            for nt_id in o.get(fld) or []:
                used["notification_template"].add(nt_id)

    return used


# ---------------------------------------------------------------------------
# Per-entity orphan finders
# ---------------------------------------------------------------------------

def find_orphan_credentials(caches, used) -> list[dict]:
    out = []
    for c in caches.get("credentials", []):
        if c["id"] in used["credential"]:
            continue
        ct_name = (c.get("summary_fields", {})
                    .get("credential_type", {})
                    .get("name") or "")
        out.append({
            "entity_type": "credential",
            "entity_id": c["id"],
            "entity_name": c.get("name", ""),
            "organization": org_name(c),
            "reasons": "not_referenced",
            "modified": c.get("modified", ""),
            "notes": f"type={ct_name}",
        })
    return out


def find_orphan_notification_templates(caches, used) -> list[dict]:
    out = []
    for nt in caches.get("notification_templates", []):
        if nt["id"] in used["notification_template"]:
            continue
        out.append({
            "entity_type": "notification_template",
            "entity_id": nt["id"],
            "entity_name": nt.get("name", ""),
            "organization": org_name(nt),
            "reasons": "not_attached",
            "modified": nt.get("modified", ""),
            "notes": f"type={nt.get('notification_type','')}",
        })
    return out


def find_orphan_projects(caches, used) -> list[dict]:
    """Projects with no JT, no workflow node / schedule, and no inventory
    source connecting to them. used['project'] is the union of all of those."""
    out = []
    for p in caches.get("projects", []):
        if p["id"] in used["project"]:
            continue
        out.append({
            "entity_type": "project",
            "entity_id": p["id"],
            "entity_name": p.get("name", ""),
            "organization": org_name(p),
            "reasons": "no_jt_no_workflow_no_inventory_source",
            "modified": p.get("modified", ""),
            "notes": (f"scm_type={p.get('scm_type') or 'manual'} "
                      f"scm_url={p.get('scm_url') or ''}"),
        })
    return out


def _orphan_ujt(record: dict, used: dict, entity_type: str,
                stale_days: int | None, include_never_run: bool,
                now: datetime) -> dict | None:
    """Shared orphan logic for job templates and workflow job templates."""
    in_use = record["id"] in used["unified_job_template"]
    last_run = parse_iso8601(record.get("last_job_run"))

    reasons = []
    if not in_use and not last_run and include_never_run:
        reasons.append("never_run_and_unreferenced")
    elif not in_use and stale_days is not None and last_run \
            and (now - last_run) > timedelta(days=stale_days):
        reasons.append(f"stale_>{stale_days}d_and_unreferenced")
    if not reasons:
        return None

    return {
        "entity_type": entity_type,
        "entity_id": record["id"],
        "entity_name": record.get("name", ""),
        "organization": org_name(record),
        "reasons": ";".join(reasons),
        "modified": record.get("modified", ""),
        "notes": f"last_job_run={record.get('last_job_run') or 'never'}",
    }


def find_orphan_job_templates(caches, used, stale_days,
                              include_never_run, now) -> list[dict]:
    out = []
    for jt in caches.get("job_templates", []):
        rec = _orphan_ujt(jt, used, "job_template",
                          stale_days, include_never_run, now)
        if rec:
            out.append(rec)
    return out


def find_orphan_workflow_job_templates(caches, used, stale_days,
                                       include_never_run, now) -> list[dict]:
    out = []
    for wf in caches.get("workflow_job_templates", []):
        rec = _orphan_ujt(wf, used, "workflow_job_template",
                          stale_days, include_never_run, now)
        if rec:
            out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# (cache key, endpoint path) — fetched as caches[key] = fetch_all(endpoint)
CACHE_ENDPOINTS = [
    ("organizations", "organizations"),
    ("credentials", "credentials"),
    ("projects", "projects"),
    ("inventory_sources", "inventory_sources"),
    ("job_templates", "job_templates"),
    ("workflow_job_templates", "workflow_job_templates"),
    ("workflow_job_template_nodes", "workflow_job_template_nodes"),
    ("schedules", "schedules"),
    ("notification_templates", "notification_templates"),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default=os.environ.get("CONTROLLER_HOST"),
                        help="Controller base URL (CONTROLLER_HOST env var)")
    parser.add_argument("--token", default=os.environ.get("CONTROLLER_TOKEN"),
                        help="OAuth2 bearer token (CONTROLLER_TOKEN env var)")
    parser.add_argument("--api-prefix", default="/api/v2",
                        help="API path prefix (default: /api/v2; use "
                             "/api/controller/v2 for AAP 2.6 via gateway)")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification entirely "
                             "(accepts any cert, including self-signed)")
    parser.add_argument("--ca-bundle", default=os.environ.get("CONTROLLER_CA_BUNDLE"),
                        help="Path to a CA bundle (PEM) to trust. "
                             "Env: CONTROLLER_CA_BUNDLE")
    parser.add_argument("--stale-days", type=int, default=None,
                        help="Flag JTs/WFJTs that are unreferenced AND whose "
                             "last run is older than N days. Templates with "
                             "no run at all are ignored unless "
                             "--include-never-run is set.")
    parser.add_argument("--include-never-run", action="store_true",
                        help="Also flag JTs/WFJTs that are unreferenced AND "
                             "have never been run. Off by default since new "
                             "or recently-created templates legitimately "
                             "have no run yet.")
    parser.add_argument("--types", default="",
                        help="Comma-separated list of entity types to check. "
                             "Defaults to all. Choices: credential, "
                             "notification_template, project, job_template, "
                             "workflow_job_template")
    parser.add_argument("--output", "-o", default="orphan_items.csv",
                        help="Output CSV path (default: orphan_items.csv)")
    args = parser.parse_args()

    if not args.host or not args.token:
        sys.stderr.write(
            "ERROR: --host and --token are required "
            "(or set CONTROLLER_HOST / CONTROLLER_TOKEN)\n"
        )
        return 2

    selected_types = (
        {t.strip() for t in args.types.split(",") if t.strip()}
        if args.types else None
    )

    base_url = args.host.rstrip("/")
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {args.token}",
        "Accept": "application/json",
    })
    if args.insecure:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    elif args.ca_bundle:
        if not os.path.isfile(args.ca_bundle):
            sys.stderr.write(f"ERROR: CA bundle not found: {args.ca_bundle}\n")
            return 2
        session.verify = args.ca_bundle

    # Fetch all caches up front. Memory cost is fine for typical AAP installs;
    # per-record filter queries would burn through rate limits otherwise.
    caches: dict[str, list[dict]] = {}
    try:
        for key, endpoint in CACHE_ENDPOINTS:
            sys.stderr.write(f"Fetching {endpoint}...")
            sys.stderr.flush()
            caches[key] = fetch_all(session, base_url, args.api_prefix, endpoint)
            sys.stderr.write(f" {len(caches[key])}\n")
    except requests.HTTPError as e:
        sys.stderr.write(f"\nERROR: API request failed: {e}\n")
        return 1
    except requests.RequestException as e:
        sys.stderr.write(f"\nERROR: connection problem: {e}\n")
        return 1

    used = build_usage_sets(caches)
    now = datetime.now(timezone.utc)

    # (type_label, finder callable returning list of orphan dicts)
    checks = [
        ("credential",
            lambda: find_orphan_credentials(caches, used)),
        ("notification_template",
            lambda: find_orphan_notification_templates(caches, used)),
        ("project",
            lambda: find_orphan_projects(caches, used)),
        ("job_template",
            lambda: find_orphan_job_templates(caches, used, args.stale_days,
                                              args.include_never_run, now)),
        ("workflow_job_template",
            lambda: find_orphan_workflow_job_templates(caches, used,
                                                       args.stale_days,
                                                       args.include_never_run,
                                                       now)),
    ]

    orphans: list[dict] = []
    for type_label, fn in checks:
        if selected_types is not None and type_label not in selected_types:
            continue
        orphans.extend(fn())

    orphans.sort(key=lambda r: (r["entity_type"], r["organization"],
                                r["entity_name"]))

    fieldnames = ["entity_type", "entity_id", "entity_name", "organization",
                  "reasons", "modified", "notes"]
    with open(args.output, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(orphans)

    by_type: dict[str, int] = {}
    for o in orphans:
        by_type[o["entity_type"]] = by_type.get(o["entity_type"], 0) + 1
    summary = ", ".join(f"{t}={n}" for t, n in sorted(by_type.items())) \
        or "none"
    sys.stderr.write(
        f"Found {len(orphans)} orphan items: {summary}. "
        f"Wrote {args.output}\n"
    )
    for row in orphans:
        print(f"{row['entity_type']}\t{row['organization']}\t"
              f"{row['entity_name']}\t{row['reasons']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
