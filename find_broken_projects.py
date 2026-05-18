#!/usr/bin/env python3
"""
Author: Magnus Glantz, sudo@®redhat.com, 2026

Identify likely-broken Ansible Automation Platform projects.

Read-only. Queries the controller API, classifies projects by failure signal,
and emits a CSV with project name, organization, and the reasons it was flagged.
Does NOT trigger any project syncs.

For projects whose most recent update failed, also fetches that update's stdout
and scans it for auth-error patterns (expired tokens, wrong creds, SSH key
problems, GitHub PAT-required, etc.). This adds specific reason tags like
'auth:token_expired' and a short excerpt from the matching line. Disable with
--no-auth-check if you don't want the extra API calls.

Tested against AAP 2.4 controller API (/api/v2/projects/). For AAP 2.6 through
the platform gateway, pass --api-prefix /api/controller/v2 and point --host
at the gateway URL.

To use this script export variables in your shell or pass as arguments.

Auth: bearer token in CONTROLLER_TOKEN env var (or --token).
Host: CONTROLLER_HOST env var (or --host), e.g. https://controller.example.com

Example use:
echo "CONTROLLER_HOST=https://aap24.example.com" >variables
echo "CONTROLLER_TOKEN=asdfasdflasdfj21231231231" >>variables
export $(cat variables|xargs)
./find_broken_projects.py --insecure
cat broken_projects.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from typing import Iterator

import requests
import urllib3

# Patterns scanned against project_update stdout, in priority order. The first
# matching pattern's tag is used to derive a short excerpt for the CSV; all
# matching tags are recorded in the reasons list.
AUTH_ERROR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Token-specific (highest signal for what the user asked about).
    (re.compile(r"token\s+(?:has\s+)?expired", re.I), "token_expired"),
    (re.compile(r"\bexpired token\b", re.I), "token_expired"),
    (re.compile(r"\btoken (?:is\s+)?invalid\b", re.I), "token_invalid"),
    (re.compile(r"support for password authentication was removed",
                re.I), "github_pat_required"),
    # Generic HTTPS auth.
    (re.compile(r"fatal:\s*authentication failed", re.I), "auth_failed"),
    (re.compile(r"https? basic:\s*access denied", re.I), "http_basic_denied"),
    (re.compile(r"\b401\s+unauthorized", re.I), "http_401"),
    (re.compile(r"\b403\s+forbidden", re.I), "http_403"),
    (re.compile(r"could not read username for", re.I), "no_credential_or_prompt"),
    (re.compile(r"terminal prompts disabled", re.I), "prompts_disabled"),
    (re.compile(r"invalid username or password", re.I), "invalid_credentials"),
    (re.compile(r"\bbad credentials\b", re.I), "bad_credentials"),
    # SSH.
    (re.compile(r"permission denied \(publickey", re.I), "ssh_publickey_denied"),
    (re.compile(r"host key verification failed", re.I), "ssh_hostkey_failed"),
    (re.compile(r"could not read from remote repository",
                re.I), "ssh_repo_unreadable"),
    # "Repo not found" on private repos is almost always an auth problem.
    (re.compile(r"repository (?:not found|does not exist)",
                re.I), "repo_not_found_or_auth"),
]


def iter_projects(session: requests.Session, base_url: str,
                  api_prefix: str) -> Iterator[dict]:
    """Yield every project record across paginated results."""
    url = f"{base_url}{api_prefix}/projects/?page_size=200&order_by=id"
    while url:
        r = session.get(url, timeout=30)
        r.raise_for_status()
        payload = r.json()
        for item in payload.get("results", []):
            yield item
        next_path = payload.get("next")
        url = f"{base_url}{next_path}" if next_path else None


def fetch_update_stdout(session: requests.Session, base_url: str,
                        api_prefix: str, update_id: int,
                        max_bytes: int) -> str:
    """Fetch a project_update's stdout as plain text, capped at max_bytes."""
    url = (f"{base_url}{api_prefix}/project_updates/{update_id}"
           f"/stdout/?format=txt")
    # Override session's Accept: application/json — the stdout endpoint does
    # content negotiation and returns 406 if Accept conflicts with format=txt.
    r = session.get(url, timeout=30, stream=True,
                    headers={"Accept": "text/plain, */*"})
    r.raise_for_status()
    buf: list[str] = []
    total = 0
    for chunk in r.iter_content(chunk_size=8192, decode_unicode=True):
        if not chunk:
            continue
        buf.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    r.close()
    return "".join(buf)


def classify(p: dict) -> list[str]:
    """Return broken-reason tags for a project record; empty means healthy."""
    reasons: list[str] = []
    status = (p.get("status") or "").lower()
    scm_type = p.get("scm_type") or ""  # empty => manual/local project
    scm_url = p.get("scm_url") or ""

    # Project directory missing on disk — always broken.
    if status == "missing":
        reasons.append("status=missing")

    # Terminal failure states from the last sync.
    if status in {"failed", "error", "canceled"}:
        reasons.append(f"status={status}")

    # Configured but never attempted a successful sync.
    if status == "never updated":
        reasons.append("status=never_updated")

    # Last sync attempt failed (orthogonal to current status — useful when a
    # project is "running" again after a failure but still suspect).
    if p.get("last_job_failed") is True:
        reasons.append("last_job_failed")

    # SCM project with no revision recorded => never produced usable content.
    if scm_type and not p.get("scm_revision"):
        reasons.append("no_scm_revision")

    # SCM project missing the URL it would need to sync.
    if scm_type and not scm_url:
        reasons.append("missing_scm_url")

    # SSH URL with no credential attached => can never authenticate.
    if scm_url and re.match(r"^(?:git@|ssh://)", scm_url) \
            and not p.get("credential"):
        reasons.append("ssh_url_no_credential")

    # Credential ID set but the related credential is gone => orphan reference.
    if p.get("credential") and not (
        p.get("summary_fields", {}).get("credential", {}).get("name")
    ):
        reasons.append("credential_orphaned")

    return reasons


def scan_auth_errors(stdout_text: str) -> tuple[list[str], str]:
    """Scan stdout for auth-error patterns.

    Returns (sorted unique tags prefixed 'auth:', short excerpt of first match).
    """
    tags: set[str] = set()
    first_excerpt = ""
    for pattern, tag in AUTH_ERROR_PATTERNS:
        m = pattern.search(stdout_text)
        if not m:
            continue
        tags.add(f"auth:{tag}")
        if not first_excerpt:
            # Capture the line containing the match, trimmed to 200 chars.
            line_start = stdout_text.rfind("\n", 0, m.start()) + 1
            line_end = stdout_text.find("\n", m.end())
            if line_end == -1:
                line_end = len(stdout_text)
            line = stdout_text[line_start:line_end].strip()
            first_excerpt = line[:200]
    return sorted(tags), first_excerpt


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
                        help="Path to a CA bundle (PEM) to trust, e.g. an "
                             "internal CA that signed the controller's cert. "
                             "Preferable to --insecure. Env: CONTROLLER_CA_BUNDLE")
    parser.add_argument("--no-auth-check", action="store_true",
                        help="Skip fetching/scanning project_update stdout for "
                             "auth-error patterns (faster, but no token/cred "
                             "diagnosis)")
    parser.add_argument("--max-stdout-bytes", type=int, default=262144,
                        help="Max bytes to fetch per project_update stdout "
                             "during auth scan (default: 262144)")
    parser.add_argument("--output", "-o", default="broken_projects.csv",
                        help="Output CSV path (default: broken_projects.csv)")
    args = parser.parse_args()

    if not args.host or not args.token:
        sys.stderr.write(
            "ERROR: --host and --token are required "
            "(or set CONTROLLER_HOST / CONTROLLER_TOKEN)\n"
        )
        return 2

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

    broken: list[dict] = []
    total = 0
    try:
        for project in iter_projects(session, base_url, args.api_prefix):
            total += 1
            reasons = classify(project)
            if not reasons:
                continue

            org_name = (
                project.get("summary_fields", {})
                       .get("organization", {})
                       .get("name") or "(no organization)"
            )
            cred_name = (
                project.get("summary_fields", {})
                       .get("credential", {})
                       .get("name") or ""
            )

            auth_excerpt = ""
            # Inspect last project_update stdout for auth failures, but only
            # when there's a recent failing update to look at — saves API calls.
            last_update = project.get("summary_fields", {}).get("last_update") or {}
            update_id = last_update.get("id")
            update_failed = (
                last_update.get("failed") is True
                or (last_update.get("status") or "").lower()
                    in {"failed", "error", "canceled"}
            )
            if (not args.no_auth_check) and update_id and update_failed:
                try:
                    stdout = fetch_update_stdout(
                        session, base_url, args.api_prefix,
                        update_id, args.max_stdout_bytes,
                    )
                    auth_tags, auth_excerpt = scan_auth_errors(stdout)
                    reasons.extend(auth_tags)
                except requests.RequestException as e:
                    # Don't fail the whole scan on a single bad update fetch.
                    sys.stderr.write(
                        f"WARN: failed fetching stdout for project "
                        f"{project.get('id')} update {update_id}: {e}\n"
                    )

            broken.append({
                "organization": org_name,
                "project_name": project.get("name", ""),
                "project_id": project.get("id"),
                "status": project.get("status") or "",
                "last_job_failed": project.get("last_job_failed"),
                "scm_type": project.get("scm_type") or "manual",
                "scm_url": project.get("scm_url") or "",
                "credential_name": cred_name,
                "scm_revision": project.get("scm_revision") or "",
                "last_updated": project.get("last_updated") or "",
                "reasons": ";".join(reasons),
                "auth_excerpt": auth_excerpt,
            })
    except requests.HTTPError as e:
        sys.stderr.write(f"ERROR: API request failed: {e}\n")
        return 1
    except requests.RequestException as e:
        sys.stderr.write(f"ERROR: connection problem: {e}\n")
        return 1

    broken.sort(key=lambda r: (r["organization"], r["project_name"]))

    fieldnames = [
        "organization", "project_name", "project_id", "status",
        "last_job_failed", "scm_type", "scm_url", "credential_name",
        "scm_revision", "last_updated", "reasons", "auth_excerpt",
    ]
    with open(args.output, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(broken)

    auth_count = sum(1 for r in broken if "auth:" in r["reasons"])
    sys.stderr.write(
        f"Scanned {total} projects. {len(broken)} flagged "
        f"({auth_count} with auth-related signals). "
        f"Wrote {args.output}\n"
    )
    # Compact tab-separated summary to stdout, easy to pipe into column/awk.
    for row in broken:
        print(f"{row['organization']}\t{row['project_name']}\t{row['reasons']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
