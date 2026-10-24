#!/usr/bin/env python3
"""Trustfield scan for GitHub Actions (stdlib only).

Calls the public Trustfield JSON API, prints a readable summary, optionally
comments on the pull request, and fails the job when the configured severity
is found. It never scans without a URL supplied by the workflow.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API = os.environ.get("TRUSTFIELD_API", "https://trustfield.dev")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def post_json(url: str, body: dict, token: str = "", timeout: int = 180) -> dict:
    data = json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "trustfield-github-action/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read() or b"{}")


def scan(target: str, has_ai: bool) -> dict:
    return post_json(
        f"{API}/api/scan",
        {"kind": "url", "target": target, "has_ai": has_ai, "consent": True},
        timeout=240,
    )


def comment_on_pr(body: str) -> None:
    token = os.environ.get("GH_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    number = os.environ.get("PR_NUMBER", "")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not (token and repo and number):
        return
    try:
        url = f"{api}/repos/{repo}/issues/{number}/comments"
        post_json(url, {"body": body}, token=token, timeout=30)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"Could not comment on the PR: {exc}")


def main() -> int:
    target = (os.environ.get("TRUSTFIELD_URL") or "").strip()
    if not target:
        print("Trustfield: input 'url' is required.")
        return 2
    fail_on = (os.environ.get("TRUSTFIELD_FAIL_ON") or "critical").lower()
    want_comment = (os.environ.get("TRUSTFIELD_COMMENT") or "true").lower() == "true"
    has_ai = (os.environ.get("TRUSTFIELD_AI") or "false").lower() == "true"

    print(f"Trustfield: scanning {target} ...")
    try:
        result = scan(target, has_ai)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"Trustfield: scan failed to run: {exc}")
        return 2

    score = result.get("score")
    grade = result.get("grade")
    counts = result.get("counts") or {}
    total = result.get("total") or 0
    findings = result.get("teaser") or []
    report_url = API + str(result.get("report_url") or "")
    critical = int(counts.get("critical") or 0)
    high = int(counts.get("high") or 0)

    lines = [
        "## Trustfield security scan",
        "",
        f"**Score: {score}/100 ({grade})** · {total} finding(s) · {report_url}",
        "",
        f"Critical: {critical} · High: {high} · Medium: {counts.get('medium', 0)} · Low: {counts.get('low', 0)}",
    ]
    if findings:
        lines.append("")
        lines.append("| Severity | Finding |")
        lines.append("| --- | --- |")
        for finding in findings[:10]:
            lines.append(f"| {finding.get('severity', '')} | {finding.get('title', '')} |")
        if len(findings) > 10:
            lines.append(f"| … | +{len(findings) - 10} more in the report |")
    lines.append("")
    lines.append("Free scan shows titles only; the ₹499 report has evidence, fixes and a PDF: " + report_url)

    summary = "\n".join(lines)
    print(summary)
    if want_comment:
        comment_on_pr(summary)

    threshold = SEVERITY_RANK.get(fail_on, 0)
    if threshold >= 4 and critical > 0:
        print(f"Trustfield: failing because {critical} critical finding(s) were found.")
        return 1
    if threshold >= 3 and (critical > 0 or high > 0):
        print(f"Trustfield: failing because high/critical findings were found.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
