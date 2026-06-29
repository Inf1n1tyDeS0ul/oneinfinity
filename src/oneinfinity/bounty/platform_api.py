"""
platform_api.py — Live bug bounty platform API clients

Provides authenticated access to:
  - HackerOne GraphQL API (programs, scope, hacktivity)
  - Bugcrowd REST API (programs, scope)
  - Intigriti REST API (programs, scope)

All report submissions require explicit human approval — never auto-submit.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import urllib.request
import urllib.parse
import json

log = logging.getLogger("oneinfinity.platform_api")


# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class ScopeAsset:
    asset: str
    asset_type: str          # "url", "wildcard", "ip_address", "cidr", "android_app", "ios_app"
    max_severity: str        # "critical", "high", "medium", "low"
    eligible_for_bounty: bool = True
    out_of_scope: bool = False
    instructions: str = ""
    program: str = ""
    platform: str = ""


@dataclass
class ProgramDetails:
    handle: str
    name: str
    platform: str
    offers_bounties: bool
    min_bounty_usd: float
    max_bounty_usd: float
    response_sla_hours: int
    in_scope: List[ScopeAsset] = field(default_factory=list)
    out_of_scope: List[ScopeAsset] = field(default_factory=list)
    policy_url: str = ""
    submission_state: str = "open"  # open, closed, invite_only


@dataclass
class DisclosedReport:
    report_id: str
    title: str
    vuln_type: str
    severity: str
    bounty_usd: float
    disclosed_at: str
    program: str
    platform: str
    url: str = ""


@dataclass
class ReportDraft:
    title: str
    summary: str
    severity: str
    vuln_type: str
    steps_to_reproduce: str
    impact: str
    cvss_score: float
    evidence: str
    program: str
    platform: str
    approved: bool = False  # must be set True by human before submission


@dataclass
class TriageStatus:
    report_id: str
    state: str          # new, triaged, resolved, informative, duplicate, not_applicable
    severity: str
    bounty_usd: float
    updated_at: str


# ── HackerOne client ─────────────────────────────────────────────────────────

class HackerOneClient:
    """Authenticated HackerOne GraphQL API client."""

    BASE = "https://api.hackerone.com/v1"
    GRAPHQL = "https://api.hackerone.com/v1/graphql"

    def __init__(self, api_username: str = "", api_token: str = ""):
        self.username = api_username or os.getenv("H1_USERNAME", "")
        self.token = api_token or os.getenv("H1_API_TOKEN", "")
        self._auth = None
        if self.username and self.token:
            import base64
            creds = f"{self.username}:{self.token}".encode()
            self._auth = "Basic " + base64.b64encode(creds).decode()

    def _gql(self, query: str, variables: dict = None) -> dict:
        payload = json.dumps({"query": query, "variables": variables or {}}).encode()
        req = urllib.request.Request(
            self.GRAPHQL,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        if self._auth:
            req.add_header("Authorization", self._auth)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def _rest(self, path: str, params: dict = None) -> dict:
        url = f"{self.BASE}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json"},
            method="GET",
        )
        if self._auth:
            req.add_header("Authorization", self._auth)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def get_program(self, handle: str) -> Optional[ProgramDetails]:
        try:
            data = self._rest(f"/programs/{handle}")
            attrs = data.get("data", {}).get("attributes", {})
            scope_in, scope_out = self.get_scope(handle)
            return ProgramDetails(
                handle=handle,
                name=attrs.get("name", handle),
                platform="hackerone",
                offers_bounties=attrs.get("offers_bounties", False),
                min_bounty_usd=float(attrs.get("minimum_bounty", 0) or 0),
                max_bounty_usd=float(attrs.get("maximum_bounty", 0) or 0),
                response_sla_hours=int(attrs.get("first_response_time", 0) or 0),
                in_scope=scope_in,
                out_of_scope=scope_out,
                policy_url=attrs.get("policy", ""),
                submission_state=attrs.get("submission_state", "open"),
            )
        except Exception as exc:
            log.warning("H1 get_program(%s) failed: %s", handle, exc)
            return None

    def get_scope(self, handle: str) -> tuple[List[ScopeAsset], List[ScopeAsset]]:
        in_scope: List[ScopeAsset] = []
        out_of_scope: List[ScopeAsset] = []
        try:
            page = 1
            while True:
                data = self._rest(
                    f"/programs/{handle}/structured_scopes",
                    {"page[number]": page, "page[size]": 100},
                )
                items = data.get("data", [])
                if not items:
                    break
                for item in items:
                    a = item.get("attributes", {})
                    asset = ScopeAsset(
                        asset=a.get("asset_identifier", ""),
                        asset_type=a.get("asset_type", "url").lower(),
                        max_severity=a.get("max_severity", "high").lower(),
                        eligible_for_bounty=a.get("eligible_for_bounty", True),
                        out_of_scope=False,
                        instructions=a.get("instruction", ""),
                        program=handle,
                        platform="hackerone",
                    )
                    in_scope.append(asset)
                page += 1
                if page > 20:
                    break
        except Exception as exc:
            log.warning("H1 get_scope(%s) failed: %s", handle, exc)
        return in_scope, out_of_scope

    def get_hacktivity(self, handle: str, limit: int = 50) -> List[DisclosedReport]:
        reports: List[DisclosedReport] = []
        try:
            query = """
            query HacktivityQuery($handle: String!, $limit: Int!) {
              team(handle: $handle) {
                hacktivity_items(first: $limit, filter: {disclosed: true}) {
                  nodes {
                    ... on HacktivityItem {
                      report {
                        id
                        title
                        disclosed_at
                        severity { rating }
                        weakness { name }
                        total_awarded_amount
                        url
                      }
                    }
                  }
                }
              }
            }
            """
            data = self._gql(query, {"handle": handle, "limit": limit})
            nodes = (
                data.get("data", {})
                .get("team", {})
                .get("hacktivity_items", {})
                .get("nodes", [])
            )
            for node in nodes:
                r = node.get("report", {})
                if not r:
                    continue
                reports.append(DisclosedReport(
                    report_id=r.get("id", ""),
                    title=r.get("title", ""),
                    vuln_type=(r.get("weakness") or {}).get("name", ""),
                    severity=(r.get("severity") or {}).get("rating", ""),
                    bounty_usd=float(r.get("total_awarded_amount") or 0),
                    disclosed_at=r.get("disclosed_at", ""),
                    program=handle,
                    platform="hackerone",
                    url=r.get("url", ""),
                ))
        except Exception as exc:
            log.warning("H1 get_hacktivity(%s) failed: %s", handle, exc)
        return reports

    def draft_report(self, finding, program: str) -> ReportDraft:
        """Build a draft report from a finding. Requires human approval before submission."""
        return ReportDraft(
            title=getattr(finding, "title", str(finding)),
            summary=getattr(finding, "description", ""),
            severity=getattr(finding, "severity", "medium"),
            vuln_type=getattr(finding, "vuln_type", ""),
            steps_to_reproduce=getattr(finding, "evidence", ""),
            impact=getattr(finding, "impact", ""),
            cvss_score=getattr(finding, "cvss_score", 0.0),
            evidence=getattr(finding, "evidence", ""),
            program=program,
            platform="hackerone",
            approved=False,
        )

    def submit_report(self, draft: ReportDraft) -> Optional[str]:
        """
        Submit a report to HackerOne. Requires draft.approved == True.
        NEVER call this without explicit human approval.
        """
        if not draft.approved:
            raise RuntimeError(
                "Report submission requires explicit human approval. "
                "Set draft.approved = True only after human review."
            )
        try:
            payload = json.dumps({
                "data": {
                    "type": "report",
                    "attributes": {
                        "team_handle": draft.program,
                        "title": draft.title,
                        "vulnerability_information": (
                            f"{draft.summary}\n\n"
                            f"**Steps to reproduce:**\n{draft.steps_to_reproduce}\n\n"
                            f"**Impact:**\n{draft.impact}"
                        ),
                        "impact": draft.impact,
                        "severity_rating": draft.severity,
                    }
                }
            }).encode()
            req = urllib.request.Request(
                f"{self.BASE}/reports",
                data=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                method="POST",
            )
            if self._auth:
                req.add_header("Authorization", self._auth)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                return data.get("data", {}).get("id")
        except Exception as exc:
            log.error("H1 submit_report failed: %s", exc)
            return None

    def get_report_status(self, report_id: str) -> Optional[TriageStatus]:
        try:
            data = self._rest(f"/reports/{report_id}")
            attrs = data.get("data", {}).get("attributes", {})
            return TriageStatus(
                report_id=report_id,
                state=attrs.get("state", "new"),
                severity=attrs.get("severity", {}).get("rating", ""),
                bounty_usd=float(attrs.get("total_awarded_amount") or 0),
                updated_at=attrs.get("updated_at", ""),
            )
        except Exception as exc:
            log.warning("H1 get_report_status(%s) failed: %s", report_id, exc)
            return None

    def is_available(self) -> bool:
        return bool(self._auth)


# ── Bugcrowd client ──────────────────────────────────────────────────────────

class BugcrowdClient:
    """Bugcrowd REST API client."""

    BASE = "https://api.bugcrowd.com"

    def __init__(self, api_token: str = ""):
        self.token = api_token or os.getenv("BUGCROWD_API_TOKEN", "")

    def _request(self, path: str, params: dict = None) -> dict:
        url = f"{self.BASE}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.bugcrowd.v4+json",
                "Authorization": f"Token {self.token}",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def get_programs(self) -> List[ProgramDetails]:
        programs: List[ProgramDetails] = []
        try:
            data = self._request("/programs", {"page[limit]": 100})
            for item in data.get("data", []):
                a = item.get("attributes", {})
                programs.append(ProgramDetails(
                    handle=item.get("id", ""),
                    name=a.get("name", ""),
                    platform="bugcrowd",
                    offers_bounties=a.get("bounty_table", False),
                    min_bounty_usd=0.0,
                    max_bounty_usd=0.0,
                    response_sla_hours=0,
                    submission_state="open" if a.get("accepting_submissions", False) else "closed",
                ))
        except Exception as exc:
            log.warning("Bugcrowd get_programs failed: %s", exc)
        return programs

    def get_scope(self, program_code: str) -> List[ScopeAsset]:
        assets: List[ScopeAsset] = []
        try:
            data = self._request(f"/programs/{program_code}/scope_groups")
            for group in data.get("data", []):
                for target in group.get("attributes", {}).get("in_scope", []):
                    assets.append(ScopeAsset(
                        asset=target.get("target", ""),
                        asset_type=target.get("type", "url").lower(),
                        max_severity=target.get("max_severity", "high"),
                        eligible_for_bounty=True,
                        out_of_scope=False,
                        program=program_code,
                        platform="bugcrowd",
                    ))
        except Exception as exc:
            log.warning("Bugcrowd get_scope(%s) failed: %s", program_code, exc)
        return assets

    def is_available(self) -> bool:
        return bool(self.token)


# ── Intigriti client ─────────────────────────────────────────────────────────

class IntigritiClient:
    """Intigriti REST API client."""

    BASE = "https://api.intigriti.com/external/researcher/v1"

    def __init__(self, api_token: str = ""):
        self.token = api_token or os.getenv("INTIGRITI_API_TOKEN", "")

    def _request(self, path: str) -> dict:
        req = urllib.request.Request(
            f"{self.BASE}{path}",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def get_programs(self) -> List[ProgramDetails]:
        programs: List[ProgramDetails] = []
        try:
            data = self._request("/programs")
            for item in (data if isinstance(data, list) else data.get("records", [])):
                programs.append(ProgramDetails(
                    handle=item.get("handle", ""),
                    name=item.get("name", ""),
                    platform="intigriti",
                    offers_bounties=item.get("maxBounty", 0) > 0,
                    min_bounty_usd=float(item.get("minBounty", 0) or 0),
                    max_bounty_usd=float(item.get("maxBounty", 0) or 0),
                    response_sla_hours=0,
                    submission_state="open" if item.get("status", "") == "open" else "closed",
                ))
        except Exception as exc:
            log.warning("Intigriti get_programs failed: %s", exc)
        return programs

    def get_scope(self, handle: str) -> List[ScopeAsset]:
        assets: List[ScopeAsset] = []
        try:
            data = self._request(f"/programs/{handle}/domains")
            for domain in (data if isinstance(data, list) else data.get("records", [])):
                assets.append(ScopeAsset(
                    asset=domain.get("endpoint", ""),
                    asset_type=domain.get("type", "url").lower(),
                    max_severity=domain.get("tier", "high"),
                    eligible_for_bounty=domain.get("bountyAvailable", True),
                    out_of_scope=domain.get("isOutOfScope", False),
                    program=handle,
                    platform="intigriti",
                ))
        except Exception as exc:
            log.warning("Intigriti get_scope(%s) failed: %s", handle, exc)
        return assets

    def is_available(self) -> bool:
        return bool(self.token)


# ── Convenience functions ─────────────────────────────────────────────────────

def get_h1_client() -> HackerOneClient:
    return HackerOneClient()


def get_bugcrowd_client() -> BugcrowdClient:
    return BugcrowdClient()


def get_intigriti_client() -> IntigritiClient:
    return IntigritiClient()
