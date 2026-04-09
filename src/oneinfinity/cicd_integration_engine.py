"""
CI/CD Integration Engine — GitHub Actions/GitLab CI/Jenkins continuous pentesting
"""
import json
import os
import logging
import subprocess
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

class CICDPlatform:
    GITHUB  = "github"
    GITLAB  = "gitlab"
    JENKINS = "jenkins"
    LOCAL   = "local"


@dataclass
class PipelineConfig:
    platform: str
    repo_url: str
    branch: str = "main"
    scan_on_pr: bool = True
    scan_on_push: bool = False
    notify_slack: bool = False
    slack_webhook: Optional[str] = None
    fail_on_critical: bool = True

    def to_dict(self):
        return {
            "platform": self.platform,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "scan_on_pr": self.scan_on_pr,
            "scan_on_push": self.scan_on_push,
            "notify_slack": self.notify_slack,
            "slack_webhook": self.slack_webhook,
            "fail_on_critical": self.fail_on_critical,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class CICDIntegrationEngine:
    """Generate and manage CI/CD pipeline integrations for continuous security scanning."""

    # ------------------------------------------------------------------
    # GitHub Actions
    # ------------------------------------------------------------------

    def generate_github_actions_workflow(self, scan_command: str = "oneinfinity run") -> str:
        """Return YAML content for .github/workflows/security-scan.yml."""
        return f"""name: One&Infinity Security Scan

on:
  pull_request:
    branches: ["**"]
  push:
    branches: [main, master, develop]
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: 60

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install oneinfinity-framework 2>/dev/null || pip install -r requirements.txt || true

      - name: Install security tools
        run: |
          go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
          go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
          export PATH="$PATH:$(go env GOPATH)/bin"

      - name: Determine scan target
        id: target
        run: |
          if [ "${{{{ github.event_name }}}}" = "pull_request" ]; then
            TARGET="${{{{ github.event.pull_request.head.repo.full_name }}}}"
          else
            TARGET="${{{{ github.repository }}}}"
          fi
          echo "target=$TARGET" >> "$GITHUB_OUTPUT"
          echo "Scan target: $TARGET"

      - name: Run security scan
        id: scan
        run: |
          set +e
          {scan_command} "${{{{ steps.target.outputs.target }}}}" \\
            --output-format json \\
            --output-file scan_results.json \\
            --no-interactive 2>&1 | tee scan_output.log
          EXIT_CODE=$?
          echo "exit_code=$EXIT_CODE" >> "$GITHUB_OUTPUT"
          set -e

      - name: Parse scan results
        id: results
        if: always()
        run: |
          if [ -f scan_results.json ]; then
            CRITICAL=$(python3 -c "
          import json, sys
          try:
              data = json.load(open('scan_results.json'))
              findings = data.get('findings', [])
              critical = [f for f in findings if f.get('severity','').lower() == 'critical']
              high     = [f for f in findings if f.get('severity','').lower() == 'high']
              print(f'critical={{len(critical)}} high={{len(high)}} total={{len(findings)}}')
          except Exception as e:
              print('critical=0 high=0 total=0')
            " 2>/dev/null || echo "critical=0 high=0 total=0")
            echo "$CRITICAL" >> "$GITHUB_OUTPUT"
          else
            echo "critical=0 high=0 total=0" >> "$GITHUB_OUTPUT"
          fi

      - name: Upload scan artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-scan-results-${{{{ github.run_number }}}}
          path: |
            scan_results.json
            scan_output.log
          retention-days: 30

      - name: Comment on PR with findings
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          github-token: ${{{{ secrets.GITHUB_TOKEN }}}}
          script: |
            const fs = require('fs');
            let body = '## Security Scan Results\\n\\n';
            try {{{{
              const raw = fs.readFileSync('scan_results.json', 'utf8');
              const data = JSON.parse(raw);
              const findings = data.findings || [];
              const critical = findings.filter(f => f.severity === 'critical');
              const high     = findings.filter(f => f.severity === 'high');
              const medium   = findings.filter(f => f.severity === 'medium');
              body += `| Severity | Count |\\n|----------|-------|\\n`;
              body += `| 🔴 Critical | ${{critical.length}} |\\n`;
              body += `| 🟠 High     | ${{high.length}} |\\n`;
              body += `| 🟡 Medium   | ${{medium.length}} |\\n`;
              body += `| Total       | ${{findings.length}} |\\n\\n`;
              if (critical.length > 0) {{{{
                body += '### Critical Findings\\n\\n';
                body += '| Title | File | Line |\\n|-------|------|------|\\n';
                critical.slice(0, 10).forEach(f => {{{{
                  body += `| ${{f.title || f.vuln_type}} | ${{f.file_path || '-'}} | ${{f.line_number || '-'}} |\\n`;
                }}}});
              }}}}
              if (findings.length === 0) body += '_No findings detected._\\n';
            }}}} catch (e) {{{{
              body += '_Could not parse scan results._\\n';
            }}}}
            body += `\\n---\\n_Scan run: #${{{{ github.run_number }}}}_`;
            github.rest.issues.createComment({{{{
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            }}}});

      - name: Fail on critical findings
        if: always()
        run: |
          if [ -f scan_results.json ]; then
            CRITICAL=$(python3 -c "
          import json, sys
          try:
              data = json.load(open('scan_results.json'))
              findings = data.get('findings', [])
              count = len([f for f in findings if f.get('severity','').lower() == 'critical'])
              sys.exit(1 if count > 0 else 0)
          except:
              sys.exit(0)
            ")
          fi
"""

    # ------------------------------------------------------------------
    # GitLab CI
    # ------------------------------------------------------------------

    def generate_gitlab_ci_config(self, scan_command: str = "oneinfinity run") -> str:
        """Return YAML content for .gitlab-ci.yml."""
        return f"""stages:
  - test
  - security-scan
  - report

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"
  GOPATH: "$CI_PROJECT_DIR/.cache/go"
  SCAN_OUTPUT: "security-scan-results.json"

cache:
  paths:
    - .cache/pip/
    - .cache/go/

security-scan:
  stage: security-scan
  image: python:3.11-slim
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl wget git golang 2>/dev/null || true
    - pip install --quiet oneinfinity-framework 2>/dev/null || pip install -r requirements.txt || true
    - export PATH="$PATH:$GOPATH/bin"
    - go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
    - go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
  script:
    - |
      TARGET="${{CI_PROJECT_URL}}"
      echo "Scanning target: $TARGET"
      {scan_command} "$TARGET" \\
        --output-format json \\
        --output-file "$SCAN_OUTPUT" \\
        --no-interactive 2>&1 | tee scan_output.log || true
    - |
      if [ -f "$SCAN_OUTPUT" ]; then
        python3 - <<'EOF'
      import json, sys
      try:
          data = json.load(open("security-scan-results.json"))
          findings = data.get("findings", [])
          critical = [f for f in findings if f.get("severity", "").lower() == "critical"]
          high     = [f for f in findings if f.get("severity", "").lower() == "high"]
          print(f"Scan complete: {{len(findings)}} findings ({{len(critical)}} critical, {{len(high)}} high)")
          if critical:
              print("CRITICAL FINDINGS:")
              for f in critical[:5]:
                  print(f"  - {{f.get('title', f.get('vuln_type', 'Unknown'))}}")
              sys.exit(1)
      except Exception as e:
          print(f"Warning: could not parse results: {{e}}")
      EOF
      fi
  artifacts:
    name: "security-scan-$CI_COMMIT_SHORT_SHA"
    paths:
      - "$SCAN_OUTPUT"
      - scan_output.log
    expire_in: 30 days
    reports:
      junit: scan_results_junit.xml
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
    - if: '$CI_PIPELINE_SOURCE == "web"'
  allow_failure: false
  tags:
    - docker

security-report:
  stage: report
  image: python:3.11-slim
  needs: ["security-scan"]
  script:
    - |
      python3 - <<'EOF'
      import json, os
      try:
          data = json.load(open("security-scan-results.json"))
          findings = data.get("findings", [])
          severities = {{}}
          for f in findings:
              s = f.get("severity", "unknown")
              severities[s] = severities.get(s, 0) + 1
          print("=== Security Scan Summary ===")
          for sev, count in sorted(severities.items()):
              print(f"  {{sev.upper()}}: {{count}}")
      except Exception as e:
          print(f"Report generation failed: {{e}}")
      EOF
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
      when: always
  allow_failure: true
"""

    # ------------------------------------------------------------------
    # Jenkins
    # ------------------------------------------------------------------

    def generate_jenkins_pipeline(self, scan_command: str = "oneinfinity run") -> str:
        """Return Groovy Jenkinsfile content."""
        return f"""pipeline {{
    agent any

    environment {{
        SCAN_OUTPUT      = 'security-scan-results.json'
        GOPATH           = "${{WORKSPACE}}/.cache/go"
        PATH             = "${{env.PATH}}:${{WORKSPACE}}/.cache/go/bin:${{HOME}}/.local/bin"
        PYTHONUNBUFFERED = '1'
    }}

    options {{
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timestamps()
    }}

    triggers {{
        // Poll SCM every 15 minutes or use GitHub/GitLab webhooks
        pollSCM('H/15 * * * *')
    }}

    stages {{
        stage('Checkout') {{
            steps {{
                checkout scm
                echo "Branch: ${{env.BRANCH_NAME}}, Commit: ${{env.GIT_COMMIT}}"
            }}
        }}

        stage('Setup Environment') {{
            steps {{
                sh '''
                    python3 -m pip install --quiet --upgrade pip
                    pip install oneinfinity-framework 2>/dev/null || pip install -r requirements.txt || true
                    which go && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true
                    which go && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
                '''
            }}
        }}

        stage('Source Analysis') {{
            steps {{
                echo 'Running static source code analysis...'
                sh '''
                    python3 -c "
from oneinfinity.source_analysis_engine import source_analysis_engine
import json, os
result = source_analysis_engine.analyze_directory('.')
data = result.to_dict()
json.dump(data, open('source_analysis.json', 'w'), indent=2)
print(f'Source analysis: {{len(data[\"findings\"])}} findings across {{sum(data[\"language_stats\"].values())}} files')
" 2>&1 || echo "Source analysis unavailable"
                '''
            }}
        }}

        stage('Security Scan') {{
            steps {{
                script {{
                    def target = env.SCAN_TARGET ?: sh(
                        script: "git remote get-url origin 2>/dev/null | sed 's/\\.git$//' || echo 'localhost'",
                        returnStdout: true
                    ).trim()
                    echo "Scanning: ${{target}}"
                    sh '''
                        ''' + scan_command + ''' "${{target}}" \\
                            --output-format json \\
                            --output-file "${{SCAN_OUTPUT}}" \\
                            --no-interactive 2>&1 | tee scan_output.log || true
                    '''
                }}
            }}
        }}

        stage('Evaluate Results') {{
            steps {{
                script {{
                    def result = sh(
                        script: '''
                            python3 - <<PYEOF
import json, sys
try:
    data  = json.load(open("security-scan-results.json"))
    finds = data.get("findings", [])
    crit  = [f for f in finds if f.get("severity","").lower() == "critical"]
    high  = [f for f in finds if f.get("severity","").lower() == "high"]
    print("SCAN_SUMMARY:total=" + str(len(finds)) + ",critical=" + str(len(crit)) + ",high=" + str(len(high)))
    sys.exit(1 if crit else 0)
except Exception as e:
    print("SCAN_SUMMARY:total=0,critical=0,high=0")
    sys.exit(0)
PYEOF
                        ''',
                        returnStatus: true
                    )
                    if (result != 0) {{
                        currentBuild.result = 'UNSTABLE'
                        echo 'WARNING: Critical security findings detected!'
                    }}
                }}
            }}
        }}

        stage('Publish Report') {{
            steps {{
                sh '''
                    python3 - <<'PYEOF'
import json, datetime
try:
    data  = json.load(open("security-scan-results.json"))
    finds = data.get("findings", [])
    rows  = ""
    for f in finds[:50]:
        rows += "<tr><td>{sev}</td><td>{vuln}</td><td>{title}</td><td>{fp}:{ln}</td></tr>".format(
            sev=f.get("severity","?"), vuln=f.get("vuln_type","?"),
            title=f.get("title","?"), fp=f.get("file_path","?"), ln=f.get("line_number","?")
        )
    html = ('<html><body><h1>Security Scan Report</h1>'
        + '<p>Total findings: ' + str(len(finds)) + '</p>'
        + '<table border="1"><tr><th>Severity</th><th>Type</th><th>Title</th><th>Location</th></tr>'
        + rows + '</table></body></html>')
    open("security-scan-report.html","w").write(html)
    print("HTML report written.")
except Exception as e:
    print(f"Report failed: {{e}}")
PYEOF
                '''
                publishHTML(target: [
                    reportDir:   '.',
                    reportFiles: 'security-scan-report.html',
                    reportName:  'Security Scan Report',
                    keepAll:     true,
                    allowMissing: true,
                ])
            }}
        }}
    }}

    post {{
        always {{
            archiveArtifacts artifacts: '${{SCAN_OUTPUT}}, scan_output.log, security-scan-report.html, source_analysis.json',
                             allowEmptyArchive: true
            cleanWs()
        }}
        failure {{
            echo 'Pipeline failed — review security findings.'
        }}
        unstable {{
            echo 'Pipeline unstable — critical findings require review.'
        }}
    }}
}}
"""

    # ------------------------------------------------------------------
    # GitHub webhook installation
    # ------------------------------------------------------------------

    def install_github_webhook(self, repo: str, webhook_url: str, secret: str) -> dict:
        """Create a GitHub webhook via the API. repo = 'owner/repo'."""
        api_token = os.environ.get("GITHUB_TOKEN", "")
        if not api_token:
            return {"success": False, "error": "GITHUB_TOKEN not set in environment"}

        payload = json.dumps({
            "name": "web",
            "active": True,
            "events": ["push", "pull_request"],
            "config": {
                "url": webhook_url,
                "content_type": "json",
                "secret": secret,
                "insecure_ssl": "0",
            },
        }).encode("utf-8")

        url = f"https://api.github.com/repos/{repo}/hooks"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {api_token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode())
                return {"success": True, "hook_id": body.get("id"), "url": body.get("url")}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode()
            return {"success": False, "error": f"HTTP {exc.code}: {err_body}"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Webhook payload handling
    # ------------------------------------------------------------------

    def handle_webhook_payload(self, payload: dict, platform: str) -> dict:
        """Parse an incoming webhook payload and return a scan config dict."""
        config = {
            "platform": platform,
            "event": "unknown",
            "target": None,
            "branch": None,
            "pr_number": None,
            "repo": None,
            "should_scan": False,
        }

        if platform == CICDPlatform.GITHUB:
            event = payload.get("action") or ("push" if "commits" in payload else "unknown")
            config["event"] = event
            config["repo"] = payload.get("repository", {}).get("full_name")
            config["branch"] = (
                payload.get("ref", "").replace("refs/heads/", "")
                or payload.get("pull_request", {}).get("head", {}).get("ref")
            )
            if "pull_request" in payload:
                pr = payload["pull_request"]
                config["pr_number"] = pr.get("number")
                config["target"] = pr.get("head", {}).get("repo", {}).get("clone_url")
                config["event"] = "pull_request"
                config["should_scan"] = pr.get("state") == "open"
            elif "commits" in payload:
                config["target"] = payload.get("repository", {}).get("clone_url")
                config["event"] = "push"
                config["should_scan"] = True

        elif platform == CICDPlatform.GITLAB:
            config["event"] = payload.get("object_kind", "unknown")
            config["repo"] = payload.get("project", {}).get("path_with_namespace")
            config["branch"] = payload.get("ref", "").replace("refs/heads/", "")
            if payload.get("object_kind") == "merge_request":
                mr = payload.get("object_attributes", {})
                config["pr_number"] = mr.get("iid")
                config["target"] = payload.get("project", {}).get("http_url")
                config["should_scan"] = mr.get("state") == "opened"
            elif payload.get("object_kind") == "push":
                config["target"] = payload.get("project", {}).get("http_url")
                config["should_scan"] = True

        elif platform == CICDPlatform.JENKINS:
            config["event"] = "jenkins_trigger"
            config["target"] = payload.get("url") or payload.get("target")
            config["branch"] = payload.get("branch", "main")
            config["should_scan"] = bool(config["target"])

        return config

    # ------------------------------------------------------------------
    # PR comment with findings
    # ------------------------------------------------------------------

    def notify_github_pr(self, repo: str, pr_number: int, findings: list, token: str) -> bool:
        """Post a findings summary comment on a GitHub PR."""
        if not token:
            logger.warning("No GitHub token provided for PR comment")
            return False

        sev_counts: dict = {}
        for f in findings:
            sev = f.get("severity", "unknown").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        rows = ""
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in sev_counts:
                rows += f"| {sev_icons.get(sev, '')} {sev.capitalize()} | {sev_counts[sev]} |\n"

        detail_rows = ""
        for f in findings[:20]:
            title   = f.get("title", f.get("vuln_type", "Unknown"))
            fp      = f.get("file_path", "-")
            ln      = f.get("line_number", "-")
            sev     = f.get("severity", "?")
            snippet = f.get("code_snippet", "")[:80].replace("|", "\\|")
            detail_rows += f"| {sev} | {title} | `{fp}:{ln}` | `{snippet}` |\n"

        body = (
            "## AI-Powered Offensive Security Research Framework : One&Infinity — Security Scan Results\n\n"
            "### Summary\n\n"
            "| Severity | Count |\n|----------|-------|\n"
            f"{rows}\n"
            "### Top Findings\n\n"
            "| Severity | Title | Location | Snippet |\n"
            "|----------|-------|----------|---------|\n"
            f"{detail_rows}\n"
        )
        if len(findings) > 20:
            body += f"\n_...and {len(findings) - 20} more findings. See artifacts for full report._\n"
        if not findings:
            body += "_No security findings detected._\n"

        payload = json.dumps({"body": body}).encode("utf-8")
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                return True
        except Exception as exc:
            logger.error("Failed to post PR comment: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Save workflow file to disk
    # ------------------------------------------------------------------

    def save_workflow_file(self, workflow_type: str, output_dir: str = ".") -> str:
        """Write the requested workflow file and return its absolute path."""
        out = Path(output_dir).resolve()

        type_map = {
            CICDPlatform.GITHUB:  (".github/workflows/security-scan.yml", self.generate_github_actions_workflow),
            "github_actions":     (".github/workflows/security-scan.yml", self.generate_github_actions_workflow),
            CICDPlatform.GITLAB:  (".gitlab-ci.yml",                       self.generate_gitlab_ci_config),
            "gitlab_ci":          (".gitlab-ci.yml",                       self.generate_gitlab_ci_config),
            CICDPlatform.JENKINS: ("Jenkinsfile",                          self.generate_jenkins_pipeline),
            "jenkins":            ("Jenkinsfile",                          self.generate_jenkins_pipeline),
        }

        if workflow_type not in type_map:
            raise ValueError(
                f"Unknown workflow_type '{workflow_type}'. "
                f"Choose from: {', '.join(type_map.keys())}"
            )

        relative_path, generator = type_map[workflow_type]
        target_file = out / relative_path
        target_file.parent.mkdir(parents=True, exist_ok=True)
        content = generator()
        target_file.write_text(content)
        logger.info("Wrote %s workflow to %s", workflow_type, target_file)
        return str(target_file)

    # ------------------------------------------------------------------
    # Status badge
    # ------------------------------------------------------------------

    def get_scan_status_badge(self, session_id: str) -> str:
        """Return an SVG badge HTML string indicating scan status."""
        # In a real deployment this would query a DB/cache keyed by session_id.
        # Here we derive status from a local result file if it exists.
        result_file = Path(f"/tmp/oneinfinity_scan_{session_id}.json")
        status = "unknown"
        color  = "#9f9f9f"

        if result_file.exists():
            try:
                data = json.loads(result_file.read_text())
                findings = data.get("findings", [])
                critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
                in_progress = data.get("in_progress", False)
                if in_progress:
                    status = "scanning"
                    color  = "#007ec6"
                elif critical_count > 0:
                    status = "failing"
                    color  = "#e05d44"
                else:
                    status = "passing"
                    color  = "#44cc11"
            except Exception:
                status = "error"
                color  = "#e05d44"
        else:
            status = "not run"
            color  = "#9f9f9f"

        label       = "security scan"
        label_width = 100
        value_width = max(50, len(status) * 8 + 10)
        total_width = label_width + value_width

        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0"  stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1"              stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="{total_width}" height="20" fill="#555"/>
  <rect rx="3" x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
  <rect x="{label_width}" width="4" height="20" fill="{color}"/>
  <rect rx="3" width="{total_width}" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_width // 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_width // 2}" y="14">{label}</text>
    <text x="{label_width + value_width // 2}" y="15" fill="#010101" fill-opacity=".3">{status}</text>
    <text x="{label_width + value_width // 2}" y="14">{status}</text>
  </g>
</svg>"""
        return svg


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

cicd_integration_engine = CICDIntegrationEngine()
