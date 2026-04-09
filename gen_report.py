import os
import sys
import json, html as htmlmod
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

def _fetch_secret_findings():
    """Fetch secret findings from PostgreSQL (hard requirement)."""
    from core.db_manager import get_db_manager_sync
    mgr = get_db_manager_sync()
    if mgr is None or mgr.mode not in ("distributed", "postgres"):
        raise RuntimeError(
            "PostgreSQL is required. Set DB_MODE=postgres or DB_MODE=distributed."
        )
    return mgr.sync_pg_execute_read(
        """
        SELECT finding_id, scan_id, target, title, severity, vuln_type,
               data->>'evidence' AS evidence,
               data->>'payload'  AS payload,
               url, tool, confidence, cvss, status,
               created_at::text  AS created_at,
               data->>'raw_json' AS raw_json
        FROM findings
        WHERE lower(vuln_type) LIKE '%secret%' OR lower(vuln_type) LIKE '%exposed%'
           OR lower(tool) LIKE '%secret%' OR lower(tool) LIKE '%trufflehog%'
           OR lower(tool) LIKE '%gitleaks%'
        ORDER BY
          CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
                        WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5 END,
          created_at DESC
        """
    )


raw_rows = _fetch_secret_findings()

findings = []
for r in raw_rows:
    raw = {}
    try:
        rj = json.loads(r.get('raw_json') or '{}')
        if isinstance(rj.get('raw'), dict):
            raw = rj['raw']
        else:
            raw = rj
    except Exception:
        pass
    findings.append({
        'finding_id': r.get('finding_id') or '',
        'scan_id': r.get('scan_id') or '',
        'target': r.get('target') or '',
        'title': r.get('title') or '',
        'severity': r.get('severity') or 'info',
        'vuln_type': r.get('vuln_type') or '',
        'evidence': r.get('evidence') or '',
        'payload': r.get('payload') or '',
        'url': r.get('url') or '',
        'tool': r.get('tool') or '',
        'confidence': float(r.get('confidence') or 0),
        'cvss': float(r.get('cvss') or 0),
        'status': r.get('status') or 'new',
        'created_at': r.get('created_at') or '',
        'secret_type': raw.get('type', r.get('vuln_type') or ''),
        'entropy': raw.get('entropy', 0) or 0,
        'repo': raw.get('repo', ''),
        'line_number': raw.get('line_number', ''),
        'snippet': raw.get('snippet', ''),
        'value_hash': raw.get('value_hash', ''),
        'fingerprint': raw.get('fingerprint', ''),
        'live_verified': bool(raw.get('live_verified', False)),
        'ai_validated': bool(raw.get('ai_validated', False)),
        'ai_is_real': raw.get('ai_is_real', None),
        'ai_reasoning': raw.get('ai_reasoning', ''),
        'exploitability': float(raw.get('exploitability', 0) or 0),
        'blast_radius': raw.get('blast_radius', '') or '',
        'cross_asset_reuse': bool(raw.get('cross_asset_reuse', False)),
        'impact': raw.get('impact', ''),
        'impact_scenarios': raw.get('impact_scenarios', []) or [],
    })

total = len(findings)
by_sev = {}
by_type = {}
by_target = {}
by_status = {}
ai_validated_count = sum(1 for f in findings if f['ai_validated'])
live_verified_count = sum(1 for f in findings if f['live_verified'])
cross_asset_count = sum(1 for f in findings if f['cross_asset_reuse'])

for f in findings:
    by_sev[f['severity']] = by_sev.get(f['severity'], 0) + 1
    by_type[f['secret_type']] = by_type.get(f['secret_type'], 0) + 1
    by_target[f['target']] = by_target.get(f['target'], 0) + 1
    by_status[f['status']] = by_status.get(f['status'], 0) + 1

sev_order = ['critical', 'high', 'medium', 'low', 'info']
sev_colors = {
    'critical': '#f85149',
    'high': '#ff7b72',
    'medium': '#e3b341',
    'low': '#58a6ff',
    'info': '#8b949e',
}

def esc(s):
    return htmlmod.escape(str(s)) if s else ''

def badge(sev):
    return f'<span class="badge badge-{sev}">{sev.upper()}</span>'

def status_badge(s):
    colors = {'confirmed': '#16a34a', 'new': '#2563eb', 'false_positive': '#9ca3af'}
    c = colors.get(s, '#9ca3af')
    return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:600;">{s.upper()}</span>'

def format_snippet(snippet):
    if not snippet:
        return ''
    return f'<pre class="snippet">{esc(snippet.strip())}</pre>'

now = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

# Severity bars
sev_bars = []
for s in sev_order:
    cnt = by_sev.get(s, 0)
    if cnt == 0:
        continue
    pct = int(cnt / total * 100)
    c = sev_colors[s]
    sev_bars.append(f'''
    <div class="sev-bar-row">
      <span class="sev-label" style="color:{c}">{s.upper()}</span>
      <div class="sev-bar-track">
        <div class="sev-bar-fill" style="width:{pct}%;background:{c}"></div>
      </div>
      <span class="sev-count">{cnt}</span>
    </div>''')
sev_bars_html = '\n'.join(sev_bars)

# Type table
type_rows = []
for t, cnt in sorted(by_type.items(), key=lambda x: -x[1]):
    type_rows.append(f'<tr><td><code>{esc(t)}</code></td><td class="cnt-cell">{cnt}</td></tr>')
type_rows_html = '\n'.join(type_rows)

# Target table
target_rows = []
for t, cnt in sorted(by_target.items(), key=lambda x: -x[1]):
    target_rows.append(f'<tr><td>{esc(t)}</td><td class="cnt-cell">{cnt}</td></tr>')
target_rows_html = '\n'.join(target_rows)

# Filter buttons
filter_btns = ['<button class="filter-btn active" onclick="filterFindings(\'all\', this)">All (' + str(total) + ')</button>']
for s in sev_order:
    cnt = by_sev.get(s, 0)
    if cnt > 0:
        filter_btns.append(
            f'<button class="filter-btn {s}" onclick="filterFindings(\'{s}\', this)">'
            f'{s.capitalize()} ({cnt})</button>'
        )
filter_btns_html = '\n'.join(filter_btns)

# Finding cards
cards = []
for i, f in enumerate(findings):
    sev = f['severity']
    c = sev_colors.get(sev, '#8b949e')

    ai_badge = ''
    if f['ai_validated']:
        ai_badge = '<span class="ai-badge validated">AI VALIDATED</span>'
    elif f['ai_reasoning']:
        ai_badge = f'<span class="ai-badge pending" title="{esc(f["ai_reasoning"])}">AI PENDING</span>'
    live_badge = '<span class="ai-badge live">LIVE VERIFIED</span>' if f['live_verified'] else ''
    cross_badge = '<span class="ai-badge cross">CROSS-ASSET REUSE</span>' if f['cross_asset_reuse'] else ''

    conf_pct = int(f['confidence'] * 100)
    expl_pct = int(f['exploitability'] * 100)

    url_display = f['url'][:100] + ('...' if len(f['url']) > 100 else '') if f['url'] else ''
    url_link = f'<a href="{esc(f["url"])}" target="_blank" class="url-link">{esc(url_display)}</a>' if f['url'] else '&mdash;'

    scenarios_html = ''
    if f['impact_scenarios']:
        items = ''.join(f'<li>{esc(s)}</li>' for s in f['impact_scenarios'])
        scenarios_html = f'<div class="section-label">Impact Scenarios</div><ul class="impact-list">{items}</ul>'

    impact_html = ''
    if f['impact']:
        impact_html = f'<div class="meta-block" style="margin-top:10px"><div class="section-label">Impact</div><p style="margin:4px 0;color:#c9d1d9;font-size:13px">{esc(f["impact"])}</p></div>'

    snippet_html = ''
    if f['snippet']:
        snippet_html = f'<div class="meta-block" style="margin-top:10px"><div class="section-label">Code Snippet</div>{format_snippet(f["snippet"])}</div>'

    ai_reason_html = ''
    if f['ai_reasoning']:
        ai_reason_html = f'<div class="meta-block" style="margin-top:10px"><div class="section-label">AI Reasoning</div><p style="margin:4px 0;color:#6e7681;font-size:12px">{esc(f["ai_reasoning"])}</p></div>'

    hash_info = f' &middot; Hash: {esc(f["value_hash"][:16])}...' if f['value_hash'] else ''
    fp_info = f' &middot; FP: {esc(f["fingerprint"][:16])}...' if f['fingerprint'] else ''

    blast_class = f'blast-{f["blast_radius"].lower()}' if f['blast_radius'] else ''
    blast_val = esc(f['blast_radius']) if f['blast_radius'] else '&mdash;'

    line_val = f'#{f["line_number"]}' if f['line_number'] else '&mdash;'
    repo_val = esc(f['repo']) if f['repo'] else '&mdash;'
    dt_val = esc(f['created_at'][:19].replace('T', ' ')) if f['created_at'] else '&mdash;'
    scan_val = esc(f['scan_id'][:8]) if f['scan_id'] else '&mdash;'

    card = f'''
    <div class="finding-card" data-severity="{sev}" id="f{i}" style="border-left:4px solid {c};">
      <div class="finding-header">
        <div class="finding-title">
          {badge(sev)}
          <span class="title-text">{esc(f["title"])}</span>
        </div>
        <div class="finding-meta-badges">
          {ai_badge}{live_badge}{cross_badge}
          {status_badge(f["status"])}
        </div>
      </div>

      <div class="finding-grid">
        <div class="meta-block">
          <div class="section-label">Secret Type</div>
          <code class="secret-type">{esc(f["secret_type"])}</code>
        </div>
        <div class="meta-block">
          <div class="section-label">Target</div>
          <span>{esc(f["target"])}</span>
        </div>
        <div class="meta-block">
          <div class="section-label">Repository</div>
          <span>{repo_val}</span>
        </div>
        <div class="meta-block">
          <div class="section-label">Line</div>
          <span>{line_val}</span>
        </div>
        <div class="meta-block">
          <div class="section-label">Entropy</div>
          <span class="entropy-val">{f["entropy"]:.3f} bits</span>
        </div>
        <div class="meta-block">
          <div class="section-label">Blast Radius</div>
          <span class="{blast_class}">{blast_val}</span>
        </div>
        <div class="meta-block">
          <div class="section-label">Scan ID</div>
          <code style="font-size:11px">{scan_val}</code>
        </div>
        <div class="meta-block">
          <div class="section-label">Detected</div>
          <span style="font-size:12px">{dt_val}</span>
        </div>
      </div>

      <div class="confidence-row">
        <div class="conf-item">
          <span class="section-label" style="white-space:nowrap">Confidence</span>
          <div class="progress-bar"><div class="progress-fill" style="width:{conf_pct}%;background:{c}"></div></div>
          <span class="conf-pct">{conf_pct}%</span>
        </div>
        <div class="conf-item">
          <span class="section-label" style="white-space:nowrap">Exploitability</span>
          <div class="progress-bar"><div class="progress-fill" style="width:{expl_pct}%;background:#bc8cff"></div></div>
          <span class="conf-pct">{expl_pct}%</span>
        </div>
      </div>

      <div class="meta-block" style="margin-top:14px">
        <div class="section-label">Source URL</div>
        {url_link}
      </div>

      <div class="meta-block" style="margin-top:10px">
        <div class="section-label">Value Preview (Redacted)</div>
        <code class="payload-preview">{esc(f["payload"])}</code>
      </div>

      {impact_html}
      {snippet_html}
      {('<div style="margin-top:10px">' + scenarios_html + '</div>') if scenarios_html else ''}
      {ai_reason_html}

      <div class="finding-footer">
        <code style="font-size:10px;color:#6e7681">ID: {esc(f["finding_id"])}{hash_info}{fp_info}</code>
      </div>
    </div>'''
    cards.append(card)

cards_html = '\n'.join(cards)

# Stat blocks
sev_stats = []
sev_labels = {'critical': ('Critical', '#f85149'), 'high': ('High', '#ff7b72'), 'medium': ('Medium', '#e3b341'), 'low': ('Low', '#58a6ff')}
for s, (label, color) in sev_labels.items():
    sev_stats.append(f'<div class="stat-card"><div class="stat-number" style="color:{color}">{by_sev.get(s, 0)}</div><div class="stat-label">{label}</div></div>')
sev_stats_html = '\n'.join(sev_stats)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OneInfinity &mdash; Exposed Secrets Intelligence Report</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f1117; color: #e1e4e8; line-height: 1.5; }}

.report-header {{ background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%); border-bottom: 1px solid #21262d; padding: 40px 48px 32px; }}
.report-logo {{ font-size: 13px; color: #58a6ff; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; margin-bottom: 16px; }}
.report-title {{ font-size: 32px; font-weight: 800; color: #f0f6fc; margin-bottom: 8px; }}
.report-subtitle {{ font-size: 15px; color: #8b949e; }}
.report-meta {{ display: flex; gap: 32px; margin-top: 20px; flex-wrap: wrap; }}
.report-meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
.report-meta-label {{ font-size: 11px; text-transform: uppercase; color: #6e7681; letter-spacing: 1px; }}
.report-meta-value {{ font-size: 14px; color: #c9d1d9; font-weight: 600; }}

.container {{ max-width: 1400px; margin: 0 auto; padding: 32px 24px; }}

.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 32px; }}
.stat-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 20px; text-align: center; }}
.stat-number {{ font-size: 36px; font-weight: 800; line-height: 1; }}
.stat-label {{ font-size: 12px; color: #8b949e; margin-top: 6px; text-transform: uppercase; letter-spacing: 0.5px; }}

.section {{ margin-bottom: 40px; }}
.section-title {{ font-size: 18px; font-weight: 700; color: #f0f6fc; border-bottom: 1px solid #21262d; padding-bottom: 12px; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}

.analysis-grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 32px; }}
.analysis-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 20px; }}
.analysis-card h3 {{ font-size: 13px; text-transform: uppercase; color: #8b949e; letter-spacing: 1px; margin-bottom: 16px; }}

.sev-bar-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
.sev-label {{ font-size: 12px; font-weight: 700; width: 70px; flex-shrink: 0; }}
.sev-bar-track {{ flex: 1; height: 8px; background: #21262d; border-radius: 4px; overflow: hidden; }}
.sev-bar-fill {{ height: 100%; border-radius: 4px; }}
.sev-count {{ font-size: 13px; font-weight: 700; color: #c9d1d9; width: 24px; text-align: right; }}

table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; padding: 8px 12px; font-size: 11px; text-transform: uppercase; color: #6e7681; border-bottom: 1px solid #21262d; }}
td {{ padding: 8px 12px; border-bottom: 1px solid #1c2128; color: #c9d1d9; }}
tr:hover td {{ background: #1c2128; }}
.cnt-cell {{ text-align: right; font-weight: 700; color: #58a6ff; }}

.badge {{ display: inline-block; padding: 3px 10px; border-radius: 9999px; font-size: 11px; font-weight: 800; letter-spacing: 0.5px; }}
.badge-critical {{ background: #490202; color: #f85149; border: 1px solid #f85149; }}
.badge-high {{ background: #3d1f00; color: #ff7b72; border: 1px solid #ff7b72; }}
.badge-medium {{ background: #3d2f00; color: #e3b341; border: 1px solid #e3b341; }}
.badge-low {{ background: #012a4a; color: #58a6ff; border: 1px solid #58a6ff; }}
.badge-info {{ background: #1c2128; color: #8b949e; border: 1px solid #30363d; }}

.ai-badge {{ display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 700; margin-right: 4px; }}
.ai-badge.validated {{ background: #1a3a2a; color: #3fb950; border: 1px solid #3fb950; }}
.ai-badge.pending {{ background: #1f1a3a; color: #bc8cff; border: 1px solid #bc8cff; cursor: help; }}
.ai-badge.live {{ background: #1a2a3a; color: #58a6ff; border: 1px solid #58a6ff; }}
.ai-badge.cross {{ background: #3a1a2a; color: #f85149; border: 1px solid #f85149; }}

.finding-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 24px; margin-bottom: 16px; }}
.finding-card:hover {{ box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
.finding-header {{ display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 16px; gap: 12px; flex-wrap: wrap; }}
.finding-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.title-text {{ font-size: 15px; font-weight: 600; color: #f0f6fc; }}
.finding-meta-badges {{ display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }}

.finding-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 12px; }}
.meta-block {{ }}
.section-label {{ font-size: 10px; text-transform: uppercase; color: #6e7681; letter-spacing: 1px; margin-bottom: 3px; }}

.secret-type {{ background: #1f1a3a; color: #a78bfa; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
.payload-preview {{ background: #0d1117; color: #e3b341; padding: 4px 10px; border-radius: 4px; font-size: 12px; border: 1px solid #21262d; word-break: break-all; display: inline-block; }}
.entropy-val {{ color: #58a6ff; font-weight: 600; }}

.blast-high {{ color: #f85149; font-weight: 700; }}
.blast-critical {{ color: #f85149; font-weight: 700; }}
.blast-medium {{ color: #e3b341; font-weight: 700; }}
.blast-low {{ color: #58a6ff; font-weight: 700; }}

.confidence-row {{ display: flex; gap: 24px; margin-top: 12px; flex-wrap: wrap; }}
.conf-item {{ display: flex; align-items: center; gap: 8px; flex: 1; min-width: 200px; }}
.progress-bar {{ flex: 1; height: 6px; background: #21262d; border-radius: 3px; overflow: hidden; }}
.progress-fill {{ height: 100%; border-radius: 3px; }}
.conf-pct {{ font-size: 12px; font-weight: 700; color: #c9d1d9; width: 36px; }}

.snippet {{ background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 12px; font-size: 12px; color: #c9d1d9; overflow-x: auto; margin-top: 4px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }}

.url-link {{ color: #58a6ff; text-decoration: none; font-size: 12px; word-break: break-all; }}
.url-link:hover {{ text-decoration: underline; }}

.impact-list {{ padding-left: 20px; margin-top: 4px; }}
.impact-list li {{ font-size: 13px; color: #c9d1d9; margin-bottom: 3px; }}

.finding-footer {{ margin-top: 16px; padding-top: 12px; border-top: 1px solid #21262d; }}

.filter-bar {{ display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }}
.filter-btn {{ padding: 6px 16px; border-radius: 6px; border: 1px solid #30363d; background: #161b22; color: #8b949e; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.15s; }}
.filter-btn:hover {{ border-color: #58a6ff; color: #58a6ff; }}
.filter-btn.active {{ border-color: #58a6ff; color: #58a6ff; background: #1c2a3a; }}
.filter-btn.critical.active {{ border-color: #f85149; color: #f85149; background: #2a1c1c; }}
.filter-btn.high.active {{ border-color: #ff7b72; color: #ff7b72; background: #2a1c1c; }}
.filter-btn.medium.active {{ border-color: #e3b341; color: #e3b341; background: #2a2000; }}
.filter-btn.low.active {{ border-color: #58a6ff; color: #58a6ff; background: #012a4a; }}

.risk-box {{ background: #161b22; border: 1px solid #f85149; border-radius: 10px; padding: 24px; margin-bottom: 32px; }}
.risk-box h3 {{ font-size: 15px; font-weight: 700; color: #f85149; margin-bottom: 12px; }}
.risk-text {{ font-size: 14px; color: #8b949e; line-height: 1.8; }}
.risk-text strong {{ color: #f0f6fc; }}

.remediation-box {{ background: #161b22; border: 1px solid #3fb950; border-radius: 10px; padding: 24px; margin-bottom: 32px; }}
.remediation-box h3 {{ font-size: 15px; font-weight: 700; color: #3fb950; margin-bottom: 12px; }}
.remediation-list {{ list-style: none; padding: 0; }}
.remediation-list li {{ padding: 6px 0; font-size: 13px; color: #c9d1d9; border-bottom: 1px solid #21262d; display: flex; gap: 10px; }}
.remediation-list li:last-child {{ border-bottom: none; }}
.step-num {{ background: #1a3a2a; color: #3fb950; border-radius: 50%; width: 22px; height: 22px; display: inline-flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; flex-shrink: 0; }}

.report-footer {{ background: #0d1117; border-top: 1px solid #21262d; padding: 24px 48px; margin-top: 48px; text-align: center; color: #6e7681; font-size: 12px; }}

@media (max-width: 900px) {{
  .analysis-grid {{ grid-template-columns: 1fr; }}
  .report-header {{ padding: 24px; }}
  .container {{ padding: 16px; }}
}}
@media print {{
  .filter-bar {{ display: none; }}
  body {{ background: white; color: black; }}
}}
</style>
</head>
<body>

<div class="report-header">
  <div class="report-logo">&#9889; OneInfinity Security Intelligence</div>
  <div class="report-title">Exposed Secrets Intelligence Report</div>
  <div class="report-subtitle">Automated GitHub source scanning &mdash; SecretIntelAgent with AI-assisted validation &amp; risk scoring</div>
  <div class="report-meta">
    <div class="report-meta-item">
      <span class="report-meta-label">Generated</span>
      <span class="report-meta-value">{now}</span>
    </div>
    <div class="report-meta-item">
      <span class="report-meta-label">Total Findings</span>
      <span class="report-meta-value">{total}</span>
    </div>
    <div class="report-meta-item">
      <span class="report-meta-label">Scanner</span>
      <span class="report-meta-value">SecretIntelAgent</span>
    </div>
    <div class="report-meta-item">
      <span class="report-meta-label">Database</span>
      <span class="report-meta-value">findings.db</span>
    </div>
    <div class="report-meta-item">
      <span class="report-meta-label">Classification</span>
      <span class="report-meta-value" style="color:#f85149;">CONFIDENTIAL</span>
    </div>
  </div>
</div>

<div class="container">

  <!-- STATS -->
  <div class="section">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-number" style="color:#7ee787">{total}</div>
        <div class="stat-label">Total Secrets Found</div>
      </div>
      {sev_stats_html}
      <div class="stat-card">
        <div class="stat-number" style="color:#bc8cff">{ai_validated_count}</div>
        <div class="stat-label">AI Validated</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color:#3fb950">{live_verified_count}</div>
        <div class="stat-label">Live Verified</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color:#f85149">{cross_asset_count}</div>
        <div class="stat-label">Cross-Asset Reuse</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color:#58a6ff">{len(by_type)}</div>
        <div class="stat-label">Secret Types Detected</div>
      </div>
      <div class="stat-card">
        <div class="stat-number" style="color:#e3b341">{len(by_target)}</div>
        <div class="stat-label">Targets Affected</div>
      </div>
    </div>
  </div>

  <!-- EXECUTIVE RISK ASSESSMENT -->
  <div class="risk-box">
    <h3>&#9888;&#65039; Executive Risk Assessment</h3>
    <div class="risk-text">
      OneInfinity&apos;s SecretIntelAgent identified <strong>{total} exposed secrets</strong> across
      <strong>{len(by_target)} target(s)</strong> through automated GitHub source scanning.
      <strong>{by_sev.get("critical", 0)} CRITICAL severity findings</strong> were detected including
      AWS access keys and cloud infrastructure credentials &mdash; these represent immediate unauthorized
      access risk to cloud infrastructure.
      <strong>{by_sev.get("high", 0)} HIGH severity findings</strong> include database URIs
      (PostgreSQL, MongoDB, Redis), API tokens, and connection strings with direct data access implications.
      {f"<strong>Cross-asset credential reuse was detected across {cross_asset_count} finding(s)</strong> &mdash; a single compromised credential may unlock multiple systems simultaneously." if cross_asset_count > 0 else ""}
      All exposed credentials must be treated as <strong>fully compromised</strong> and rotated immediately.
      Do not assume secrets are unexploited because live_verified is false &mdash; GitHub
      indexes commits; exposed keys may have been harvested by automated scanners before discovery.
    </div>
  </div>

  <!-- REMEDIATION -->
  <div class="remediation-box">
    <h3>&#9989; Immediate Remediation Checklist</h3>
    <ul class="remediation-list">
      <li><span class="step-num">1</span><span><strong>Rotate ALL exposed credentials immediately</strong> &mdash; treat every finding as confirmed-compromised regardless of live_verified status</span></li>
      <li><span class="step-num">2</span><span><strong>AWS Keys (CRITICAL):</strong> Deactivate via IAM console, audit CloudTrail for unauthorized usage in last 90 days, enable GuardDuty if not active</span></li>
      <li><span class="step-num">3</span><span><strong>Database URIs (HIGH):</strong> Rotate passwords, audit access logs, check for unauthorized schema changes or data exfiltration</span></li>
      <li><span class="step-num">4</span><span><strong>Redis URIs (HIGH):</strong> Rotate credentials, flush suspicious sessions, check for CONFIG SET exploit attempts in logs</span></li>
      <li><span class="step-num">5</span><span><strong>Remove secrets from Git history</strong> using git-filter-repo or BFG Repo Cleaner &mdash; deleting the file is not sufficient</span></li>
      <li><span class="step-num">6</span><span><strong>Implement pre-commit hooks</strong> with detect-secrets or gitleaks to prevent future secret commits</span></li>
      <li><span class="step-num">7</span><span><strong>Migrate to secrets managers:</strong> AWS Secrets Manager, HashiCorp Vault, or GitHub Actions Secrets for all credentials</span></li>
      <li><span class="step-num">8</span><span><strong>Enable GitHub Secret Scanning</strong> on all repositories to catch future leaks at push time</span></li>
    </ul>
  </div>

  <!-- ANALYSIS -->
  <div class="section">
    <div class="section-title">&#128202; Distribution Analysis</div>
    <div class="analysis-grid">
      <div class="analysis-card">
        <h3>By Severity</h3>
        {sev_bars_html}
      </div>
      <div class="analysis-card">
        <h3>By Secret Type</h3>
        <table>
          <thead><tr><th>Type</th><th style="text-align:right">Count</th></tr></thead>
          <tbody>{type_rows_html}</tbody>
        </table>
      </div>
      <div class="analysis-card">
        <h3>By Target</h3>
        <table>
          <thead><tr><th>Target</th><th style="text-align:right">Count</th></tr></thead>
          <tbody>{target_rows_html}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- FINDINGS -->
  <div class="section">
    <div class="section-title">&#128269; All Findings ({total})</div>
    <div class="filter-bar">
      {filter_btns_html}
    </div>
    <div id="findingsContainer">
      {cards_html}
    </div>
  </div>

</div>

<div class="report-footer">
  Generated by <strong>OneInfinity SecretIntelAgent</strong> &mdash; {now}
  &mdash; <strong style="color:#f85149;">CONFIDENTIAL</strong>
  &mdash; For authorized security personnel only &mdash; Do not distribute
</div>

<script>
function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(function(b) {{
    b.classList.remove('active');
  }});
  btn.classList.add('active');
  document.querySelectorAll('#findingsContainer .finding-card').forEach(function(card) {{
    if (sev === 'all') {{
      card.style.display = '';
    }} else {{
      card.style.display = (card.dataset.severity === sev) ? '' : 'none';
    }}
  }});
}}
</script>

</body>
</html>"""

output_dir = os.path.join(os.path.dirname(__file__), 'output')
os.makedirs(output_dir, exist_ok=True)
out = os.path.join(output_dir, 'exposed_secrets_report.html')
with open(out, 'w', encoding='utf-8') as fh:
    fh.write(HTML)
print(f"DONE: {out}")
print(f"Size: {len(HTML):,} bytes")
print(f"Findings: {len(findings)}")
print(f"Severity breakdown: {dict(by_sev)}")
