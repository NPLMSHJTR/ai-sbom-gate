"""Self-contained interactive HTML5 AI-SBOM compliance dashboard generator."""

from __future__ import annotations

import html

from ai_sbom_gate.models import ComplianceReport


def render_html_report(report: ComplianceReport) -> str:
    score = report.compliance_score
    score_color = "#10b981" if score >= 85 else "#f59e0b" if score >= 60 else "#ef4444"
    counts = report.severity_counts
    type_counts = report.asset_type_counts

    finding_rows: list[str] = []
    for f in report.findings:
        sev_cls = f.severity.value.lower()
        alts_html = (
            "<div class='alts'><strong>Permissive Alternatives:</strong> "
            + html.escape("; ".join(f.suggested_alternatives))
            + "</div>"
            if f.suggested_alternatives
            else ""
        )
        finding_rows.append(
            f"""
            <tr class="row-item" data-sev="{html.escape(sev_cls)}">
              <td><span class="badge badge-{html.escape(sev_cls)}">{html.escape(f.severity.value)}</span></td>
              <td><code>{html.escape(f.rule_id)}</code></td>
              <td><code>{html.escape(f.asset_name)}</code><br><small>{html.escape(f.asset_type.value)}</small></td>
              <td><code>{html.escape(f.detected_license)}</code></td>
              <td><code>{html.escape(f.source_file)}:{f.line_number}</code></td>
              <td>
                <div>{html.escape(f.message)}</div>
                <div class="rem">{html.escape(f.remediation)}</div>
                {alts_html}
              </td>
            </tr>
            """
        )

    asset_rows: list[str] = []
    for a in report.assets:
        asset_rows.append(
            f"""
            <tr>
              <td><code>{html.escape(a.name)}</code></td>
              <td>{html.escape(a.asset_type.value)}</td>
              <td><code>{html.escape(a.normalized_license)}</code></td>
              <td>{html.escape(a.license_category.value)}</td>
              <td><code>{html.escape(a.source_file)}:{a.line_number}</code></td>
            </tr>
            """
        )

    max_v = max(1, max(counts.values()))
    bars: list[str] = []
    for idx, (label, val, fill) in enumerate(
        [
            ("CRITICAL", counts["CRITICAL"], "#dc2626"),
            ("HIGH", counts["HIGH"], "#ea580c"),
            ("MEDIUM", counts["MEDIUM"], "#d97706"),
            ("LOW", counts["LOW"], "#0284c7"),
        ]
    ):
        y = 10 + idx * 26
        w = max(2, int((val / max_v) * 160))
        bars.append(
            f'<text x="0" y="{y + 13}" font-size="11" fill="#94a3b8" font-family="monospace">{label}</text>'
            f'<rect x="74" y="{y + 2}" width="{w}" height="14" rx="3" fill="{fill}" />'
            f'<text x="{82 + w}" y="{y + 13}" font-size="11" fill="#e2e8f0" font-family="monospace">{val}</text>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI-SBOM-Gate Report - {html.escape(report.target)}</title>
  <style>
    :root {{ --bg:#0b1120; --card:#111827; --border:#1f2937; --text:#f3f4f6; --muted:#9ca3af; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; padding:24px; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,sans-serif; }}
    .wrap {{ max-width:1200px; margin:0 auto; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:16px; margin-bottom:18px; }}
    .card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; margin-bottom:18px; }}
    .kpi {{ font-size:28px; font-weight:800; margin-top:6px; }}
    .label {{ color:var(--muted); font-size:12px; text-transform:uppercase; }}
    table {{ width:100%; border-collapse:collapse; font-size:13px; }}
    th, td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--border); vertical-align:top; }}
    th {{ color:var(--muted); }}
    code {{ background:#030712; padding:2px 6px; border-radius:4px; color:#38bdf8; font-size:12px; }}
    .badge {{ display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:700; }}
    .badge-critical {{ background:#7f1d1d; color:#fecaca; }}
    .badge-high {{ background:#7c2d12; color:#fed7aa; }}
    .badge-medium {{ background:#78350f; color:#fde68a; }}
    .badge-low {{ background:#0c4a6e; color:#bae6fd; }}
    .rem {{ color:#94a3b8; font-size:12px; margin-top:4px; }}
    .alts {{ color:#86efac; font-size:12px; margin-top:4px; }}
    input, select {{ background:#030712; color:var(--text); border:1px solid var(--border); padding:7px 10px; border-radius:8px; margin-right:8px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>AI-SBOM Compliance Report</h1>
    <p style="color:#9ca3af;">Target: <code>{html.escape(report.target)}</code> &middot; Policy: <code>{html.escape(report.policy.value)}</code> &middot; Project License: <code>{html.escape(report.declared_project_license)}</code></p>
    <div class="grid">
      <div class="card"><div class="label">Compliance Score</div><div class="kpi" style="color:{score_color};">{score} / 100</div></div>
      <div class="card"><div class="label">Total Assets</div><div class="kpi">{len(report.assets)}</div><small style="color:#9ca3af;">Py {type_counts['python-package']} / JS {type_counts['node-package']} / Models {type_counts['hf-model']} / Data {type_counts['hf-dataset']}</small></div>
      <div class="card"><div class="label">Findings</div><div class="kpi">{len(report.findings)}</div></div>
      <div class="card"><div class="label">Severity Mix</div><svg width="280" height="114">{''.join(bars)}</svg></div>
    </div>

    <section class="card">
      <h2>License Conflicts &amp; Warnings</h2>
      <div style="margin-bottom:12px;">
        <input id="q" type="search" placeholder="Filter findings..." oninput="flt()" />
        <select id="s" onchange="flt()">
          <option value="all">All Severities</option>
          <option value="critical">CRITICAL</option>
          <option value="high">HIGH</option>
          <option value="medium">MEDIUM</option>
          <option value="low">LOW</option>
        </select>
      </div>
      <table>
        <thead><tr><th>Severity</th><th>Rule</th><th>Asset</th><th>License</th><th>Source</th><th>Details &amp; Alternatives</th></tr></thead>
        <tbody>{''.join(finding_rows) or '<tr><td colspan="6" style="color:#86efac;text-align:center;">No compliance violations detected.</td></tr>'}</tbody>
      </table>
    </section>

    <section class="card">
      <h2>Discovered AI-SBOM Inventory ({len(report.assets)})</h2>
      <table>
        <thead><tr><th>Name</th><th>Type</th><th>Normalized License</th><th>Category</th><th>Source</th></tr></thead>
        <tbody>{''.join(asset_rows) or '<tr><td colspan="5">No assets discovered.</td></tr>'}</tbody>
      </table>
    </section>
  </div>
  <script>
    function flt() {{
      const q = document.getElementById("q").value.toLowerCase();
      const s = document.getElementById("s").value;
      document.querySelectorAll(".row-item").forEach((r) => {{
        const okS = s === "all" || r.dataset.sev === s;
        const okT = !q || r.innerText.toLowerCase().includes(q);
        r.style.display = (okS && okT) ? "" : "none";
      }});
    }}
  </script>
</body>
</html>
"""
