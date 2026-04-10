import json, os
from datetime import datetime
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>Ransomware Forensic Report</title>
<style>
  body{font-family:Consolas,monospace;background:#0d1117;color:#c9d1d9;padding:32px;line-height:1.7}
  h1{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:12px}
  h2{color:#7ee787;margin-top:32px}
  .meta{color:#8b949e;font-size:13px;margin-bottom:24px}
  .alert-box{background:#3d1a1a;border:1px solid #f85149;padding:16px;border-radius:8px;margin:16px 0}
  .ok-box{background:#0d2a1a;border:1px solid #56d364;padding:16px;border-radius:8px;margin:16px 0}
  table{width:100%;border-collapse:collapse;margin:16px 0}
  th{background:#161b22;color:#8b949e;padding:10px;text-align:left;font-size:12px;text-transform:uppercase}
  td{padding:9px 10px;border-bottom:1px solid #21262d;font-size:13px}
  .badge-red{background:#3d1a1a;color:#f85149;padding:2px 8px;border-radius:4px;font-size:11px}
  .badge-green{background:#0d2a1a;color:#56d364;padding:2px 8px;border-radius:4px;font-size:11px}
  .score-bar{height:12px;background:#1c2128;border-radius:6px;margin:8px 0;overflow:hidden}
  .score-fill{height:100%;background:linear-gradient(90deg,#f85149,#ff7b72);border-radius:6px}
  .mitre-row td{font-size:12px}
  code{background:#161b22;padding:2px 6px;border-radius:3px;color:#79c0ff}
</style></head><body>
<h1>🔍 Ransomware Forensic Investigation Report</h1>
<div class="meta">Generated: {{ timestamp }} | Case ID: {{ case_id }}</div>

{% if alert %}
<div class="alert-box">🚨 <strong>RANSOMWARE ACTIVITY CONFIRMED</strong> — Risk Score: {{ score }}/100</div>
{% else %}
<div class="ok-box">✅ No high-confidence ransomware indicators detected (Score: {{ score }}/100)</div>
{% endif %}

<div class="score-bar"><div class="score-fill" style="width:{{ score }}%"></div></div>

<h2>1. File System Findings</h2>
<table><thead><tr><th>File</th><th>Extension</th><th>Family</th><th>Size</th></tr></thead><tbody>
{% for f in encrypted_files %}<tr>
  <td><code>{{ f.path }}</code></td>
  <td><span class="badge-red">{{ f.extension }}</span></td>
  <td>{{ f.family }}</td>
  <td>{{ f.size_bytes }} B</td>
</tr>{% endfor %}</tbody></table>

<h2>2. MITRE ATT&CK Techniques Detected</h2>
<table><thead><tr><th>ID</th><th>Name</th><th>Tactic</th></tr></thead><tbody>
{% for t in mitre %}<tr class="mitre-row">
  <td><span class="badge-red">{{ t.id }}</span></td>
  <td>{{ t.name }}</td>
  <td>{{ t.tactic }}</td>
</tr>{% endfor %}</tbody></table>

<h2>3. Attack Timeline</h2>
<table><thead><tr><th>Time</th><th>Phase</th><th>Source</th><th>Description</th></tr></thead><tbody>
{% for e in timeline %}<tr>
  <td>{{ e.time[:19] }}</td>
  <td>{% if e.suspicious %}<span class="badge-red">{{ e.phase }}</span>{% else %}<span class="badge-green">{{ e.phase }}</span>{% endif %}</td>
  <td>{{ e.source }}</td>
  <td>{{ e.description }}</td>
</tr>{% endfor %}</tbody></table>
</body></html>
"""

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def generate_report():
    corr   = load_json('reports/correlation_result.json', {})
    scan   = load_json('reports/file_scan_results.json', {})
    mitre  = load_json('reports/mitre_mapping.json', [])
    tl     = load_json('reports/attack_timeline.json', [])

    html = Template(HTML_TEMPLATE).render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        case_id=f"RFC-{datetime.now().strftime('%Y%m%d%H%M')}",
        score=corr.get('score', 0),
        alert=corr.get('alert', False),
        encrypted_files=scan.get('encrypted_files', []),
        mitre=mitre,
        timeline=tl
    )

    os.makedirs("reports", exist_ok=True)

    out = f"reports/forensic_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html"

    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[✓] Report saved: {out}")
    return out

if __name__ == '__main__':
    generate_report()