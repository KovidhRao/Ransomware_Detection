import json, os, hashlib
from datetime import datetime
from jinja2 import Template

def load(p, d=None):
    try:
        with open(p, encoding='utf-8') as f: return json.load(f)
    except: return d if d is not None else []

def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except: return 'N/A'

def severity_label(score):
    if score >= 80: return ('CRITICAL', '#ef4444')
    if score >= 60: return ('HIGH',     '#f97316')
    if score >= 40: return ('MEDIUM',   '#eab308')
    return ('LOW', '#22c55e')

TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Forensic Report — {{ case_id }}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono&family=Inter:wght@400;500;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box;}
body{background:#0a0a0f;color:#e2e8f0;font-family:'Inter',sans-serif;font-size:14px;line-height:1.7;}
.page{max-width:900px;margin:0 auto;padding:40px 32px;}
.cover{border:1px solid #1e2030;border-radius:16px;padding:48px;margin-bottom:40px;background:#0f1018;position:relative;overflow:hidden;}
.cover::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,{{ sev_color }},#818cf8);}
.cover-label{font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:#4a5568;margin-bottom:12px;}
.cover-title{font-size:28px;font-weight:700;margin-bottom:8px;}
.cover-meta{color:#64748b;font-size:13px;display:flex;flex-direction:column;gap:4px;margin-top:20px;}
.sev-badge{display:inline-block;padding:6px 18px;border-radius:6px;font-weight:700;font-size:13px;font-family:'IBM Plex Mono',monospace;letter-spacing:.05em;background:{{ sev_color }}22;color:{{ sev_color }};border:1px solid {{ sev_color }}44;margin-top:16px;}
h2{font-size:16px;font-weight:700;color:#38bdf8;margin:36px 0 12px;padding-bottom:8px;border-bottom:1px solid #1e2030;display:flex;align-items:center;gap:10px;}
h2 .num{font-family:'IBM Plex Mono',monospace;font-size:10px;background:#1e2030;padding:3px 8px;border-radius:4px;color:#64748b;}
.score-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:12px 0;}
.sc{background:#0f1018;border:1px solid #1e2030;border-radius:10px;padding:16px;}
.sc-label{font-size:11px;font-family:'IBM Plex Mono',monospace;text-transform:uppercase;letter-spacing:.05em;color:#4a5568;margin-bottom:6px;}
.sc-val{font-size:24px;font-weight:700;}
.score-bar-wrap{height:8px;background:#1e2030;border-radius:4px;margin:12px 0;overflow:hidden;}
.score-bar-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,{{ sev_color }},#818cf8);}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:13px;}
th{background:#0f1018;color:#64748b;font-family:'IBM Plex Mono',monospace;font-size:10px;text-transform:uppercase;letter-spacing:.05em;padding:9px 12px;text-align:left;border-bottom:1px solid #1e2030;}
td{padding:9px 12px;border-bottom:1px solid #0f1520;vertical-align:top;}
tr:hover td{background:#0f1220;}
.ebar-wrap{display:flex;align-items:center;gap:10px;}
.ebar{height:8px;border-radius:4px;min-width:4px;}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-family:'IBM Plex Mono',monospace;font-size:10px;}
.b-r{background:#ef444420;color:#ef4444;border:1px solid #ef444430;}
.b-g{background:#22c55e20;color:#22c55e;border:1px solid #22c55e30;}
.b-b{background:#38bdf820;color:#38bdf8;border:1px solid #38bdf830;}
.b-p{background:#818cf820;color:#818cf8;border:1px solid #818cf830;}
.tl-item{display:flex;gap:14px;margin-bottom:12px;}
.tl-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;margin-top:5px;}
.tl-line{display:flex;flex-direction:column;gap:2px;}
.tl-time{font-family:'IBM Plex Mono',monospace;font-size:11px;color:#64748b;}
.tl-desc{font-size:13px;}
.ioc-box{background:#0d0d14;border:1px solid #1e2030;border-radius:8px;padding:14px;margin:8px 0;font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:#a5d6ff;word-break:break-all;}
.reco-item{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid #0f1520;}
.reco-num{width:28px;height:28px;border-radius:7px;background:#0f1018;border:1px solid #1e2030;display:flex;align-items:center;justify-content:center;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#38bdf8;flex-shrink:0;}
.exec-box{background:#0f1018;border-left:3px solid #38bdf8;padding:16px 20px;border-radius:0 8px 8px 0;margin:12px 0;font-size:14px;color:#94a3b8;line-height:1.8;}
code{font-family:'IBM Plex Mono',monospace;font-size:11px;background:#1e2030;padding:2px 6px;border-radius:3px;color:#a5d6ff;}
.footer{margin-top:48px;padding-top:20px;border-top:1px solid #1e2030;font-size:12px;color:#4a5568;font-family:'IBM Plex Mono',monospace;display:flex;justify-content:space-between;}
</style></head>
<body><div class="page">

<div class="cover">
  <div class="cover-label">Digital Forensic Investigation Report</div>
  <div class="cover-title">Ransomware Post-Incident Analysis</div>
  <div class="sev-badge">{{ severity }} SEVERITY</div>
  <div class="cover-meta">
    <span>Case ID: <strong style="color:#e2e8f0">{{ case_id }}</strong></span>
    <span>Analyst: <strong style="color:#e2e8f0">Forensic Investigation Framework v1.0</strong></span>
    <span>Date: <strong style="color:#e2e8f0">{{ report_date }}</strong></span>
    <span>Classification: <strong style="color:#e2e8f0">ACADEMIC — SIMULATED ENVIRONMENT</strong></span>
  </div>
</div>

<h2><span class="num">01</span> Executive Summary</h2>
<div class="exec-box">
Forensic analysis identified strong indicators of a ransomware attack. 
A total of <strong style="color:#f87171">{{ enc_count }} files</strong> were found with ransomware-associated extensions.
Risk score is <strong style="color:{{ sev_color }}">{{ score }}/100 ({{ severity }})</strong>.
</div>

<h2><span class="num">02</span> Risk Scorecard</h2>
<div class="score-row">
  <div class="sc"><div class="sc-label">Overall Score</div><div class="sc-val" style="color:{{ sev_color }}">{{ score }}/100</div></div>
  <div class="sc"><div class="sc-label">Encrypted Files</div><div class="sc-val" style="color:#f87171">{{ enc_count }}</div></div>
  <div class="sc"><div class="sc-label">MITRE Techniques</div><div class="sc-val" style="color:#818cf8">{{ mitre_count }}</div></div>
  <div class="sc"><div class="sc-label">Timeline Events</div><div class="sc-val" style="color:#38bdf8">{{ tl_count }}</div></div>
</div>
<div class="score-bar-wrap"><div class="score-bar-fill" style="width:{{ score }}%"></div></div>

<h2><span class="num">03</span> File System Evidence</h2>
<table><thead><tr><th>Filename</th><th>Ext</th><th>Family</th><th>Entropy</th><th>Size</th></tr></thead><tbody>
{% for f in encrypted_files %}<tr>
  <td><code>{{ f.path.split('\\\\')[-1] }}</code></td>
  <td><span class="badge b-r">{{ f.extension }}</span></td>
  <td>{{ f.family }}</td>
  <td>{{ "%.3f"|format(f.entropy|default(7.9)) }}</td>
  <td>{{ f.size_bytes }} B</td>
</tr>{% endfor %}</tbody></table>

<h2><span class="num">04</span> MITRE ATT&CK Mapping</h2>
<table><thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th></tr></thead><tbody>
{% for t in mitre %}<tr>
  <td><span class="badge b-r">{{ t.id }}</span></td>
  <td><strong>{{ t.name }}</strong></td>
  <td><span class="badge b-p">{{ t.tactic }}</span></td>
</tr>{% endfor %}</tbody></table>

<h2><span class="num">05</span> attack Timeline</h2>
{% for e in timeline %}<div class="tl-item">
  <div class="tl-dot" style="background:{% if e.suspicious %}#ef4444{% else %}#22c55e{% endif %}"></div>
  <div class="tl-line">
    <div class="tl-time">{{ e.time[:19] }} | {{ e.source }}</div>
    <div class="tl-desc">{{ e.description }}</div>
  </div>
</div>{% endfor %}

<div class="footer">
  <span>Case: {{ case_id }}</span>
  <span>Generated: {{ report_date }}</span>
</div>
</div></body></html>"""

RECOMMENDATIONS = [
    {'title': 'Immediate Network Isolation', 'detail': 'Disconnect affected system from network.'},
    {'title': 'Preserve Evidence', 'detail': 'Create a full disk image and memory dump.'},
]

def generate_enhanced_report():
    corr   = load('reports/correlation_result.json', {})
    scan   = load('reports/file_scan_results.json',  {})
    reg    = load('reports/registry_findings.json',   [])
    mitre  = load('reports/mitre_mapping.json',        [])
    tl     = load('reports/attack_timeline.json',      [])
    ent    = load('reports/entropy_results.json',       [])

    score = corr.get('score', 0)
    severity, sev_color = severity_label(score)

    enc_files = scan.get('encrypted_files', [])
    entropy_map = {r['file']: r['entropy'] for r in ent}
    for ef in enc_files:
        ef['entropy'] = entropy_map.get(ef['path'], 7.9)
        ef['sha256'] = sha256_file(ef['path'])

    suspicious_ent = [r['entropy'] for r in ent if r.get('suspicious')]
    mean_ent = round(sum(suspicious_ent) / len(suspicious_ent), 3) if suspicious_ent else 0.0

    html = Template(TEMPLATE).render(
        case_id=f"RFC-{datetime.now().strftime('%Y%m%d-%H%M')}",
        report_date=datetime.now().strftime("%d %B %Y, %H:%M:%S"),
        score=score, severity=severity, sev_color=sev_color,
        enc_count=len(enc_files),
        reg_count=len([r for r in reg if r.get('suspicious')]),
        mitre_count=len(mitre), tl_count=len(tl),
        mean_entropy=mean_ent,
        encrypted_files=enc_files,
        ransom_notes=scan.get('ransom_notes', []),
        registry=reg, mitre=mitre, timeline=tl,
        recommendations=RECOMMENDATIONS
    )

    out = f"reports/enhanced_forensic_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
    os.makedirs('reports', exist_ok=True)
    with open(out, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[✓] Enhanced report saved: {out}")
    return out

if __name__ == '__main__':
    generate_enhanced_report()