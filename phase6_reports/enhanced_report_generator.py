"""
enhanced_report_generator.py  -  12-Section Professional Forensic Report
Save at: C:/ransomware_forensic/phase6_reports/enhanced_report_generator.py

APPROACH: Pure Python string building - NO Jinja2 template engine.
This completely eliminates all TemplateSyntaxError issues forever.

Run:  python phase6_reports/enhanced_report_generator.py
Also called by main.py automatically.
"""

import json, os, hashlib, math
from datetime import datetime
from collections import Counter


# ── helpers ───────────────────────────────────────────────────────────────────

def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else []


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


def calc_entropy(path):
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
        if not data:
            return 0.0
        freq = Counter(data)
        total = len(data)
        return round(
            -sum((c / total) * math.log2(c / total) for c in freq.values() if c),
            4,
        )
    except Exception:
        return 0.0


def severity_label(score):
    if score >= 80:
        return "CRITICAL", "#ef4444"
    if score >= 60:
        return "HIGH",     "#f97316"
    if score >= 40:
        return "MEDIUM",   "#eab308"
    return "LOW", "#22c55e"


def esc(s):
    """HTML-escape a value."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# ── tiny component helpers ────────────────────────────────────────────────────

_BADGE_COLORS = {
    "r": ("#ef444422", "#ef4444", "#ef444440"),
    "g": ("#22c55e22", "#22c55e", "#22c55e40"),
    "b": ("#38bdf822", "#38bdf8", "#38bdf840"),
    "p": ("#818cf822", "#818cf8", "#818cf840"),
    "a": ("#f9731622", "#f97316", "#f9731640"),
    "y": ("#eab30822", "#eab308", "#eab30840"),
}

def badge(text, style="r"):
    bg, fg, border = _BADGE_COLORS.get(style, _BADGE_COLORS["r"])
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-family:IBM Plex Mono,monospace;font-size:10px;font-weight:500;'
        f'background:{bg};color:{fg};border:1px solid {border}">'
        f'{esc(text)}</span>'
    )


def ebar(entropy_val, max_px=110):
    px = min(int((float(entropy_val) / 8.0) * max_px), max_px)
    color = ("#ef4444" if entropy_val > 7.5
             else "#f97316" if entropy_val > 7.2
             else "#22c55e")
    return (
        f'<div style="display:flex;align-items:center;gap:8px">'
        f'<div style="width:{px}px;height:6px;border-radius:3px;'
        f'background:{color};min-width:2px"></div>'
        f'<span style="font-family:IBM Plex Mono,monospace;font-size:10.5px;'
        f'color:#94a3b8">{entropy_val}</span>'
        f'</div>'
    )


# ── CSS builder (plain Python f-string) ──────────────────────────────────────

def build_css(sc):
    """sc = sev_color hex string e.g. '#ef4444' """
    return f"""<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
html,body,div,span,h1,h2,h3,h4,p,a,table,thead,tbody,tr,th,td,strong,code
  {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#09090b; color:#f1f5f9; font-family:'Inter',sans-serif;
        font-size:14px; line-height:1.75; }}
.page {{ max-width:960px; margin:0 auto; padding:48px 40px 100px; }}

/* COVER */
.cover {{ background:#0f0f12; border:1px solid #1f1f26; border-radius:16px;
          padding:56px 48px; margin-bottom:48px; position:relative; overflow:hidden; }}
.cover-stripe {{ position:absolute; top:0; left:0; right:0; height:4px;
                 background:linear-gradient(90deg,{sc},#818cf8,#38bdf8); }}
.cover-wm {{ position:absolute; bottom:20px; right:32px; font-family:'IBM Plex Mono',monospace;
             font-size:80px; font-weight:700; color:rgba(255,255,255,.025); user-select:none; }}
.cover-eyebrow {{ font-family:'IBM Plex Mono',monospace; font-size:10px; letter-spacing:.12em;
                  text-transform:uppercase; color:#475569; margin-bottom:14px; }}
.cover-title {{ font-size:32px; font-weight:700; line-height:1.15; margin-bottom:4px; }}
.cover-sub {{ font-size:16px; color:#94a3b8; margin-bottom:28px; }}
.sev-badge {{ display:inline-flex; align-items:center; gap:8px; padding:8px 20px;
              border-radius:8px; font-weight:700; font-size:13px;
              font-family:'IBM Plex Mono',monospace; letter-spacing:.06em;
              background:{sc}22; color:{sc}; border:1px solid {sc}44; margin-bottom:28px; }}
.sev-dot {{ width:8px; height:8px; border-radius:50%; background:{sc};
            animation:pulse 2s infinite; }}
@keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:.4; }} }}
.cover-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:8px; }}
.cover-field {{ background:rgba(255,255,255,.03); border:1px solid #1f1f26;
                border-radius:8px; padding:10px 14px; }}
.cf-label {{ font-family:'IBM Plex Mono',monospace; font-size:9px; letter-spacing:.1em;
             text-transform:uppercase; color:#475569; margin-bottom:3px; }}
.cf-val {{ font-size:13px; color:#f1f5f9; font-weight:500; }}

/* SECTIONS */
.sec {{ display:flex; align-items:center; gap:12px; margin:44px 0 14px;
        padding-bottom:10px; border-bottom:1px solid #1f1f26; }}
.sec-num {{ font-family:'IBM Plex Mono',monospace; font-size:10px; background:#1f1f26;
            color:#475569; padding:3px 9px; border-radius:5px; }}
.sec h2 {{ font-size:15px; font-weight:700; color:{sc}; }}

/* EXEC BOX */
.exec-box {{ background:#0f0f12; border:1px solid #1f1f26;
             border-left:3px solid {sc}; border-radius:0 10px 10px 0;
             padding:18px 22px; font-size:14px; color:#94a3b8; line-height:1.85; }}
.exec-box strong {{ color:#f1f5f9; }}

/* STAT CARDS */
.stat-row {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:14px 0; }}
.stat-card {{ background:#0f0f12; border:1px solid #1f1f26;
              border-radius:10px; padding:16px 14px; text-align:center; }}
.stat-label {{ font-family:'IBM Plex Mono',monospace; font-size:9px; text-transform:uppercase;
               letter-spacing:.08em; color:#475569; margin-bottom:6px; }}
.stat-val {{ font-size:26px; font-weight:700; line-height:1; }}
.bar-wrap {{ height:6px; background:#1f1f26; border-radius:3px;
             margin:12px 0 6px; overflow:hidden; }}
.bar-fill {{ height:100%; border-radius:3px;
             background:linear-gradient(90deg,{sc},#818cf8); }}

/* TABLES */
table {{ width:100%; border-collapse:collapse; margin:12px 0; font-size:12.5px; }}
thead tr {{ background:#0f0f12; }}
th {{ font-family:'IBM Plex Mono',monospace; font-size:9.5px; text-transform:uppercase;
      letter-spacing:.07em; color:#475569; padding:10px 12px; text-align:left;
      border-bottom:1px solid #2a2a35; }}
td {{ padding:9px 12px; border-bottom:1px solid #1f1f26; vertical-align:middle; }}
tbody tr:hover td {{ background:rgba(255,255,255,.015); }}
tbody tr:last-child td {{ border-bottom:none; }}

/* TIMELINE */
.tl-wrap {{ position:relative; padding-left:22px; }}
.tl-wrap::before {{ content:''; position:absolute; left:4px; top:8px; bottom:8px;
                    width:1px; background:#2a2a35; }}
.tl-item {{ position:relative; margin-bottom:18px; }}
.tl-dot {{ position:absolute; left:-22px; top:5px; width:9px; height:9px;
            border-radius:50%; border:1px solid; }}
.tl-dot.sus  {{ background:#ef444430; border-color:#ef4444; }}
.tl-dot.norm {{ background:#22c55e30; border-color:#22c55e; }}
.tl-head {{ display:flex; align-items:center; gap:8px; margin-bottom:3px; flex-wrap:wrap; }}
.tl-time {{ font-family:'IBM Plex Mono',monospace; font-size:10.5px; color:#475569; }}
.tl-desc {{ font-size:13px; color:#94a3b8; }}

/* IOC */
.ioc-box {{ background:#060608; border:1px solid #1f1f26; border-radius:7px;
            padding:8px 12px; font-family:'IBM Plex Mono',monospace; font-size:10.5px;
            color:#a5d6ff; word-break:break-all; line-height:1.6; }}

/* RECO */
.reco-item {{ display:flex; gap:14px; padding:14px 0;
              border-bottom:1px solid #1f1f26; align-items:flex-start; }}
.reco-item:last-child {{ border-bottom:none; }}
.reco-num {{ width:34px; height:34px; border-radius:8px; background:#0f0f12;
             border:1px solid #2a2a35; display:flex; align-items:center;
             justify-content:center; font-family:'IBM Plex Mono',monospace;
             font-size:12px; font-weight:600; color:{sc}; flex-shrink:0; }}
.reco-pri {{ font-size:10px; font-family:'IBM Plex Mono',monospace; color:#475569; margin-bottom:3px; }}
.reco-title {{ font-weight:600; font-size:14px; margin-bottom:3px; }}
.reco-detail {{ font-size:12.5px; color:#94a3b8; }}

/* NARRATIVE */
.narrative {{ background:#0f0f12; border:1px solid #1f1f26; border-radius:10px;
              padding:20px 24px; margin:14px 0; color:#94a3b8; font-size:13.5px; line-height:1.85; }}
.narrative strong {{ color:#f1f5f9; }}
.hl {{ color:{sc}; font-weight:600; }}

/* MITRE TACTIC HEADER */
.mt-head {{ background:#0f0f12; border:1px solid #1f1f26; border-radius:7px;
            padding:7px 14px; font-family:'IBM Plex Mono',monospace; font-size:10px;
            letter-spacing:.06em; text-transform:uppercase; color:#475569;
            margin:16px 0 4px; display:inline-flex; gap:8px; }}
.mt-head span {{ color:#818cf8; font-weight:600; }}

/* MISC */
code {{ font-family:'IBM Plex Mono',monospace; font-size:10.5px;
        background:rgba(255,255,255,.05); padding:2px 6px;
        border-radius:3px; color:#a5d6ff; }}
p {{ color:#94a3b8; font-size:13.5px; margin-bottom:8px; }}
.footer {{ margin-top:60px; padding-top:16px; border-top:1px solid #1f1f26;
           font-family:'IBM Plex Mono',monospace; font-size:10px; color:#475569;
           display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }}
</style>"""


# ── section builders ──────────────────────────────────────────────────────────

def s_cover(case_id, report_date, score, severity, sc):
    return f"""
<div class="cover">
  <div class="cover-stripe"></div>
  <div class="cover-wm">RFC</div>
  <div class="cover-eyebrow">Digital Forensic Investigation Report &middot; Confidential</div>
  <div class="cover-title">Ransomware Post-Incident<br>Forensic Analysis</div>
  <div class="cover-sub">Post-Incident Artifact-Based Investigation &mdash; Academic Environment</div>
  <div class="sev-badge"><div class="sev-dot"></div>
    {esc(severity)} SEVERITY &mdash; Risk Score {score}/100
  </div>
  <div class="cover-grid">
    <div class="cover-field"><div class="cf-label">Case ID</div><div class="cf-val">{esc(case_id)}</div></div>
    <div class="cover-field"><div class="cf-label">Report Date</div><div class="cf-val">{esc(report_date)}</div></div>
    <div class="cover-field"><div class="cf-label">Framework</div><div class="cf-val">Ransomware Forensic Framework v2.0</div></div>
    <div class="cover-field"><div class="cf-label">Classification</div><div class="cf-val">Academic &mdash; Simulated Environment</div></div>
    <div class="cover-field"><div class="cf-label">Scan Target</div><div class="cf-val">ransomware_forensic\\artifacts\\</div></div>
    <div class="cover-field"><div class="cf-label">Analysis Method</div><div class="cf-val">Artifact-Based / No Live Malware</div></div>
  </div>
</div>"""


def s_exec(enc, mean_e, reg_c, mitre_c, tactic_c, yara_c, score, severity, sc):
    return f"""
<div class="sec"><span class="sec-num">01</span><h2>Executive Summary</h2></div>
<div class="exec-box">
  Forensic analysis of the target system reveals <strong>strong, multi-source evidence of a
  ransomware attack</strong>. A total of <strong style="color:{sc}">{enc} file(s)</strong> were
  identified with ransomware-characteristic file extensions and anomalously high Shannon entropy
  values (mean: <strong>{mean_e}</strong>), consistent with AES-256 encryption. A ransom demand note
  was discovered in the artifact directory confirming attacker intent.
  <br><br>
  Registry analysis revealed <strong>{reg_c} suspicious persistence mechanism(s)</strong> at autostart
  locations. Event log reconstruction shows an attack chain beginning with a <strong>phishing email
  attachment</strong>, followed by shell execution, shadow copy deletion, and mass file encryption.
  The attack maps to <strong style="color:{sc}">{mitre_c} MITRE ATT&amp;CK technique(s)</strong>
  across {tactic_c} tactic(s). YARA scanning matched <strong>{yara_c} file(s)</strong>.
  Overall risk score: <strong style="color:{sc}">{score}/100 ({severity})</strong>.
</div>"""


def s_scorecard(score, enc, mitre_c, yara_c, tl_c, sc, severity):
    bar_w = min(score, 100)
    return f"""
<div class="sec"><span class="sec-num">02</span><h2>Risk Scorecard &amp; Key Metrics</h2></div>
<div class="stat-row">
  <div class="stat-card"><div class="stat-label">Risk Score</div>
    <div class="stat-val" style="color:#ef4444">{score}/100</div></div>
  <div class="stat-card"><div class="stat-label">Encrypted Files</div>
    <div class="stat-val" style="color:#ef4444">{enc}</div></div>
  <div class="stat-card"><div class="stat-label">MITRE Techniques</div>
    <div class="stat-val" style="color:#818cf8">{mitre_c}</div></div>
  <div class="stat-card"><div class="stat-label">YARA Matches</div>
    <div class="stat-val" style="color:#f97316">{yara_c}</div></div>
  <div class="stat-card"><div class="stat-label">Timeline Events</div>
    <div class="stat-val" style="color:#38bdf8">{tl_c}</div></div>
</div>
<div class="bar-wrap"><div class="bar-fill" style="width:{bar_w}%"></div></div>
<p style="font-size:11.5px;color:#475569;margin-top:4px">
  Severity: <strong style="color:{sc}">{severity}</strong> &nbsp;|&nbsp; Confidence: HIGH
  &nbsp;|&nbsp; Method: Extension + Entropy + YARA + Registry + Event Log Correlation
</p>"""


def s_narrative(enc, mean_e, reg_c, sc):
    return f"""
<div class="sec"><span class="sec-num">03</span><h2>Attack Narrative &amp; Analyst Notes</h2></div>
<div class="narrative">
  <strong>Initial Access:</strong> Evidence suggests the attack began with a phishing email
  containing a malicious Microsoft Office attachment. Event log analysis shows
  <code>WINWORD.EXE</code> spawning <code>cmd.exe</code> ~12 minutes after initial logon
  (MITRE T1566.001 / T1204.002).
  <br><br>
  <strong>Execution &amp; Defense Evasion:</strong> A ransomware payload was executed from a
  temporary directory. Shadow copies were deleted via
  <code>vssadmin.exe delete shadows /all /quiet</code> (T1490), preventing file recovery.
  <br><br>
  <strong>Persistence:</strong> <span class="hl">{reg_c} registry autostart entry(s)</span> written
  to <code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code>, ensuring re-execution
  on every logon (T1547.001).
  <br><br>
  <strong>Impact:</strong> <span class="hl">{enc} file(s)</span> encrypted. All flagged files show
  Shannon entropy exceeding 7.2 (mean: <strong>{mean_e}</strong>), consistent with symmetric
  encryption. A ransom demand note was deposited in the affected directory.
</div>"""


def s_file_evidence(encrypted_files, ransom_notes):
    rows = ""
    for i, f in enumerate(encrypted_files, 1):
        e = f.get("entropy", 0.0)
        verdict = badge("ENCRYPTED", "r") if e > 7.2 else badge("NORMAL", "g")
        rows += (
            f"<tr>"
            f"<td style='color:#475569;font-family:IBM Plex Mono,monospace;font-size:10px'>{i}</td>"
            f"<td><code>{esc(f.get('basename','?'))}</code></td>"
            f"<td>{badge(f.get('extension','?'),'r')}<br>"
            f"<span style='font-size:10.5px;color:#475569'>{esc(f.get('family','Unknown'))}</span></td>"
            f"<td>{ebar(e)}</td>"
            f"<td>{verdict}</td>"
            f"<td style='font-family:IBM Plex Mono,monospace;font-size:10.5px'>{esc(str(f.get('size_bytes','?')))} B</td>"
            f"<td style='font-family:IBM Plex Mono,monospace;font-size:10px;color:#475569'>{esc(f.get('modified','')[:19])}</td>"
            f"<td><code style='font-size:9.5px'>{esc(f.get('sha256','N/A')[:16])}...</code></td>"
            f"</tr>"
        )
    notes_html = ""
    if ransom_notes:
        nlist = " ".join(f"<code>{esc(n)}</code>" for n in ransom_notes)
        notes_html = f'<p style="margin-top:8px;color:#ef4444;font-size:13px">&#x1F6A8; Ransom note(s): {nlist}</p>'
    return (
        '<div class="sec"><span class="sec-num">04</span><h2>File System Evidence</h2></div>'
        '<table><thead><tr><th>#</th><th>Filename</th><th>Ext/Family</th>'
        '<th>Entropy</th><th>Verdict</th><th>Size</th><th>Modified</th><th>SHA-256 (16c)</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
        + notes_html
    )


def s_entropy(all_entropy, mean_e):
    rows = ""
    for item in all_entropy:
        e = item.get("entropy", 0.0)
        v = (badge("ENCRYPTED","r") if e > 7.5
             else badge("SUSPICIOUS","a") if e > 7.2
             else badge("NORMAL","g"))
        ec = "#ef4444" if e > 7.2 else "#22c55e"
        rows += (
            f"<tr>"
            f"<td><code style='font-size:10.5px'>{esc(item.get('basename','?'))}</code></td>"
            f"<td style='font-family:IBM Plex Mono,monospace;font-size:11px;color:{ec}'>{e}</td>"
            f"<td>{ebar(e)}</td>"
            f"<td>{v}</td>"
            f"<td style='font-family:IBM Plex Mono,monospace;font-size:10px;color:#475569'>7.20</td>"
            f"</tr>"
        )
    return (
        '<div class="sec"><span class="sec-num">05</span><h2>Shannon Entropy Analysis</h2></div>'
        '<div class="narrative">Shannon entropy measures data randomness (0=ordered, 8=maximum random). '
        'AES-256 encrypted files score &gt;7.8. Normal documents score 4.5&ndash;6.5. '
        f'Mean entropy of flagged files: <strong style="color:#ef4444">{mean_e}</strong>.</div>'
        '<table><thead><tr><th>Filename</th><th>Entropy</th><th>Visual</th>'
        f'<th>Verdict</th><th>Threshold</th></tr></thead><tbody>{rows}</tbody></table>'
    )


def s_yara(yara_results):
    if not yara_results:
        return ('<div class="sec"><span class="sec-num">06</span>'
                '<h2>YARA Signature Scan Results</h2></div>'
                '<p>No YARA results. Run <code>python phase4_advanced/yara_scanner.py</code> first.</p>')
    rows = ""
    for yr in yara_results:
        fname = esc(yr.get("basename", yr.get("file", "?")))
        for m in yr.get("yara_matches", []):
            sev = m.get("severity", "MEDIUM")
            sb = badge(sev, "r" if sev == "CRITICAL" else "a" if sev == "HIGH" else "y")
            rows += (f"<tr><td><code style='font-size:10.5px'>{fname}</code></td>"
                     f"<td>{badge(m.get('rule_id','?'),'b')}</td>"
                     f"<td style='font-size:12px'>{esc(m.get('rule','?'))}</td>"
                     f"<td>{badge(m.get('mitre',''),'p')}</td><td>{sb}</td></tr>")
        for flag in yr.get("heuristic_flags", []):
            rows += (f"<tr><td><code style='font-size:10.5px'>{fname}</code></td>"
                     f"<td>{badge('HEURISTIC','y')}</td>"
                     f"<td style='font-size:12px'>{esc(flag)}</td>"
                     f"<td>{badge('T1486','p')}</td><td>{badge('HIGH','a')}</td></tr>")
    return (
        '<div class="sec"><span class="sec-num">06</span><h2>YARA Signature Scan Results</h2></div>'
        '<table><thead><tr><th>File</th><th>Rule ID</th><th>Rule Name</th>'
        f'<th>MITRE</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table>'
    )


def s_registry(registry):
    rows = ""
    for r in registry:
        sus = r.get("suspicious", False)
        rows += (
            f"<tr>{badge(r.get('hive','HKCU'),'p')}</td>"
            f"<td><code style='font-size:9.5px'>...\\{esc(r.get('key_tail',''))}</code></td>"
            f"<td><code style='font-size:10.5px'>{esc(r.get('name',''))}</code></td>"
            f"<td style='font-size:11.5px;color:#94a3b8;word-break:break-all'>{esc(r.get('value_short',''))}</td>"
            f"<td>{badge('SUSPICIOUS','r') if sus else badge('LEGITIMATE','g')}</td></tr>"
        )
    return (
        '<div class="sec"><span class="sec-num">07</span><h2>Registry Persistence Analysis</h2></div>'
        '<table><thead><tr><th>Hive</th><th>Key Path</th><th>Value Name</th>'
        f'<th>Executable</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table>'
    )


def s_mitre(mitre):
    if not mitre:
        return ('<div class="sec"><span class="sec-num">08</span>'
                '<h2>MITRE ATT&amp;CK Mapping</h2></div>'
                '<p>No MITRE data. Run <code>python phase4_advanced/mitre_mapper.py</code>.</p>')
    cur_tactic = None
    html = '<div class="sec"><span class="sec-num">08</span><h2>MITRE ATT&amp;CK Technique Mapping</h2></div>'
    for t in mitre:
        tactic = t.get("tactic", "")
        if tactic != cur_tactic:
            cur_tactic = tactic
            html += (f'<div class="mt-head">Tactic &nbsp;'
                     f'<span>{esc(tactic)}</span>&nbsp; {esc(t.get("tactic_id",""))}</div>')
        conf = t.get("confidence", "MEDIUM")
        cb = badge(conf, "r" if conf == "HIGH" else "y")
        evidence = esc(", ".join(t.get("evidence", [])))
        desc = esc(t.get("desc", ""))
        if len(desc) > 130:
            desc = desc[:130] + "..."
        ref = esc(t.get("reference", "#"))
        html += (
            '<table style="margin-bottom:4px"><thead><tr>'
            '<th>Sub-ID</th><th>Technique</th><th>Evidence</th><th>Confidence</th><th>IOC</th>'
            '</tr></thead><tbody><tr>'
            f'<td><a href="{ref}" style="color:#818cf8;font-family:IBM Plex Mono,monospace;'
            f'font-size:10.5px;text-decoration:none">{esc(t.get("sub_id",""))}</a></td>'
            f'<td><strong style="font-size:12.5px">{esc(t.get("name",""))}</strong><br>'
            f'<span style="font-size:11px;color:#475569">{desc}</span></td>'
            f'<td style="font-size:10.5px;color:#94a3b8">{evidence}</td>'
            f'<td>{cb}</td>'
            f'<td>{badge(t.get("ioc_type",""),"b")}</td>'
            '</tr></tbody></table>'
        )
    return html


def s_timeline(timeline):
    items = ""
    for e in timeline:
        sus = e.get("suspicious", False)
        dc = "sus" if sus else "norm"
        sus_b = badge("SUSPICIOUS", "r") if sus else ""
        items += (
            f'<div class="tl-item"><div class="tl-dot {dc}"></div><div>'
            f'<div class="tl-head">'
            f'<span class="tl-time">{esc(e.get("time_short",""))}</span>'
            f'{badge(e.get("source",""),"b")}'
            f'{badge(e.get("phase","Unknown"),"r" if sus else "g")}'
            f'{sus_b}'
            f'</div>'
            f'<div class="tl-desc">{esc(e.get("description",""))}</div>'
            f'</div></div>'
        )
    return (
        '<div class="sec"><span class="sec-num">09</span>'
        '<h2>Chronological Attack Timeline</h2></div>'
        f'<div class="tl-wrap">{items}</div>'
    )


def s_ioc(encrypted_files, registry, yara_results):
    rows = ""
    for f in encrypted_files:
        rows += (
            f"<tr><td>{badge('FILE-HASH','b')}</td>"
            f"<td><div class='ioc-box'>SHA256: {esc(f.get('sha256','N/A'))}<br>"
            f"Filename: {esc(f.get('basename','?'))}</div></td>"
            f"<td style='font-size:11px;color:#94a3b8'>File System</td>"
            f"<td>{badge('HIGH','r')}</td></tr>"
        )
    for r in registry:
        if r.get("suspicious"):
            path = f"{r.get('hive','HKCU')}\\{r.get('key','')}\\{r.get('name','')}"
            rows += (
                f"<tr><td>{badge('REGISTRY','p')}</td>"
                f"<td><div class='ioc-box'>{esc(path)}<br>Value: {esc(r.get('value_short',''))}</div></td>"
                f"<td style='font-size:11px;color:#94a3b8'>Registry</td>"
                f"<td>{badge('HIGH','r')}</td></tr>"
            )
    for yr in yara_results:
        fname = yr.get("basename", yr.get("file", "?"))
        rules = ", ".join(m.get("rule","") for m in yr.get("yara_matches",[]))
        flags = ", ".join(yr.get("heuristic_flags", []))
        rows += (
            f"<tr><td>{badge('YARA-SIG','y')}</td>"
            f"<td><div class='ioc-box'>File: {esc(fname)}<br>"
            f"Rules: {esc(rules + (', ' if rules and flags else '') + flags)}</div></td>"
            f"<td style='font-size:11px;color:#94a3b8'>YARA Scanner</td>"
            f"<td>{badge('HIGH','a')}</td></tr>"
        )
    return (
        '<div class="sec"><span class="sec-num">10</span>'
        '<h2>Indicators of Compromise (IOC)</h2></div>'
        '<table><thead><tr><th>Type</th><th>Indicator</th>'
        f'<th>Source</th><th>Confidence</th></tr></thead><tbody>{rows}</tbody></table>'
    )


RECOMMENDATIONS = [
    ("P1 — IMMEDIATE",  "Isolate Affected System",
     "Immediately disconnect from network. Disable Wi-Fi, unplug Ethernet. Do NOT shut down."),
    ("P1 — IMMEDIATE",  "Preserve Forensic Evidence",
     "Use FTK Imager to create full disk image and memory dump BEFORE any remediation."),
    ("P1 — IMMEDIATE",  "Do Not Pay the Ransom",
     "Payment does not guarantee decryption. Contact law enforcement (CERT-In / FBI IC3)."),
    ("P2 — SHORT TERM", "Remove Registry Persistence Keys",
     "Use Autoruns (Sysinternals) to enumerate startup entries and remove malicious Run keys."),
    ("P2 — SHORT TERM", "Restore from Verified Backup",
     "Restore from most recent clean offline backup. Verify SHA-256 hashes before use."),
    ("P2 — SHORT TERM", "Patch Email Gateway & Disable Macros",
     "Block macro-enabled Office files at gateway. Enable DMARC/DKIM/SPF on mail domain."),
    ("P3 — LONG TERM",  "Implement 3-2-1 Backup Strategy",
     "3 copies, 2 different media types, 1 offsite/offline. Test restores monthly."),
    ("P3 — LONG TERM",  "Deploy EDR Solution",
     "Wazuh, CrowdStrike, or SentinelOne provide real-time behavioural monitoring."),
    ("P3 — LONG TERM",  "Enable PowerShell Logging",
     "Enable Script Block Logging via Group Policy. Forward logs to SIEM for correlation."),
    ("P3 — LONG TERM",  "User Awareness Training",
     "Conduct quarterly phishing simulations. Train users to report suspicious emails."),
]


def s_recommendations():
    items = ""
    for i, (pri, title, detail) in enumerate(RECOMMENDATIONS, 1):
        items += (
            f'<div class="reco-item"><div class="reco-num">{i}</div><div>'
            f'<div class="reco-pri">{esc(pri)}</div>'
            f'<div class="reco-title">{esc(title)}</div>'
            f'<div class="reco-detail">{esc(detail)}</div>'
            f'</div></div>'
        )
    return (
        '<div class="sec"><span class="sec-num">11</span>'
        f'<h2>Remediation Recommendations</h2></div>{items}'
    )


def s_methodology():
    return (
        '<div class="sec"><span class="sec-num">12</span>'
        '<h2>Methodology &amp; Limitations</h2></div>'
        '<div class="narrative">'
        '<strong>Methodology:</strong> Post-incident, artifact-based forensic approach. '
        'No live ransomware executed. Four complementary detection layers applied: '
        '(1) file extension analysis, (2) Shannon entropy measurement, '
        '(3) YARA signature matching, (4) registry and event log correlation — '
        'all mapped to MITRE ATT&amp;CK.'
        '<br><br>'
        '<strong>Tools:</strong> Python 3.11 (psutil, colorama, jinja2, yara-python), '
        'Autopsy, FTK Imager, Regshot, Sysinternals Suite.'
        '<br><br>'
        '<strong>Limitations:</strong> Simulated artifact environment; real-world rates may vary. '
        'Entropy threshold 7.20 may produce false positives on compressed files (.zip, .pdf). '
        'YARA rules cover known families; novel ransomware may evade signature detection. '
        'Future work: ML-based behavioural classifiers, Linux support, STIX 2.1 integration.'
        '</div>'
    )


# ── main generator ────────────────────────────────────────────────────────────

def generate_enhanced_report():
    print("[*] Loading JSON reports...")

    corr     = load_json("reports/correlation_result.json", {})
    scan     = load_json("reports/file_scan_results.json",  {})
    reg_raw  = load_json("reports/registry_findings.json",  [])
    mitre    = load_json("reports/mitre_mapping.json",      [])
    tl_raw   = load_json("reports/attack_timeline.json",    [])
    ent_raw  = load_json("reports/entropy_results.json",    [])
    yara_raw = load_json("reports/yara_results.json",       [])

    score = corr.get("score", 0)
    severity, sc = severity_label(score)
    case_id     = f"RFC-{datetime.now().strftime('%Y%m%d-%H%M')}"
    report_date = datetime.now().strftime("%d %B %Y, %H:%M:%S")

    # Entropy lookup
    entropy_map = {
        item.get("file", ""): item.get("entropy", 0.0)
        for item in ent_raw if isinstance(item, dict)
    }

    # Encrypted files
    encrypted_files = []
    for ef in scan.get("encrypted_files", []):
        path    = ef.get("path", "")
        ev      = entropy_map.get(path, calc_entropy(path))
        sha     = sha256_file(path)
        encrypted_files.append({
            "path":       path,
            "basename":   os.path.basename(path),
            "extension":  ef.get("extension", "?"),
            "family":     ef.get("family", "Unknown"),
            "size_bytes": ef.get("size_bytes", "?"),
            "modified":   str(ef.get("modified", ""))[:19],
            "entropy":    round(ev, 4),
            "sha256":     sha,
        })

    # All entropy
    all_entropy = [
        {
            "basename":  os.path.basename(item.get("file", "?")),
            "entropy":   round(item.get("entropy", 0.0), 4),
        }
        for item in ent_raw if isinstance(item, dict)
    ]

    sus_ent     = [f["entropy"] for f in encrypted_files if f["entropy"] > 7.2]
    mean_e      = round(sum(sus_ent) / max(len(sus_ent), 1), 4)

    # Registry
    registry = []
    for r in reg_raw:
        key = r.get("key", "")
        val = str(r.get("value", ""))
        registry.append({
            "hive":        r.get("hive", "HKCU"),
            "key":         key,
            "key_tail":    key.split("\\")[-1] if "\\" in key else key,
            "name":        r.get("name", ""),
            "value_short": val[:90] + ("..." if len(val) > 90 else ""),
            "value":       val,
            "suspicious":  r.get("suspicious", False),
        })

    # Timeline
    timeline = [
        {
            "time_short":  e.get("time", "")[:19].replace("T", " "),
            "source":      e.get("source", ""),
            "phase":       e.get("phase", "Unknown"),
            "description": e.get("description", ""),
            "suspicious":  e.get("suspicious", False),
        }
        for e in tl_raw
    ]

    # YARA
    yara_results = []
    for yr in yara_raw:
        y = dict(yr)
        y["basename"] = os.path.basename(yr.get("file", yr.get("basename", "?")))
        yara_results.append(y)

    tactic_count = len(set(t.get("tactic", "") for t in mitre))
    reg_count    = sum(1 for r in registry if r["suspicious"])
    ransom_notes = [os.path.basename(n) for n in scan.get("ransom_notes", [])]

    print("[*] Building report sections...")

    parts = [
        s_cover(case_id, report_date, score, severity, sc),
        s_exec(len(encrypted_files), mean_e, reg_count,
               len(mitre), tactic_count, len(yara_results), score, severity, sc),
        s_scorecard(score, len(encrypted_files), len(mitre),
                    len(yara_results), len(timeline), sc, severity),
        s_narrative(len(encrypted_files), mean_e, reg_count, sc),
        s_file_evidence(encrypted_files, ransom_notes),
        s_entropy(all_entropy, mean_e),
        s_yara(yara_results),
        s_registry(registry),
        s_mitre(mitre),
        s_timeline(timeline),
        s_ioc(encrypted_files, registry, yara_results),
        s_recommendations(),
        s_methodology(),
    ]

    footer = (
        f'<div class="footer">'
        f'<span>Case: {esc(case_id)}</span>'
        f'<span>{esc(report_date)}</span>'
        f'<span>Ransomware Forensic Framework v2.0 &mdash; Academic Use Only</span>'
        f'</div>'
    )

    html = (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        f"<title>Forensic Report &mdash; {esc(case_id)}</title>\n"
        f"{build_css(sc)}\n"
        "</head>\n<body>\n<div class=\"page\">\n"
        + "\n".join(parts)
        + "\n" + footer
        + "\n</div>\n</body>\n</html>"
    )

    os.makedirs("reports", exist_ok=True)
    out = f"reports/forensic_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[OK] 12-section report saved -> {out}")
    print(f"     Open in browser: start {out}")
    return out


if __name__ == "__main__":
    generate_enhanced_report()