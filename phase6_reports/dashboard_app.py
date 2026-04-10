from flask import Flask, jsonify, render_template_string
import json

app = Flask(__name__)

def load(p, d): 
    try: return json.load(open(p))
    except: return d

DASHBOARD_HTML = """
<!DOCTYPE html>
<html><head><title>Forensic Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body{font-family:system-ui;background:#0d1117;color:#e6edf3;padding:24px;margin:0}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
  .card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px}
  .card h3{color:#7d8590;font-size:12px;text-transform:uppercase;margin-bottom:8px}
  .card .val{font-size:28px;font-weight:700;color:#e6edf3}
  .card .val.red{color:#f85149}
  .card .val.green{color:#56d364}
  h1{color:#58a6ff;margin-bottom:24px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#161b22;color:#8b949e;padding:8px;text-align:left}
  td{padding:8px;border-bottom:1px solid #21262d}
  .badge{padding:2px 8px;border-radius:4px;font-size:11px;background:#3d1a1a;color:#f85149}
</style></head><body>
<h1>🔬 Ransomware Forensic Dashboard</h1>
<div class="grid">
  <div class="card"><h3>Risk Score</h3><div class="val red" id="score">—</div></div>
  <div class="card"><h3>Encrypted Files</h3><div class="val" id="enc">—</div></div>
  <div class="card"><h3>MITRE Techniques</h3><div class="val red" id="mitre">—</div></div>
  <div class="card"><h3>Timeline Events</h3><div class="val" id="evts">—</div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
  <div class="card"><canvas id="entropyChart"></canvas></div>
  <div class="card"><canvas id="mitreChart"></canvas></div>
</div>
<script>
async function load() {
  const d = await fetch('/api/summary').then(r=>r.json());
  document.getElementById('score').textContent = d.score + '/100';
  document.getElementById('enc').textContent = d.encrypted_files;
  document.getElementById('mitre').textContent = d.mitre_count;
  document.getElementById('evts').textContent = d.timeline_events;
  new Chart(document.getElementById('entropyChart'), {
    type:'bar', data:{
      labels: d.entropy_files.map(f=>f.file.split('\\\\').pop()),
      datasets:[{label:'Entropy',data:d.entropy_files.map(f=>f.entropy),
        backgroundColor:d.entropy_files.map(f=>f.suspicious?'#f85149':'#56d364')}]
    },
    options:{plugins:{title:{display:true,text:'File Entropy Values',color:'#8b949e'}},
      scales:{y:{max:8,grid:{color:'#21262d'},ticks:{color:'#8b949e'}},
              x:{grid:{color:'#21262d'},ticks:{color:'#8b949e'}}}}
  });
  new Chart(document.getElementById('mitreChart'), {
    type:'doughnut',
    data:{labels:d.mitre_names,
      datasets:[{data:Array(d.mitre_names.length).fill(1),
        backgroundColor:['#f85149','#ff7b72','#ffa657','#e3b341','#79c0ff','#56d364']}]},
    options:{plugins:{legend:{labels:{color:'#8b949e'}},
      title:{display:true,text:'MITRE Techniques',color:'#8b949e'}}}
  });
}
load();
</script></body></html>"""

@app.route('/')
def index(): return render_template_string(DASHBOARD_HTML)

@app.route('/api/summary')
def summary():
    corr   = load('reports/correlation_result.json', {})
    scan   = load('reports/file_scan_results.json',  {})
    entropy= load('reports/entropy_results.json',     [])
    mitre  = load('reports/mitre_mapping.json',         [])
    tl     = load('reports/attack_timeline.json',       [])
    return jsonify({
        'score':          corr.get('score', 0),
        'encrypted_files': len(scan.get('encrypted_files', [])),
        'mitre_count':     len(mitre),
        'mitre_names':     [m['name'] for m in mitre],
        'timeline_events': len(tl),
        'entropy_files':   entropy[:8]
    })

if __name__ == '__main__':
    print("[*] Dashboard: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)