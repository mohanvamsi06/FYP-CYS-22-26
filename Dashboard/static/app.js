// static/app.js
// Lightweight client that fetches /api/processed and renders UI (no charts)

async function fetchProcessed() {
  const res = await fetch('/api/processed');
  if (!res.ok) {
    const text = await res.text().catch(()=>null);
    throw new Error(`HTTP ${res.status} ${res.statusText} ${text ? ' - ' + text : ''}`);
  }
  return res.json();
}

function safeText(v){ return (v === undefined || v === null) ? '—' : String(v); }

function renderSummary(summary) {
  const counts = summary && summary.counts ? summary.counts : {};
  const total = summary && summary.total_checks ? summary.total_checks : Object.values(counts).reduce((a,b)=>a+(b||0),0);
  document.getElementById('total-checks').textContent = safeText(total);
  document.getElementById('count-pass').textContent = safeText(counts.PASS || counts.Pass || counts.pass || 0);
  document.getElementById('count-fail').textContent = safeText(counts.FAIL || counts.Fail || counts.fail || 0);
  const warnCount = counts.WARN || counts.Warning || counts.warning || counts.warn || 0;
  document.getElementById('count-warn').textContent = safeText(warnCount);

  // Populate a simple textual summary instead of a chart
  const summaryHost = document.getElementById('status-summary-text');
  if (summaryHost) {
    const lines = [];
    const keys = Object.keys(counts).sort();
    if (keys.length === 0) {
      summaryHost.textContent = 'No status data available';
    } else {
      keys.forEach(k => lines.push(`${k}: ${counts[k]}`));
      summaryHost.textContent = lines.join('  •  ');
    }
  }
}

function renderPerFile(perFile) {
  const tbody = document.querySelector('#per-file-table tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!perFile || Object.keys(perFile).length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td colspan="5" style="padding:8px">No per-file data</td>`;
    tbody.appendChild(tr);
    return;
  }
  const rows = Object.entries(perFile).map(([src, counts]) => {
    const total = (counts.PASS||counts.Pass||counts.pass||0) + (counts.FAIL||counts.Fail||counts.fail||0) + (counts.WARN||counts.Warn||counts.warn||0) + (counts.UNKNOWN||counts.Unknown||counts.unknown||0);
    return { src, counts, total };
  }).sort((a,b) => b.total - a.total);
  rows.forEach(r => {
    const pass = r.counts.PASS || r.counts.Pass || r.counts.pass || 0;
    const fail = r.counts.FAIL || r.counts.Fail || r.counts.fail || 0;
    const warn = r.counts.WARN || r.counts.Warn || r.counts.warn || 0;
    const unknown = r.counts.UNKNOWN || r.counts.Unknown || r.counts.unknown || 0;
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="padding:6px;border-top:1px solid #eee">${r.src}</td>
                    <td style="text-align:center;padding:6px;border-top:1px solid #eee">${pass}</td>
                    <td style="text-align:center;padding:6px;border-top:1px solid #eee">${fail}</td>
                    <td style="text-align:center;padding:6px;border-top:1px solid #eee">${warn}</td>
                    <td style="text-align:center;padding:6px;border-top:1px solid #eee">${unknown}</td>`;
    tbody.appendChild(tr);
  });
}

function renderTopFailed(list) {
  const host = document.getElementById('top-failed');
  if (!host) return;
  host.innerHTML = '';
  if (!Array.isArray(list) || list.length === 0) {
    host.innerHTML = '<div style="padding:8px;color:#666">No failures found</div>';
    return;
  }
  list.forEach(item => {
    const card = document.createElement('div');
    card.style.background = '#fff';
    card.style.padding = '10px';
    card.style.borderRadius = '6px';
    card.style.boxShadow = '0 1px 2px rgba(0,0,0,0.04)';
    card.style.display = 'flex';
    card.style.flexDirection = 'column';
    const title = document.createElement('div');
    title.style.fontWeight = '600';
    title.style.marginBottom = '6px';
    title.textContent = (item.check_id && `${item.check_id} — ${item._source_file || ''}`) || (item.description || 'Unnamed check');
    card.appendChild(title);
    const reason = document.createElement('div');
    reason.style.color = '#444';
    reason.style.fontSize = '13px';
    reason.style.marginBottom = '6px';
    reason.textContent = (item.reason && (typeof item.reason === 'string' ? item.reason : JSON.stringify(item.reason).slice(0,200))) || (item.description && item.description.slice(0,200)) || '';
    card.appendChild(reason);
    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '8px';
    actions.style.alignItems = 'center';
    const expandBtn = document.createElement('button');
    expandBtn.textContent = 'Details';
    expandBtn.style.cursor = 'pointer';
    expandBtn.style.padding = '6px 8px';
    expandBtn.style.border = '1px solid #e5e7eb';
    expandBtn.style.borderRadius = '6px';
    expandBtn.style.background = '#fff';
    actions.appendChild(expandBtn);
    card.appendChild(actions);
    const details = document.createElement('div');
    details.style.display = 'none';
    details.style.marginTop = '8px';
    details.style.fontSize = '13px';
    details.style.color = '#333';
    const rem = document.createElement('div');
    rem.innerHTML = `<strong>Remediation:</strong> ${item.remediation ? safeText(item.remediation) : '<em>n/a</em>'}`;
    details.appendChild(rem);
    const src = document.createElement('div');
    src.innerHTML = `<strong>Source:</strong> ${safeText(item._source_file || 'unknown')}`;
    details.appendChild(src);
    if (Array.isArray(item.line_results) && item.line_results.length) {
      const lr = document.createElement('pre');
      lr.style.background = '#f5f7fa';
      lr.style.padding = '8px';
      lr.style.borderRadius = '6px';
      lr.style.marginTop = '8px';
      lr.style.maxHeight = '160px';
      lr.style.overflow = 'auto';
      lr.textContent = item.line_results.map(r => typeof r === 'string' ? r : JSON.stringify(r)).join('\n');
      details.appendChild(lr);
    }
    expandBtn.addEventListener('click', () => {
      details.style.display = details.style.display === 'none' ? 'block' : 'none';
    });
    card.appendChild(details);
    host.appendChild(card);
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  const rawPre = document.getElementById('rawjson');
  try {
    const data = await fetchProcessed();
    if (rawPre) rawPre.textContent = JSON.stringify(data, null, 2);
    renderSummary(data.summary || {});
    renderPerFile(data.per_file || {});
    renderTopFailed(data.top_failed || []);
  } catch (e) {
    console.error('Failed to fetch processed data', e);
    if (rawPre) rawPre.textContent = 'Failed to fetch processed data: ' + (e && e.message ? e.message : String(e));
    document.getElementById('total-checks').textContent = '—';
    document.getElementById('count-pass').textContent = '—';
    document.getElementById('count-fail').textContent = '—';
    document.getElementById('count-warn').textContent = '—';
  }
});

async function startScan() {
  const statusEl = document.getElementById('scan-status');
  const btn = document.getElementById('run-scan-btn');

  btn.disabled = true;
  btn.style.opacity = '0.6';
  statusEl.textContent = 'Starting scan…';

  try {
    const res = await fetch('/api/scan/start', { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to start scan');

    pollJobStatus();
  } catch (e) {
    statusEl.textContent = 'Error: ' + e.message;
    btn.disabled = false;
    btn.style.opacity = '1';
  }
}

async function pollJobStatus() {
  const statusEl = document.getElementById('scan-status');

  const interval = setInterval(async () => {
    try {
      const res = await fetch('/api/scan/status');
      const data = await res.json();

      if (data.status === 'running') {
        statusEl.textContent = 'Scan running…';
      } else if (data.status === 'completed') {
        statusEl.textContent = 'Scan completed. Reloading…';
        clearInterval(interval);
        setTimeout(() => location.reload(), 1000);
      } else if (data.status === 'failed') {
        statusEl.textContent = 'Scan failed. Check logs.';
        clearInterval(interval);
      }
    } catch (e) {
      statusEl.textContent = 'Status check failed';
      clearInterval(interval);
    }
  }, 2000); // poll every 2s
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('run-scan-btn');
  if (btn) btn.addEventListener('click', startScan);
});
