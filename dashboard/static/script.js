let allAttacks = [];
let attackChart = null;
let mitreChart = null;

async function fetchData() {
    try {
        const res = await fetch('/api/stats');
        const data = await res.json();

        document.getElementById('ssh-count').textContent = data.ssh;
        document.getElementById('http-count').textContent = data.http;
        document.getElementById('smb-count').textContent = data.smb;
        document.getElementById('total-count').textContent = data.total;
        document.getElementById('high-count').textContent = data.high;
        document.getElementById('medium-count').textContent = data.medium;

        updateAttackChart(data);
        updateMitreChart(data.mitre);
        updateIPTable(data.top_ips);

        allAttacks = data.attacks;
        filterTable();

        if (data.high > 0) {
            document.title = '🚨 HIGH THREAT | Honeypot Dashboard';
        } else {
            document.title = '🍯 Zero-Trust Honeypot Dashboard';
        }

    } catch (err) {
        console.error('Fetch error:', err);
    }
}

function updateAttackChart(data) {
    const ctx = document.getElementById('attackChart').getContext('2d');
    if (attackChart) attackChart.destroy();
    attackChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['SSH', 'HTTP', 'SMB'],
            datasets: [{
                data: [data.ssh, data.http, data.smb],
                backgroundColor: ['#f78166', '#79c0ff', '#56d364'],
                borderColor: '#161b22',
                borderWidth: 2,
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { labels: { color: '#e6edf3' } }
            }
        }
    });
}

function updateMitreChart(mitre) {
    const ctx = document.getElementById('mitreChart').getContext('2d');
    if (mitreChart) mitreChart.destroy();
    mitreChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: mitre.map(m => m.technique),
            datasets: [{
                label: 'Count',
                data: mitre.map(m => m.count),
                backgroundColor: '#ffa657',
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
                y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
            }
        }
    });
}

function updateIPTable(ips) {
    const body = document.getElementById('ip-body');
    body.innerHTML = '';
    ips.forEach((ip, i) => {
        const level = ip.count >= 20 ? 'high' : ip.count >= 5 ? 'medium' : 'low';
        body.innerHTML += `
            <tr>
                <td>${i + 1}</td>
                <td>${ip.ip}</td>
                <td>${ip.count}</td>
                <td><span class="badge badge-${level}">${level.toUpperCase()}</span></td>
            </tr>
        `;
    });
}

function filterTable() {
    const ipSearch = document.getElementById('ip-search').value.toLowerCase();
    const typeFilter = document.getElementById('type-filter').value;

    const filtered = allAttacks.filter(e => {
        const ipMatch = !ipSearch || (e.src_ip && e.src_ip.includes(ipSearch));
        const typeMatch = !typeFilter || e.event_type === typeFilter;
        return ipMatch && typeMatch;
    });

    const body = document.getElementById('attack-body');
    body.innerHTML = '';
    filtered.forEach(e => {
        const type = e.event_type || '';
        const badge = type.includes('AUTH') ? 'ssh' : type.includes('HTTP') ? 'http' : 'smb';
        const count = allAttacks.filter(a => a.src_ip === e.src_ip).length;
        const level = count >= 20 ? 'high' : count >= 5 ? 'medium' : 'low';

        body.innerHTML += `
            <tr>
                <td>${(e.timestamp || '').substring(11, 19)}</td>
                <td><span class="badge badge-${badge}">${badge.toUpperCase()}</span></td>
                <td>${e.src_ip || '-'}</td>
                <td>${e.username || '-'}</td>
                <td>${e.password || '-'}</td>
                <td>${e.mitre_technique || '-'}</td>
                <td><span class="badge badge-${level}">${level.toUpperCase()}</span></td>
            </tr>
        `;
    });
}

async function exportPDF() {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const res = await fetch('/api/stats');
    const data = await res.json();

    doc.setFontSize(18);
    doc.text('Zero-Trust Honeypot Mesh Report', 20, 20);
    doc.setFontSize(12);
    doc.text(`Generated  : ${new Date().toLocaleString()}`, 20, 35);
    doc.text(`Total Attacks : ${data.total}`, 20, 50);
    doc.text(`SSH Attacks   : ${data.ssh}`, 20, 60);
    doc.text(`HTTP Attacks  : ${data.http}`, 20, 70);
    doc.text(`SMB Attacks   : ${data.smb}`, 20, 80);
    doc.text(`High Threats  : ${data.high}`, 20, 90);
    doc.text(`Medium Threats: ${data.medium}`, 20, 100);

    doc.text('Top Attacker IPs:', 20, 120);
    data.top_ips.forEach((ip, i) => {
        doc.text(`${i + 1}. ${ip.ip} — ${ip.count} attacks`, 20, 130 + (i * 10));
    });

    doc.save('honeypot_report.pdf');
}

fetchData();
setInterval(fetchData, 10000);