generate_dashboard() {
    log "INFO" "Generating the Enterprise SaaS Nginx Dashboard (SPA/CSP)..."

    local UI_DIR="/etc/syswarden/ui"
    mkdir -p "$UI_DIR"

    chmod 750 /etc/syswarden
    chmod 750 "$UI_DIR"

    if id "www-data" >/dev/null 2>&1; then
        chown root:www-data /etc/syswarden "$UI_DIR"
    elif id "apache" >/dev/null 2>&1; then
        chown root:apache /etc/syswarden "$UI_DIR"
    elif id "nginx" >/dev/null 2>&1; then
        chown root:nginx /etc/syswarden "$UI_DIR"
    fi

    # 1. Generating the HTML file (Single Page Layout)
    cat <<'EOF' >"$UI_DIR/index.html"
<!DOCTYPE html>
<html lang="en" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>SysWarden | Dashboard</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700;900&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
    
    <style>
        /* --- THEME DEFINITIONS --- */
        :root[data-bs-theme="light"] {
            --sw-bg: #ffffff;
            --sw-nav-bg: #f8f9fa;
            --sw-card-bg: #ffffff;
            --sw-border: #e2e8f0;
            --sw-text: #1e293b;
            --sw-text-muted: #64748b;
            --sw-brand-icon: #2563eb;
            --sw-danger: #dc2626;
            --sw-success: #16a34a;
        }
        :root[data-bs-theme="dark"] {
            --sw-bg: #000000;
            --sw-nav-bg: #09090b;
            --sw-card-bg: #0a0a0a;
            --sw-border: #27272a;
            --sw-text: #f8fafc;
            --sw-text-muted: #a1a1aa;
            --sw-brand-icon: #3b82f6;
            --sw-danger: #ef4444;
            --sw-success: #10b981;
        }

        /* --- GLOBAL TYPOGRAPHY & LAYOUT --- */
        body { 
            font-family: 'Roboto', -apple-system, sans-serif;
            background-color: var(--sw-bg); 
            color: var(--sw-text);
            transition: background-color 0.2s ease, color 0.2s ease;
            -webkit-font-smoothing: antialiased;
            font-size: 0.85rem;
        }
        .font-mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-weight: 500; }
        .main-wrapper { flex-grow: 1; overflow-y: auto; overflow-x: hidden; scroll-behavior: smooth; height: calc(100vh - 55px); }

        /* --- NAVBAR --- */
        .top-navbar {
            height: 55px; min-height: 55px;
            background-color: var(--sw-nav-bg); 
            border-bottom: 1px solid var(--sw-border);
            display: flex; align-items: center; justify-content: space-between; padding: 0 1.5rem;
        }
        .theme-toggle-btn { background: transparent; border: none; color: var(--sw-text); cursor: pointer; display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; border-radius: 4px; transition: background 0.2s; }
        .theme-toggle-btn:hover { background: var(--sw-border); }

        /* --- WAZUH STYLE CARDS --- */
        .card { 
            background-color: var(--sw-card-bg); 
            border: 1px solid var(--sw-border); 
            border-radius: 4px; 
            box-shadow: none; 
        }
        .card-header { 
            background-color: transparent;
            border-bottom: 1px solid var(--sw-border); 
            font-weight: 700; 
            letter-spacing: 0.5px; 
            text-transform: uppercase; 
            font-size: 0.75rem; 
            color: var(--sw-text-muted); 
            padding: 0.75rem 1.25rem;
        }
        .card-body { padding: 1.25rem; }

        /* --- METRICS --- */
        .card-l3 { border-top: 3px solid var(--sw-brand-icon) !important; }
        .card-l7 { border-top: 3px solid var(--sw-danger) !important; }
        .card-wl { border-top: 3px solid var(--sw-success) !important; }

        .stat-value { font-size: 1.75rem; font-weight: 800; line-height: 1.1; letter-spacing: -0.5px; }
        .stat-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; color: var(--sw-text-muted); font-weight: 700; }
        
        /* --- TABLES & SCROLLBARS --- */
        .table-container { max-height: 350px; overflow-y: auto; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--sw-border); border-radius: 4px; }
        
        .table { --bs-table-bg: transparent !important; margin-bottom: 0 !important; color: var(--sw-text); }
        .table > :not(caption) > * > * { background-color: transparent !important; border-color: var(--sw-border) !important; padding: 0.75rem 1.25rem; }
        .table thead th { position: sticky; top: 0; background: var(--sw-card-bg) !important; z-index: 2; border-bottom: 2px solid var(--sw-border) !important; font-size: 0.70rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .ip-font { font-size: 85% !important; font-weight: 600; }
        
        /* --- UTILITIES --- */
        .badge-wazuh { font-size: 0.70rem; padding: 0.35em 0.65em; border-radius: 3px; font-weight: 600; }
    </style>
</head>
<body class="d-flex flex-column" style="height: 100vh; margin: 0;">

    <nav class="top-navbar">
        <div class="d-flex align-items-center gap-3">
            <svg style="color: var(--sw-brand-icon);" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <div class="d-none d-md-flex align-items-baseline gap-2">
                <h5 class="mb-0 fw-bold text-uppercase" style="letter-spacing: 0.5px; font-size: 1rem; color: var(--sw-text);">SYSWARDEN</h5>
                <span class="font-mono text-muted" style="font-size: 0.80rem;">v0.33.2</span>
            </div>
        </div>
        
        <div class="d-flex align-items-center gap-3 gap-md-4">
            <!-- FILTRATION EFFICIENCY NAVBAR INJECTION -->
            <div class="d-none d-xl-flex align-items-center gap-3 border-end pe-3 font-mono" style="border-color: var(--sw-border) !important; font-size: 0.80rem;">
                <div title="Automated Noise Blocked (L2/L3)"><span class="text-muted">Noise:</span> <span id="nav-noise-pct" style="color: var(--sw-success); font-weight: 700;">--%</span></div>
                <div title="Actionable Signals (L7)"><span class="text-muted">Signal:</span> <span id="nav-signal-pct" style="color: var(--sw-danger); font-weight: 700;">--%</span></div>
            </div>

            <div class="d-none d-md-flex align-items-center gap-4 border-end pe-4" style="border-color: var(--sw-border) !important;">
                <a href="https://github.com/duggytuxy/syswarden" target="_blank" rel="noopener noreferrer" class="text-decoration-none small font-mono d-flex align-items-center gap-2" style="color: var(--sw-text);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                    Stars <span id="gh-stars" class="fw-bold">--</span>
                </a>
                <a href="https://github.com/duggytuxy/syswarden/releases/latest" target="_blank" rel="noopener noreferrer" class="text-decoration-none small font-mono d-flex align-items-center gap-2" style="color: var(--sw-text);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                    Release <span id="gh-release" class="text-primary fw-bold">--</span>
                </a>
            </div>

            <div class="d-flex align-items-center gap-2 px-3 py-1 rounded-pill" style="background: var(--sw-bg); border: 1px solid var(--sw-border);">
                <div id="status-spinner" class="spinner-grow spinner-grow-sm text-success" style="width: 8px; height: 8px;" role="status"></div>
                <span id="sys-hostname" class="text-truncate fw-bold small" style="max-width: 150px;">Node</span>
                <span id="sys-ip" class="text-muted font-mono small d-none d-lg-block"></span>
            </div>
            
            <button class="theme-toggle-btn" id="theme-toggle-btn" title="Toggle Theme">
                <svg id="icon-sun" class="d-none" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                <svg id="icon-moon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
        </div>
    </nav>

    <main class="main-wrapper">
        <div class="container-fluid px-xl-4 px-3 py-4">
            
            <!-- SYSTEM HARDWARE & METRICS -->
            <div class="card mb-4">
                <div class="card-body py-3 d-flex flex-column gap-2">
                    <div class="d-flex flex-wrap gap-4 align-items-center border-bottom pb-2" style="border-color: var(--sw-border) !important;">
                        <div class="font-mono"><span class="text-muted">Cores:</span> <span id="hw-cores" class="ms-1 fw-bold">--</span></div>
                        <div class="font-mono"><span class="text-muted">Arch:</span> <span id="hw-arch" class="ms-1 fw-bold">--</span></div>
                        <div class="font-mono"><span class="text-muted">OS:</span> <span id="hw-os" class="ms-1 fw-bold">--</span></div>
                        <div class="font-mono d-flex align-items-center"><span class="text-muted me-1">CPU:</span> <span class="text-truncate fw-bold" style="max-width: 300px;" id="hw-cpu">--</span></div>
                        <div class="font-mono"><span class="text-muted">Last sync:</span> <span id="hw-update" class="ms-1 fw-bold">--</span></div>
                    </div>
                    <div class="d-flex flex-wrap gap-4 align-items-center border-bottom pb-2 pt-1" style="border-color: var(--sw-border) !important;">
                        <div class="font-mono"><span class="text-muted">Uptime:</span> <span id="sys-uptime" class="ms-1" style="color: var(--sw-brand-icon); font-weight: 700;">--</span></div>
                        <div class="font-mono"><span class="text-muted">Load Avg:</span> <span id="sys-load" class="ms-1 fw-bold">--</span></div>
                        <div class="font-mono"><span class="text-muted">RAM:</span> <span id="sys-ram" class="ms-1 fw-bold">-- MB</span></div>
                        <div class="font-mono"><span class="text-muted">Storage:</span> <span id="sys-disk" class="ms-1 fw-bold">-- GB</span></div>
                    </div>
                    <div class="d-flex flex-wrap gap-3 align-items-center border-bottom pb-2 pt-1 font-mono" id="sys-services-list" style="border-color: var(--sw-border) !important;"></div>
                    <div class="d-flex flex-wrap gap-3 align-items-center pt-1 font-mono" id="sys-ports-list"></div>
                </div>
            </div>
            
            <!-- LAYER 3 & LAYER 7 METRICS -->
            <div class="row g-3 mb-4">
                <div class="col-xxl-4 col-lg-6">
                    <div class="card card-l3 h-100">
                        <div class="card-body">
                            <div class="stat-label mb-2">L3 Kernel Blocks (Global)</div>
                            <div class="stat-value font-mono mb-3" style="color: var(--sw-brand-icon);" id="l3-global">0</div>
                            <div class="d-flex justify-content-between border-top pt-2 font-mono text-muted" style="border-color: var(--sw-border) !important; font-size: 0.80rem;">
                                <span>GeoIP: <strong class="text-body" id="l3-geoip">0</strong></span>
                                <span>ASN: <strong class="text-body" id="l3-asn">0</strong></span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xxl-4 col-lg-6">
                    <div class="card card-l7 h-100">
                        <div class="card-body">
                            <div class="stat-label mb-2">L7 Active Bans (Fail2ban)</div>
                            <div class="stat-value font-mono mb-3" style="color: var(--sw-danger);" id="l7-banned">0</div>
                            <div class="d-flex justify-content-between border-top pt-2 font-mono text-muted" style="border-color: var(--sw-border) !important; font-size: 0.80rem;">
                                <span>Active Guard Jails:</span>
                                <strong class="text-body" id="l7-jails">0</strong>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xxl-4 col-lg-12">
                    <div class="card card-wl h-100">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <div class="stat-label">Trusted Hosts (Whitelist)</div>
                                <span class="badge wazuh-badge font-mono" style="background-color: rgba(16, 185, 129, 0.15); color: var(--sw-success); border: 1px solid rgba(16, 185, 129, 0.3);" id="wl-count">0</span>
                            </div>
                            <div class="table-container pe-2 font-mono" style="max-height: 60px; font-size: 0.80rem; color: var(--sw-success);">
                                <ul class="list-unstyled mb-0" id="whitelist-ips-list"></ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- RISK & TOP ATTACKERS -->
            <div class="row g-3 mb-4">
                <div class="col-xl-4">
                    <div class="card h-100">
                        <div class="card-header">Global Risk Vectors</div>
                        <div class="card-body d-flex align-items-center justify-content-center">
                            <div style="position: relative; height: 260px; width: 100%;">
                                <canvas id="riskChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-8">
                    <div class="card h-100">
                        <div class="card-header">Top Attackers (OSINT History)</div>
                        <div class="card-body p-0">
                            <div class="table-responsive table-container" style="max-height: 295px;">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr>
                                            <th>IP ADDRESS</th>
                                            <th>PORT</th>
                                            <th class="text-end">HITS</th>
                                        </tr>
                                    </thead>
                                    <tbody id="top-ips-list"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- JAILS & BANNED IPS -->
            <div class="row g-3 mb-4">
                <div class="col-xl-4">
                    <div class="card h-100">
                        <div class="card-header">Jails Load Distribution</div>
                        <div class="card-body p-0">
                            <div class="table-responsive table-container" style="max-height: 400px;">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr>
                                            <th>TARGET JAIL</th>
                                            <th>MITRE ATT&CK</th>
                                            <th class="text-end">LOAD</th>
                                        </tr>
                                    </thead>
                                    <tbody id="top-jails-list"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-8">
                    <div class="card h-100">
                        <div class="card-header">L7 Banned IP Registry (Live Jail Allocations)</div>
                        <div class="card-body p-0">
                            <div class="table-responsive table-container" style="max-height: 400px;">
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr>
                                            <th style="min-width: 140px;">IP ADDRESS</th>
                                            <th style="min-width: 140px;">TARGET JAIL</th>
                                            <th style="min-width: 180px;">MITRE ATT&CK</th>
                                            <th style="min-width: 250px;">TRIGGER PAYLOAD</th>
                                        </tr>
                                    </thead>
                                    <tbody id="banned-ips-list"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            
        </div>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    let riskChart = null;

    document.addEventListener('DOMContentLoaded', () => {
        
        // --- THEME ENGINE (ICONS) ---
        const themeBtn = document.getElementById('theme-toggle-btn');
        const iconSun = document.getElementById('icon-sun');
        const iconMoon = document.getElementById('icon-moon');
        
        const applyThemeState = (isDark) => {
            document.documentElement.setAttribute('data-bs-theme', isDark ? 'dark' : 'light');
            if(isDark) {
                iconMoon.classList.add('d-none');
                iconSun.classList.remove('d-none');
            } else {
                iconSun.classList.add('d-none');
                iconMoon.classList.remove('d-none');
            }
            updateChartTheme(isDark ? 'dark' : 'light');
        };

        const toggleTheme = () => {
            const currentTheme = document.documentElement.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('syswarden-theme', newTheme);
            applyThemeState(newTheme === 'dark');
        };

        themeBtn.addEventListener('click', toggleTheme);

        const savedTheme = localStorage.getItem('syswarden-theme');
        if (savedTheme) {
            applyThemeState(savedTheme === 'dark');
        } else {
            applyThemeState(window.matchMedia('(prefers-color-scheme: dark)').matches);
        }

        // --- CHART.JS INITIALIZATION (DOUGHNUT ONLY) ---
        try {
            const ctxRadar = document.getElementById('riskChart').getContext('2d');
            riskChart = new Chart(ctxRadar, {
                type: 'doughnut',
                data: {
                    labels: ['Exploits', 'Brute-Force', 'Recon', 'DDoS', 'Abuse/Spam'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#ef4444', // Red
                            '#eab308', // Yellow
                            '#3b82f6', // Blue
                            'var(--sw-chart-ddos)', // Black/Grey depending on theme
                            '#f97316'  // Orange
                        ],
                        borderWidth: 2,
                        borderColor: 'var(--sw-card-bg)'
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, cutout: '65%',
                    plugins: { 
                        legend: { position: 'bottom', labels: { padding: 20, font: { family: 'Roboto', size: 12, weight: '500' } } },
                        tooltip: { padding: 10, cornerRadius: 8, bodyFont: { family: 'monospace', size: 13, weight: 'bold' } }
                    }
                }
            });
        } catch (e) { console.warn("Chart.js init failed:", e); }

        updateChartTheme(document.documentElement.getAttribute('data-bs-theme'));

        function updateChartTheme(theme) {
            if(riskChart) {
                const isDark = theme === 'dark';
                riskChart.data.datasets[0].borderColor = isDark ? '#09090b' : '#ffffff';
                riskChart.options.plugins.legend.labels.color = isDark ? '#a1a1aa' : '#6b7280';
                riskChart.update();
            }
        }
        
        // --- UI HELPER: MATCH JAIL TO DOUGHNUT CHART COLORS ---
        function getJailBadgeStyle(jailName) {
            const j = jailName.toLowerCase();
            const baseStyle = 'padding: 0.35em 0.65em; border-radius: 3px; font-weight: 600; font-size: 0.70rem; ';
            
            if (j.match(/(sqli|xss|lfi|revshell|webshell|ssti|ssrf|jndi|homoglyph|prestashop|atlassian|wordpress|drupal|nginx|apache)/)) 
                return baseStyle + 'background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3);';
            if (j.match(/(portscan|scan|bot|mapper|enum|hunter|proxy|tls)/))
                return baseStyle + 'background-color: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3);';
            if (j.match(/(recidive|postfix|dovecot|exim|mail)/)) 
                return baseStyle + 'background-color: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3);';
            if (j.match(/(flood|limit|ddos)/)) 
                return baseStyle + 'background-color: rgba(161, 161, 170, 0.15); color: var(--sw-text); border: 1px solid var(--sw-border);';
            return baseStyle + 'background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.3);';
        }

        // --- DATA INGESTION ENGINE ---
        async function fetchTelemetry() {
            try {
                const response = await fetch(`data.json?t=${new Date().getTime()}`);
                if (!response.ok) throw new Error('HTTP request failed');
                const data = await response.json();

                // Status Spinner -> Online
                const spinner = document.getElementById('status-spinner');
                if (spinner) {
                    spinner.classList.remove('text-danger');
                    spinner.classList.add('text-success');
                }

                // System Metrics
                document.getElementById('sys-hostname').innerText = data.system.hostname;
                if(data.system.ip) {
                    document.getElementById('sys-ip').innerText = data.system.ip;
                }
                document.getElementById('sys-uptime').innerText = data.system.uptime;
                
                // Hardware Header
                if (document.getElementById('hw-cores')) {
                    document.getElementById('hw-cores').innerText = data.system.cores || '--';
                    document.getElementById('hw-arch').innerText = data.system.arch || '--';
                    document.getElementById('hw-os').innerText = data.system.os || '--';
                    document.getElementById('hw-cpu').innerText = data.system.cpu_model || '--';
                    
                    const fetchTime = new Date();
                    document.getElementById('hw-update').innerText = fetchTime.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });
                }
                
                const ramUsed = parseInt(data.system.ram_used_mb) || 0;
                const ramTotal = parseInt(data.system.ram_total_mb) || 1;
                document.getElementById('sys-ram').innerText = `${ramUsed.toLocaleString()} / ${ramTotal.toLocaleString()} MB`;
                
                const diskUsed = (parseInt(data.system.disk_used_mb) / 1024).toFixed(1);
                const diskTotal = (parseInt(data.system.disk_total_mb) / 1024).toFixed(1);
                document.getElementById('sys-disk').innerText = `${diskUsed} / ${diskTotal} GB`;

                const sysLoadEl = document.getElementById('sys-load');
                sysLoadEl.innerText = data.system.load_average;
                const load1m = parseFloat(data.system.load_average.split(',')[0]);
                sysLoadEl.classList.remove('text-success', 'text-warning', 'text-danger');
                sysLoadEl.classList.add(load1m <= 0.35 ? 'text-success' : load1m <= 0.70 ? 'text-warning' : 'text-danger');

                // Flat Services Listing
                const srvEl = document.getElementById('sys-services-list');
                if(data.system.services && srvEl) {
                    srvEl.innerHTML = data.system.services.map(srv => {
                        const shortName = srv.name.split(' ')[0];
                        const statusClass = srv.status === 'active' ? 'text-success' : (srv.status === 'skipped' ? 'text-warning opacity-75' : 'text-danger');
                        return `<span class="text-muted">${shortName}:</span> <span class="${statusClass}">${srv.status.toUpperCase()}</span>`;
                    }).join(' <span class="text-muted opacity-50 px-2">|</span> ');
                }

                // Flat Network Ports Listing
                const portsEl = document.getElementById('sys-ports-list');
                if(data.system.ports && portsEl) {
                    if (data.system.ports.length > 0) {
                        portsEl.innerHTML = data.system.ports.map(p => {
                            const safePort = (p.port && p.port.trim() !== '' && p.port !== '*') ? p.port : 'N/A';
                            return `<span class="text-muted">${p.protocol || 'TCP'}:</span> <span style="color: var(--sw-brand-icon); font-weight: 700;">${safePort}</span>`;
                        }).join(' <span class="text-muted opacity-50 px-2">|</span> ');
                    } else {
                        portsEl.innerHTML = '<span class="text-muted fst-italic">No external ports exposed. Architecture is fully locked down.</span>';
                    }
                }

                // Layer 3 & 7 Metrics
                document.getElementById('l3-global').innerText = parseInt(data.layer3.global_blocked).toLocaleString();
                document.getElementById('l3-geoip').innerText = parseInt(data.layer3.geoip_blocked).toLocaleString();
                document.getElementById('l3-asn').innerText = parseInt(data.layer3.asn_blocked).toLocaleString();
                document.getElementById('l7-banned').innerText = parseInt(data.layer7.total_banned).toLocaleString();
                document.getElementById('l7-jails').innerText = data.layer7.active_jails;
                document.getElementById('wl-count').innerText = data.whitelist.active_ips;

                // Signal vs Noise Calculation
                const l3Blocked = parseInt(data.layer3.global_blocked) || 0;
                const l7Banned = parseInt(data.layer7.total_banned) || 0;
                const totalThreats = l3Blocked + l7Banned;
                
                let noisePercent = 0;
                let signalPercent = 0;
                
                if (totalThreats > 0) {
                    noisePercent = ((l3Blocked / totalThreats) * 100).toFixed(2);
                    signalPercent = ((l7Banned / totalThreats) * 100).toFixed(2);
                }

                // UI Updates: Navbar Injections
                const navNoise = document.getElementById('nav-noise-pct');
                if (navNoise) navNoise.innerText = `${noisePercent}%`;
                const navSignal = document.getElementById('nav-signal-pct');
                if (navSignal) navSignal.innerText = `${signalPercent}%`;
                
                // Inject Doughnut Data
                if(riskChart && data.layer7.risk_radar) {
                    riskChart.data.datasets[0].data = data.layer7.risk_radar;
                    riskChart.update();
                }

                // Renderers (Threat Intel Tables)
                document.getElementById('whitelist-ips-list').innerHTML = data.whitelist.ips.map(ip => `<li class="mb-1 opacity-75">${ip}</li>`).join('');

                const topIpsEl = document.getElementById('top-ips-list');
                if(data.layer7.top_attackers.length > 0) {
                    topIpsEl.innerHTML = data.layer7.top_attackers.map(attacker => `
                        <tr>
                            <td class="align-middle py-3 ps-4 font-mono"><a href="https://www.abuseipdb.com/check/${attacker.ip}" target="_blank" rel="noopener noreferrer" class="text-decoration-none ip-font" style="color: var(--sw-text);">${attacker.ip}</a></td>
                            <td class="align-middle py-3 font-mono">
                                <span class="badge rounded-pill" style="background-color: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3); font-size: 0.70rem;">
                                    ${attacker.port || 'N/A'}
                                </span>
                            </td>
                            <td class="text-end align-middle py-3 pe-4 font-mono text-body-secondary">${attacker.count.toLocaleString()}</td>
                        </tr>`).join('');
                } else { topIpsEl.innerHTML = `<tr><td colspan="3" class="text-center text-muted small py-4">No attackers recorded.</td></tr>`; }

                const jailsEl = document.getElementById('top-jails-list');
                if(data.layer7.jails_data.length > 0) {
                    jailsEl.innerHTML = [...data.layer7.jails_data].sort((a, b) => b.count - a.count).map(jail => {
                        const mitreId = jail.mitre ? jail.mitre.split(':')[0] : 'T1499';
                        const mitreLabel = jail.mitre || 'Unknown';
                        
                        return `
                        <tr>
                            <td class="align-middle py-3 ps-4 font-mono"><span class="badge rounded-pill" style="${getJailBadgeStyle(jail.name)}">${jail.name}</span></td>
                            <td class="align-middle py-3 font-mono">
                                <a href="https://attack.mitre.org/techniques/${mitreId}/" target="_blank" rel="noopener noreferrer" class="text-decoration-none badge rounded-pill" style="${getJailBadgeStyle(jail.name)} font-size: 0.70rem;">
                                    ${mitreLabel}
                                </a>
                            </td>
                            <td class="text-end align-middle py-3 pe-4 font-mono text-body-secondary">${jail.count}</td>
                        </tr>`;
                    }).join('');
                } else { jailsEl.innerHTML = `<tr><td colspan="3" class="text-center text-muted small py-4">No active jails loaded.</td></tr>`; }

                const bannedEl = document.getElementById('banned-ips-list');
                if(data.layer7.banned_ips.length > 0) {
                    bannedEl.innerHTML = [...data.layer7.banned_ips].reverse().map(entry => {
                        const mitreId = entry.mitre ? entry.mitre.split(':')[0] : 'T1499';
                        const mitreLabel = entry.mitre || 'Unknown';
                        
                        // Removed the Timestamp column entirely as requested
                        return `
                        <tr>
                            <td class="align-middle py-3 ps-4 font-mono"><a href="https://www.abuseipdb.com/check/${entry.ip}" target="_blank" rel="noopener noreferrer" class="text-decoration-none ip-font" style="color: var(--sw-text);">${entry.ip}</a></td>
                            <td class="align-middle py-3 font-mono"><span class="badge rounded-pill" style="${getJailBadgeStyle(entry.jail)}">${entry.jail}</span></td>
                            <td class="align-middle py-3 ps-3 font-mono">
                                <a href="https://attack.mitre.org/techniques/${mitreId}/" target="_blank" rel="noopener noreferrer" class="text-decoration-none badge rounded-pill" style="${getJailBadgeStyle(entry.jail)} font-size: 0.70rem;">
                                    ${mitreLabel}
                                </a>
                            </td>
                            <td class="align-middle py-3 ps-4 pe-4 font-mono text-muted small text-nowrap" style="font-size: 0.75rem;">${entry.payload || 'N/A'}</td>
                        </tr>`
                    }).join('');
                } else { 
                    bannedEl.innerHTML = `<tr><td colspan="4" class="text-center text-muted small py-5">Registry is empty. Architecture is secure.</td></tr>`; 
                }

            } catch (error) {
                console.error("Telemetry Sync Error:", error);
                
                const spinner = document.getElementById('status-spinner');
                if (spinner) {
                    spinner.classList.remove('text-success');
                    spinner.classList.add('text-danger');
                }
            }
        }
        
        async function fetchGitHubData() {
            try {
                const repoRes = await fetch('https://api.github.com/repos/duggytuxy/syswarden');
                if (repoRes.ok) {
                    const repoData = await repoRes.json();
                    document.getElementById('gh-stars').innerText = repoData.stargazers_count;
                }
                
                const relRes = await fetch('https://api.github.com/repos/duggytuxy/syswarden/releases/latest');
                if (relRes.ok) {
                    const relData = await relRes.json();
                    document.getElementById('gh-release').innerText = relData.tag_name;
                }
            } catch (error) {
                console.warn("GitHub API Fetch Error:", error);
                document.getElementById('gh-stars').innerText = "N/A";
                document.getElementById('gh-release').innerText = "N/A";
            }
        }
        
        fetchGitHubData();

        fetchTelemetry();
        setInterval(fetchTelemetry, 5000);
    });
    </script>
</body>
</html>
EOF

    # --- 3. DYNAMIC ACCESS CONTROL (IP Whitelisting) ---
    local NGINX_ALLOW_RULES=""
    local APACHE_ALLOW_RULES=""

    if [[ -s "$WHITELIST_FILE" ]]; then
        while IFS= read -r wl_ip; do
            [[ -z "$wl_ip" ]] || [[ "$wl_ip" =~ ^# ]] && continue
            NGINX_ALLOW_RULES+="        allow $wl_ip;\n"
            APACHE_ALLOW_RULES+="        Require ip $wl_ip\n"
        done <"$WHITELIST_FILE"
    fi

    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        NGINX_ALLOW_RULES+="        allow ${WG_SUBNET};\n"
        APACHE_ALLOW_RULES+="        Require ip ${WG_SUBNET}\n"
    fi

    NGINX_ALLOW_RULES+="        allow 127.0.0.1;\n"
    NGINX_ALLOW_RULES+="        deny all;"
    APACHE_ALLOW_RULES+="        Require ip 127.0.0.1\n"
    # Apache uses 'Require all denied' implicitly via <RequireAny> block exclusion.

    # --- 4. CRYPTOGRAPHY (Self-Signed TLS) ---
    local SSL_DIR="/etc/syswarden/ssl"
    mkdir -p "$SSL_DIR"
    if [[ ! -f "$SSL_DIR/syswarden.crt" ]]; then
        log "INFO" "Generating Self-Signed RSA 4096 TLS Certificate..."
        openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
            -keyout "$SSL_DIR/syswarden.key" \
            -out "$SSL_DIR/syswarden.crt" \
            -subj "/C=BE/ST=Brussels/L=Brussels/O=SysWarden/CN=syswarden-dashboard" 2>/dev/null
        chmod 600 "$SSL_DIR/syswarden.key"
    fi

    # --- 5. WEB SERVER VHOST CONFIGURATION (Apache or Nginx) ---
    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        log "INFO" "Apache detected. Configuring Apache VHost for port 9999..."
        local APACHE_CONF_DIR="/etc/apache2/sites-available"
        local APACHE_ENABLE_DIR="/etc/apache2/sites-enabled"
        local APACHE_DAEMON="apache2"

        if command -v httpd >/dev/null 2>&1 || [[ -d "/etc/httpd" ]]; then
            APACHE_CONF_DIR="/etc/httpd/conf.d"
            APACHE_ENABLE_DIR="/etc/httpd/conf.d"
            APACHE_DAEMON="httpd"
        fi

        mkdir -p "$APACHE_CONF_DIR"
        cat <<EOF >"$APACHE_CONF_DIR/syswarden-ui.conf"
Listen 9999
<VirtualHost *:9999>
    DocumentRoot "$UI_DIR"
    SSLEngine on
    SSLCertificateFile "$SSL_DIR/syswarden.crt"
    SSLCertificateKeyFile "$SSL_DIR/syswarden.key"

    <Directory "$UI_DIR">
        Options -Indexes +FollowSymLinks
        AllowOverride None
        <RequireAny>
$(echo -e "$APACHE_ALLOW_RULES")
        </RequireAny>
    </Directory>

    # Strict Security Headers
    Header always set Content-Security-Policy "default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://api.github.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com;"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "0"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</VirtualHost>
EOF

        if [[ "$APACHE_DAEMON" == "apache2" ]]; then
            # Debian/Ubuntu specific enabling
            a2enmod ssl headers >/dev/null 2>&1 || true
            ln -sf "$APACHE_CONF_DIR/syswarden-ui.conf" "$APACHE_ENABLE_DIR/syswarden-ui.conf" 2>/dev/null || true
        fi
    else
        log "INFO" "Configuring Nginx VHost for port 9999..."
        local NGINX_CONF_DIR="/etc/nginx/conf.d"
        if [[ -d "/etc/nginx/sites-available" ]]; then
            NGINX_CONF_DIR="/etc/nginx/sites-available"
        fi

        # HTTP/2 directive handling for backward compatibility (Nginx >= 1.25.1)
        local NGINX_HTTP2_DIRECTIVE="listen 9999 ssl http2;"
        if nginx -v 2>&1 | grep -qE "nginx/1\.(2[5-9]|[3-9][0-9])"; then
            NGINX_HTTP2_DIRECTIVE="listen 9999 ssl;
    http2 on;"
        fi

        cat <<EOF >"$NGINX_CONF_DIR/syswarden-ui.conf"
server {
    $NGINX_HTTP2_DIRECTIVE
    server_name _;

    ssl_certificate $SSL_DIR/syswarden.crt;
    ssl_certificate_key $SSL_DIR/syswarden.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    root $UI_DIR;
    index index.html;

    include mime.types;

    # --- Security Access Control ---
$(echo -e "$NGINX_ALLOW_RULES")

    # --- Strict Security Headers ---
    add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://api.github.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com;" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "0" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    server_tokens off;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ /\. {
        deny all;
    }
}
EOF

        if [[ -d "/etc/nginx/sites-enabled" ]]; then
            ln -sf "$NGINX_CONF_DIR/syswarden-ui.conf" "/etc/nginx/sites-enabled/syswarden-ui.conf"
            rm -f /etc/nginx/sites-enabled/default
        fi
    fi

    # --- 6. EXPOSE DASHBOARD PORT NATIVELY ---
    log "INFO" "Opening Port 9999 in OS Firewall to enable Dashboard routing..."
    if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        local DASH_ZONE
        DASH_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
        firewall-cmd --permanent --zone="$DASH_ZONE" --add-port=9999/tcp >/dev/null 2>&1 || true
        firewall-cmd --zone="$DASH_ZONE" --add-port=9999/tcp >/dev/null 2>&1 || true
    elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
        ufw allow 9999/tcp >/dev/null 2>&1 || true
    elif [[ "$FIREWALL_BACKEND" == "iptables" ]]; then
        if ! iptables -C INPUT -p tcp --dport 9999 -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -p tcp --dport 9999 -j ACCEPT
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true; fi
        fi
    elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        if nft list chain inet filter input >/dev/null 2>&1; then
            if ! nft list chain inet filter input 2>/dev/null | grep "tcp dport 9999 accept" >/dev/null; then
                nft insert rule inet filter input tcp dport 9999 accept 2>/dev/null || true
            fi
            if ! grep -q 'include "/etc/syswarden/syswarden.nft"' /etc/nftables.conf 2>/dev/null; then
                echo -e '\n# Added by SysWarden' >>/etc/nftables.conf
                echo 'include "/etc/syswarden/syswarden.nft"' >>/etc/nftables.conf
            fi
        fi
    fi

    # --- 7. DAEMON ORCHESTRATION ---
    if systemctl is-active --quiet syswarden-ui; then
        systemctl stop syswarden-ui >/dev/null 2>&1 || true
        systemctl disable syswarden-ui >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/syswarden-ui.service /usr/local/bin/syswarden-ui-server.py
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        local APACHE_SVC="apache2"
        if command -v httpd >/dev/null 2>&1; then APACHE_SVC="httpd"; fi

        systemctl enable "$APACHE_SVC" >/dev/null 2>&1 || true
        if systemctl is-active --quiet "$APACHE_SVC"; then
            systemctl reload "$APACHE_SVC" >/dev/null 2>&1 || true
        else
            systemctl restart "$APACHE_SVC" >/dev/null 2>&1 || true
        fi
    else
        systemctl enable nginx >/dev/null 2>&1 || true
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx >/dev/null 2>&1 || true
        else
            systemctl restart nginx >/dev/null 2>&1 || true
        fi
    fi

    local SERVER_IP
    SERVER_IP=$(curl -sL4 https://ifconfig.me 2>/dev/null || wget -qO- https://ifconfig.me 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i == "src") print $(i+1)}' | head -n 1 || echo "<YOUR_IP>")

    log "INFO" "Dashboard UI secured by Web Server at https://${SERVER_IP}:9999"
}
