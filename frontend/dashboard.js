// ============ CONFIG ============
const CONFIG = {
    API_BASE: 'http://localhost:5000/api',
    POLL_INTERVAL_MS: 5000,
    COLORS: {
        cyan: '#00d4ff',
        cyanDim: 'rgba(0,212,255,0.15)',
        cyanFill: 'rgba(0,212,255,0.07)',
        purple: '#a855f7',
        purpleDim: 'rgba(168,85,247,0.15)',
        high: '#ff4d6d',
        highDim: 'rgba(255,77,109,0.15)',
        medium: '#ff9f43',
        mediumDim: 'rgba(255,159,67,0.15)',
        low: '#00d4aa',
        lowDim: 'rgba(0,212,170,0.15)',
        textPrimary: '#ffffff',
        textSecondary: '#64748b',
        border: 'rgba(255,255,255,0.05)',
        bgSurface2: '#0e1628'
    },
    CHART_FONT: "'Space Grotesk', sans-serif"
};

// ============ STATE =============
const state = {
    currentDetections: [],
    selectedDetectionId: null,
    sortColumn: 'timestamp',
    sortDirection: 'desc',
    filterSeverity: 'all',
    filterSearch: '',
    currentMode: 'analyst',
    trainingMode: false,
    dismissedAlerts: new Set(),
    chartInstances: {},
    activeSimulation: null,
    simulationTimer: null,
    tourActive: false,
    tourStep: 0,
    apiError: false
};

// ============ API LAYER =========
async function fetchAPI(endpoint, options = {}) {
    try {
        const res = await fetch(`${CONFIG.API_BASE}${endpoint}`, options);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (state.apiError) {
            state.apiError = false;
            document.querySelector('.live-indicator').innerHTML = '<span class="live-dot"></span><span>LIVE</span>';
            document.querySelector('.live-indicator').style.color = 'var(--accent)';
        }
        return data;
    } catch (err) {
        if (!state.apiError) {
            state.apiError = true;
            document.querySelector('.live-indicator').innerHTML = '<span style="color:red">CONNECTION LOST</span>';
            const errOverlay = document.getElementById('connection-error-overlay');
            if (errOverlay) errOverlay.classList.remove('hidden');
        }
        throw err;
    }
}

// ============ SPLASH CARDS ======
async function loadSystemStats() {
    try {
        const res = await fetch('/api/system_stats');
        const data = await res.json();

        var updates = {
            'splash-active-hosts': data.active_hosts,
            'splash-packets': data.packets,
            'splash-data': data.data_transferred,
            'splash-uptime': data.uptime_str
        };

        Object.entries(updates).forEach(function ([id, val]) {
            var el = document.getElementById(id);
            if (el && el.textContent !== String(val)) {
                el.textContent = val;
            }
        });

    } catch (err) {
        console.error('System stats error:', err);
    }
}

function animateCount(elementId, target) {
    const el = document.getElementById(
        elementId
    );
    if (!el) return;

    // If target is 0 or invalid show 0
    if (!target || isNaN(target)) {
        el.textContent = '0';
        return;
    }

    const duration = 1500;
    const start = performance.now();

    function easeOut(t) {
        return 1 - Math.pow(1 - t, 3);
    }

    function tick(now) {
        const progress = Math.min(
            (now - start) / duration, 1
        );
        const value = Math.floor(
            easeOut(progress) * target
        );
        // Always set as string number
        el.textContent = value.toLocaleString();

        if (progress < 1) {
            requestAnimationFrame(tick);
        } else {
            el.textContent = target.toLocaleString();
        }
    }
    requestAnimationFrame(tick);
}

// Splash cards are now updated inside loadDashboardData() to guarantee matching numbers

// ============ UTILS ============
function safeNumber(val) {
    return (val !== null && val !== undefined) ? val.toLocaleString() : '0';
}

// getHealthStatus removed to unify logic with getReportStatus

// ============ KPI MODULE ========
const KPIModule = {
    async update() {
        if (typeof loadDashboardData === 'function') {
            await loadDashboardData();
        }
    },
    animateCountUp(element, target, duration = 1200) {
        if (!element) return;
        const start = performance.now();
        const easeOutExpo = t => t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
        const isFloat = target.toString().includes('.') || !Number.isInteger(target);

        function update(now) {
            const progress = Math.min((now - start) / duration, 1);
            const eased = easeOutExpo(progress);
            const val = eased * target;
            element.textContent = isFloat ? val.toFixed(1) : Math.floor(val);
            if (progress < 1) window.requestAnimationFrame(update);
            else element.textContent = isFloat ? target.toFixed(1) : target;
        }
        window.requestAnimationFrame(update);
    }
};

// Helper to safely set text or HTML
function setEl(id, val, isHTML = false) {
    const el = document.getElementById(id);
    if (!el) return;
    if (isHTML) el.innerHTML = val;
    else el.textContent = val;
}

async function loadDashboardData() {
    try {
        const res = await fetch(CONFIG.API_BASE + '/kpi');
        const data = await res.json();

        // Update splash with same data
        // same call same moment = same numbers
        const total = (data.high || 0) + (data.medium || 0) + (data.low || 0);

        // updateLiveIndicator removed

        const splashT = document.getElementById('splash-threats');
        const splashF = document.getElementById('splash-flows');
        if (splashT) splashT.textContent = total.toLocaleString();
        if (splashF) splashF.textContent = (data.total_flows || 0).toLocaleString();

        // ==========================================
        // COMMON KPI CARDS
        // ==========================================
        const fields = {
            'kpi-total': data.total_flows,
            'kpi-high': data.high,
            'kpi-medium': data.medium,
            'kpi-low': data.low,
            'kpi-avg-risk': data.avg_risk,
            'kpi-today': data.total
        };

        Object.entries(fields).forEach(([id, value]) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.textContent = typeof value === 'number' && !Number.isInteger(value)
                ? value.toFixed(1)
                : (value || 0).toLocaleString();
        });

        document.querySelectorAll('.kpi-sublabel').forEach(el => {
            el.textContent = 'Last 24 hours';
        });

        // ==========================================
        // SIMPLE MODE
        // ==========================================
        setEl('simple-health-title', data.status_simple);
        setEl('simple-health-subtext', data.status_sub);
        setEl('simple-incident-count', data.total.toLocaleString());
        setEl('simple-top-threat', data.top_attack || 'None detected');
        // Format last threat — handle timestamps, relative strings, or null
        var _rawLT = data.last_threat||data.last_detection||null;
        var _fmtLT = 'None';
        if(_rawLT){
            var _ts = Number(_rawLT);
            if(!isNaN(_ts) && _ts > 1000000000){
                // Unix timestamp (seconds or ms)
                var _d = new Date(_ts < 9999999999 ? _ts*1000 : _ts);
                _fmtLT = _d.getHours().toString().padStart(2,'0')+':'+_d.getMinutes().toString().padStart(2,'0');
            } else {
                _fmtLT = String(_rawLT); // already a string like "2 mins ago"
            }
        }
        var _ltt=document.getElementById('simple-last-threat-time');
        if(_ltt) _ltt.textContent=_fmtLT;
        var _ltt2=document.getElementById('simple-last-threat');
        if(_ltt2) _ltt2.textContent=_fmtLT;

        const bannerEl = document.getElementById('simple-health-banner');
        if (bannerEl) {
            let bClass = 'healthy';
            if (data.status === 'CRITICAL' || data.status === 'HIGH RISK') bClass = 'danger';
            else if (data.status === 'MODERATE') bClass = 'warning';
            bannerEl.className = `health-banner ${bClass}`;
        }

        let health = 100 - data.avg_risk;
        health = Math.max(0, Math.min(100, health));
        KPIModule.animateCountUp(document.getElementById('simple-health-pct'), health);

        const hFill = document.getElementById('simple-health-fill');
        if (hFill) {
            hFill.style.width = `${health}%`;
            hFill.style.backgroundColor = data.status_color;
        }

        // ==========================================
        // EXECUTIVE MODE
        // ==========================================
        const badge = document.getElementById('exec-risk-badge');
        const wrap = document.getElementById('exec-risk-badge-wrap');
        const hero = document.getElementById('exec-hero-card');

        if (badge && wrap && hero) {
            let bClass = 'low';
            if (data.status === 'CRITICAL') bClass = 'critical';
            else if (data.status === 'HIGH RISK') bClass = 'high';
            else if (data.status === 'MODERATE') bClass = 'medium';

            badge.className = `exec-risk-badge ${bClass}`;
            wrap.className = `exec-risk-badge-wrap ${bClass}`;
            hero.className = `exec-hero risk-${bClass}`;
            badge.style.color = data.status_color;

            // Unified Icon & Status
            badge.innerHTML = `<span style="font-size:24px; margin-right:12px">${data.status_icon}</span> ${data.status}`;
        }

        setEl('exec-risk-sublabel', data.status_sub);

        const totalIncidents = document.getElementById('exec-incident-total');
        if (totalIncidents) {
            KPIModule.animateCountUp(totalIncidents, data.total);
            if (data.total > 0) totalIncidents.classList.add('has-incidents');
            else totalIncidents.classList.remove('has-incidents');
        }

        // Ensure top_attack updates if element exists
        const execTopCat = document.getElementById('exec-top-category');
        if (execTopCat) {
            const attackName = (data.top_attack || 'None')
                .replace('dos', 'Server Flood')
                .replace('portscan', 'Network Spy')
                .replace('bruteforce', 'Brute Force')
                .replace('suspdns', 'DNS Tunnel')
                .replace('lateral', 'Lateral Move');
            execTopCat.textContent = attackName !== 'None' ? attackName : 'No threats detected';
        }

        // ==========================================
        // ANALYST MODE
        // ==========================================
        GaugeModule.update(data.avg_risk);

    } catch (err) {
        console.error('Dashboard error:', err);
    }
}

// ============ CHART MODULE ======
const glowPlugin = {
    id: 'lineGlow',
    beforeDraw(chart) {
        if (chart.config.type !== 'line') return;
        const ctx = chart.ctx;
        ctx.save();
        ctx.shadowColor = 'rgba(0,212,255,0.35)';
        ctx.shadowBlur = 10;
    },
    afterDraw(chart) {
        if (chart.config.type !== 'line') return;
        chart.ctx.restore();
    }
};

const ChartModule = {
    defaults() {
        Chart.defaults.color = CONFIG.COLORS.textSecondary;
        Chart.defaults.borderColor = CONFIG.COLORS.border;
        Chart.defaults.font.family = CONFIG.CHART_FONT;
        Chart.defaults.font.size = 11;
        Chart.defaults.plugins.legend.labels.color = CONFIG.COLORS.textPrimary;
        Chart.register(glowPlugin);
    },

    updateBarChart(chart, labels, data, bgColors, hoverColors) {
        if (!labels || labels.length === 0) {
            chart.data.labels = ['No data yet'];
            chart.data.datasets[0].data = [0];

            if (bgColors) chart.data.datasets[0].backgroundColor = bgColors;
            if (hoverColors) chart.data.datasets[0].hoverBackgroundColor = hoverColors;

            // Depends on if x or y is the value axis
            if (chart.options.indexAxis === 'y') {
                chart.options.scales.x.min = 0;
                chart.options.scales.x.max = 10;
            } else {
                chart.options.scales.y.min = 0;
                chart.options.scales.y.max = 10;
            }
        } else {
            chart.data.labels = labels;
            chart.data.datasets[0].data = data;

            if (bgColors) chart.data.datasets[0].backgroundColor = bgColors;
            if (hoverColors) chart.data.datasets[0].hoverBackgroundColor = hoverColors;

            if (chart.options.indexAxis === 'y') {
                chart.options.scales.x.min = 0;
                chart.options.scales.x.max = undefined;
            } else {
                chart.options.scales.y.min = 0;
                chart.options.scales.y.max = undefined;
            }
        }
        chart.update('none');
    },

    init() {
        this.defaults();

        // Severity Chart (Analyst)
        const ctxSev = document.getElementById('analyst-severity-chart');
        if (ctxSev) {
            state.chartInstances.sev = new Chart(ctxSev, {
                type: 'doughnut',
                data: { labels: ['High', 'Medium', 'Low'], datasets: [{ data: [0, 0, 0], backgroundColor: ['rgba(255,77,109,0.85)', 'rgba(255,159,67,0.85)', 'rgba(0,212,170,0.85)'], borderColor: ['rgba(255,77,109,0.3)', 'rgba(255,159,67,0.3)', 'rgba(0,212,170,0.3)'], hoverBackgroundColor: [CONFIG.COLORS.high, CONFIG.COLORS.medium, CONFIG.COLORS.low], borderWidth: 1 }] },
                options: { responsive: true, maintainAspectRatio: false, cutout: '72%', animation: { duration: 300 } }
            });
        }

        // Trend Chart (Analyst)
        const ctxTrend = document.getElementById('analyst-trend-chart');
        if (ctxTrend) {
            state.chartInstances.trend = new Chart(ctxTrend, {
                type: 'line',
                data: { labels: [], datasets: [{ label: 'Avg Risk', data: [], borderColor: CONFIG.COLORS.cyan, backgroundColor: CONFIG.COLORS.cyanFill, borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0, pointHoverRadius: 5, pointHoverBackgroundColor: CONFIG.COLORS.cyan, pointHoverBorderColor: '#060b14', pointHoverBorderWidth: 2 }] },
                options: {
                    responsive: true, maintainAspectRatio: false, animation: { duration: 300 },
                    scales: {
                        y: {
                            beginAtZero: true, max: 100, grid: { color: CONFIG.COLORS.border },
                            ticks: { callback: function (val) { return Number.isInteger(val) ? val : null; } }
                        },
                        x: { grid: { display: false } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        // Protocol Chart (Analyst)
        const ctxProto = document.getElementById('analyst-protocol-chart');
        if (ctxProto) {
            state.chartInstances.proto = new Chart(ctxProto, {
                type: 'bar',
                data: { labels: [], datasets: [{ data: [], backgroundColor: CONFIG.COLORS.cyan, borderRadius: 5, barThickness: 18 }] },
                options: {
                    indexAxis: 'y', responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false } },
                    scales: {
                        x: {
                            min: 0, grid: { color: CONFIG.COLORS.border },
                            ticks: { callback: function (val) { return Number.isInteger(val) ? val : null; } }
                        },
                        y: { grid: { display: false } }
                    }
                }
            });
        }

        const ctxSrc = document.getElementById('analyst-src-chart');
        if (ctxSrc) {
            state.chartInstances.src = new Chart(ctxSrc, {
                type: 'bar',
                data: { labels: [], datasets: [{ data: [], backgroundColor: 'rgba(255,77,109,0.20)', borderColor: CONFIG.COLORS.high, borderWidth: 1, hoverBackgroundColor: 'rgba(255,77,109,0.35)', borderRadius: 5, barThickness: 16 }] },
                options: {
                    indexAxis: 'y', responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false } },
                    scales: {
                        x: {
                            min: 0, grid: { color: CONFIG.COLORS.border },
                            ticks: { callback: function (val) { return Number.isInteger(val) ? val : null; } }
                        },
                        y: { grid: { display: false } }
                    }
                }
            });
        }

        const ctxDst = document.getElementById('analyst-dst-chart');
        if (ctxDst) {
            state.chartInstances.dst = new Chart(ctxDst, {
                type: 'bar',
                data: { labels: [], datasets: [{ data: [], backgroundColor: 'rgba(0,212,170,0.20)', borderColor: CONFIG.COLORS.low, borderWidth: 1, hoverBackgroundColor: 'rgba(0,212,170,0.35)', borderRadius: 5, barThickness: 16 }] },
                options: {
                    indexAxis: 'y', responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false } },
                    scales: {
                        x: {
                            min: 0, grid: { color: CONFIG.COLORS.border },
                            ticks: { callback: function (val) { return Number.isInteger(val) ? val : null; } }
                        },
                        y: { grid: { display: false } }
                    }
                }
            });
        }

        // Exec Severity Chart
        const ctxExecSev = document.getElementById('exec-severity-chart');
        if (ctxExecSev) {
            state.chartInstances.execSev = new Chart(ctxExecSev, {
                type: 'bar',
                data: { labels: ['High', 'Medium', 'Low'], datasets: [{ data: [0, 0, 0], backgroundColor: [CONFIG.COLORS.high, CONFIG.COLORS.medium, CONFIG.COLORS.low], borderRadius: 5, barThickness: 30 }] },
                options: {
                    responsive: true, maintainAspectRatio: false, animation: { duration: 300 }, plugins: { legend: { display: false } },
                    scales: {
                        y: {
                            min: 0, grid: { color: CONFIG.COLORS.border },
                            ticks: { callback: function (val) { return Number.isInteger(val) ? val : null; } }
                        },
                        x: { grid: { display: false } }
                    }
                }
            });
        }
    },

    async update() {
        if (state.currentMode === 'simple') return;

        try {
            if (state.currentMode === 'analyst' || state.currentMode === 'executive') {
                const sevData = await fetchAPI('/severity');
                const sevArr = [sevData.High || 0, sevData.Medium || 0, sevData.Low || 0];
                if (state.chartInstances.sev) { state.chartInstances.sev.data.datasets[0].data = sevArr; state.chartInstances.sev.update(); }
                if (state.chartInstances.execSev) { state.chartInstances.execSev.data.datasets[0].data = sevArr; state.chartInstances.execSev.update(); }
            }

            if (state.currentMode === 'analyst') {
                const [trend, proto, src, dst] = await Promise.all([
                    fetchAPI('/trend'), fetchAPI('/protocol'), fetchAPI('/top_src'), fetchAPI('/top_dst')
                ]);

                if (state.chartInstances.trend) {
                    state.chartInstances.trend.data.labels = trend.map(t => {
                        const d = new Date(t.minute);
                        return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
                    });
                    state.chartInstances.trend.data.datasets[0].data = trend.map(t => t.avg_risk);
                    state.chartInstances.trend.update();

                    const arrow = document.getElementById('kpi-risk-trend');
                    if (arrow && trend.length >= 2) {
                        const cur = trend[trend.length - 1].avg_risk;
                        const prev = trend[trend.length - 2].avg_risk;
                        arrow.innerText = cur > prev ? '↑' : (cur < prev ? '↓' : '→');
                        arrow.style.color = cur > prev ? CONFIG.COLORS.high : (cur < prev ? CONFIG.COLORS.low : CONFIG.COLORS.textSecondary);
                    }
                }

                if (state.chartInstances.proto) {
                    const protocolColors = { 'TCP': '#00d4ff', 'UDP': '#a855f7', 'DNS': '#00d4aa', 'ICMP': '#ff9f43', 'IRC': '#ff4d6d', 'Telnet': '#ff4d6d' };
                    const keys = Object.keys(proto).slice(0, 10);
                    const values = keys.map(k => proto[k]);
                    const bgColors = keys.map(k => protocolColors[k] || '#64748b');
                    const hoverColors = keys.map(k => (protocolColors[k] || '#64748b').replace(')', ',0.8)').replace('rgb', 'rgba'));
                    this.updateBarChart(state.chartInstances.proto, keys, values, bgColors, hoverColors);
                }

                if (state.chartInstances.src) {
                    this.updateBarChart(state.chartInstances.src, src.map(s => s.src_ip), src.map(s => s.count));
                }

                if (state.chartInstances.dst) {
                    this.updateBarChart(state.chartInstances.dst, dst.map(s => s.dst_ip), dst.map(s => s.count));
                }
            }

            // Removed top_src executive override to rely on loadDashboardData mapping.
            const trendElVal = document.getElementById('exec-trend-value');
            const trendEl = document.getElementById('exec-trend-sentence');
            if (trendEl && trendElVal) {
                const trend = await fetchAPI('/trend');
                if (trend.length >= 2) {
                    const cur = trend[trend.length - 1].avg_risk;
                    const prev = trend[0].avg_risk;
                    if (cur > prev + 5) {
                        trendEl.innerText = "Risk trending upward over last 30 minutes ⚠️";
                        trendElVal.innerText = "RISING";
                        trendElVal.style.color = CONFIG.COLORS.high;
                    }
                    else if (cur < prev - 5) {
                        trendEl.innerText = "Risk trending downward over last 30 minutes ✓";
                        trendElVal.innerText = "DROPPING";
                        trendElVal.style.color = CONFIG.COLORS.low;
                    }
                    else {
                        trendEl.innerText = "Risk trend is stable.";
                        trendElVal.innerText = "STABLE";
                        trendElVal.style.color = CONFIG.COLORS.textPrimary;
                    }
                }
            }
        } catch (err) { }
    }
};

// ============ HEATMAP MODULE ====
const HeatmapModule = {
    async update() {
        if (state.currentMode !== 'analyst') return;
        const container = document.getElementById('analyst-heatmap');
        if (!container) return;

        try {
            const data = await fetchAPI('/heatmap');
            if (!data || data.length === 0) return;

            const protocols = [...new Set(data.map(d => d.protocol))].sort();
            container.innerHTML = '';

            // Header row
            const blank = document.createElement('div');
            container.appendChild(blank);
            for (let i = 0; i < 24; i++) {
                const el = document.createElement('div');
                el.className = 'hm-label';
                el.innerText = i.toString().padStart(2, '0');
                container.appendChild(el);
            }

            // Calc max for opacity
            const maxVal = Math.max(...data.map(d => d.count), 1);

            protocols.forEach(p => {
                const label = document.createElement('div');
                label.className = 'hm-label';
                label.innerText = p;
                container.appendChild(label);

                for (let i = 0; i < 24; i++) {
                    const hourStr = i.toString().padStart(2, '0');
                    const match = data.find(d => d.protocol === p && d.hour === hourStr);
                    const count = match ? match.count : 0;

                    const cell = document.createElement('div');
                    cell.className = 'hm-cell hm-val';

                    if (count > 0) {
                        const intensity = Math.max(0.1, count / maxVal);
                        cell.style.backgroundColor = `rgba(99, 179, 237, ${intensity})`; // Blue accent
                        cell.title = `${p} at ${hourStr}:00 - ${count} flows`;
                    } else {
                        cell.style.backgroundColor = CONFIG.COLORS.bgSurface2;
                    }
                    container.appendChild(cell);
                }
            });

        } catch (e) { }
    }
};

// ============ GAUGE MODULE ======
function drawGauge(canvas, value) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cw = canvas.width;
    const ch = canvas.height;

    // Clear canvas
    ctx.clearRect(0, 0, cw, ch);

    const cx = cw / 2;
    const cy = ch - 20; // Move up slightly
    const r = Math.min(cw, ch * 2) / 2.5;

    const startAngle = Math.PI;
    const endAngle = 0;

    // 1) Draw dim background track
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, endAngle);
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.strokeStyle = 'rgba(255,255,255,0.04)';
    ctx.stroke();

    // 2) Determine color by score
    let color = CONFIG.COLORS.low;
    let glow = 'rgba(0,212,170,0.5)';
    if (value >= 75) {
        color = CONFIG.COLORS.high;
        glow = 'rgba(255,77,109,0.6)';
    }
    else if (value >= 45) {
        color = CONFIG.COLORS.medium;
        glow = 'rgba(255,159,67,0.5)';
    }

    const valAngle = startAngle + (value / 100) * Math.PI;

    // 3) Draw active arc
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, valAngle);
    ctx.lineWidth = 14;
    ctx.lineCap = 'round';
    ctx.strokeStyle = color;
    ctx.shadowColor = glow;
    ctx.shadowBlur = 15;
    ctx.stroke();
    ctx.shadowBlur = 0; // reset

    // 4) Draw dot at the tip
    const tipX = cx + r * Math.cos(valAngle);
    const tipY = cy + r * Math.sin(valAngle);
    ctx.beginPath();
    ctx.arc(tipX, tipY, 6, 0, Math.PI * 2);
    ctx.fillStyle = '#fff';
    ctx.shadowColor = glow;
    ctx.shadowBlur = 10;
    ctx.fill();
    ctx.shadowBlur = 0; // reset

    // 5) Text Value
    ctx.font = `800 52px ${CONFIG.CHART_FONT}`;
    ctx.fillStyle = color;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    ctx.fillText(value.toFixed(1), cx, cy - 20);

    // 6) Text Label
    ctx.font = `500 13px ${CONFIG.CHART_FONT}`;
    ctx.fillStyle = CONFIG.COLORS.textSecondary;
    ctx.fillText('Threat Level', cx, cy + 10);
}

const GaugeModule = {
    update(score) {
        if (state.currentMode !== 'analyst') return;
        const canvas = document.getElementById('gauge-canvas');
        if (canvas) {
            drawGauge(canvas, score);
        }
    }
};

// ============ ALERT MODULE ======
// Track last alert time
window.lastAlertTime = 0;
// Set this BEFORE any data loads
window.alertsEnabled = false;

// Enable alerts after 10 seconds
// This gives page time to load
// without spamming alerts
setTimeout(() => {
    window.alertsEnabled = true;
}, 10000);

function showAlert(message, severity) {
    if (!window.alertsEnabled) return;

    // Minimum 30 seconds between alerts
    const now = Date.now();
    if (now - window.lastAlertTime < 30000) {
        return;
    }
    window.lastAlertTime = now;

    // Only show HIGH severity alerts
    // Never show medium or low as popups
    if (severity !== 'high' && severity !== 'High') return;

    // Maximum 1 popup at a time
    const existing = document.querySelectorAll('.alert-popup');
    if (existing.length >= 1) return;

    // Build and show alert
    const popup = document.createElement('div');
    popup.className = 'alert-popup';
    popup.innerHTML = `
    <div class="alert-title">
      🔴 HIGH SEVERITY ALERT
    </div>
    <div class="alert-body">
      ${message}
    </div>
    <button class="alert-close" onclick="this.parentElement.remove()">
      ✕
    </button>
  `;

    document.body.appendChild(popup);

    // Auto dismiss after 5 seconds
    setTimeout(() => {
        if (popup.parentElement) {
            popup.remove();
        }
    }, 5000);
}

const AlertModule = {
    async update() {
        if (state.currentMode !== 'analyst' && state.currentMode !== 'simple') return;

        try {
            const alerts = await fetchAPI('/alerts');

            alerts.filter(a => !state.dismissedAlerts.has(a.id)).slice(0, 5).forEach(alert => {
                const type = state.currentMode === 'simple' ? JSON.parse(alert.simple_context).front_summary : alert.alert_type;
                const ip = state.currentMode === 'simple' ? 'a device' : alert.src_ip;

                showAlert(`${type} detected from ${ip}`, alert.severity ? alert.severity.toLowerCase() : 'high');
                state.dismissedAlerts.add(alert.id);
            });

        } catch (e) { }
    },
    dismiss(id) {
        state.dismissedAlerts.add(id);
    }
};

// ============ TABLE MODULE ======
const TableModule = {
    init() {
        document.querySelectorAll('th[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.dataset.sort;
                if (state.sortColumn === col) {
                    state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
                } else {
                    state.sortColumn = col;
                    state.sortDirection = 'desc';
                }
                this.render();
            });
        });

        const searchInput = document.getElementById('table-search');
        if (searchInput) {
            let debounceTimer;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    state.filterSearch = e.target.value.toLowerCase();
                    this.render();
                }, 300);
            });
        }

        const sevFilter = document.getElementById('table-filter-sev');
        if (sevFilter) {
            sevFilter.addEventListener('change', (e) => {
                state.filterSeverity = e.target.value;
                this.render();
            });
        }
    },

    async update() {
        if (state.currentMode !== 'analyst') return;
        try {
            state.currentDetections = await fetchAPI('/live');
            this.render();
        } catch (e) { }
    },

    render() {
        const tbody = document.getElementById('table-body');
        if (!tbody) return;

        let data = [...state.currentDetections];

        // Filter
        if (state.filterSeverity !== 'all') {
            data = data.filter(d => d.severity === state.filterSeverity);
        }
        if (state.filterSearch) {
            data = data.filter(d =>
                d.src_ip.toLowerCase().includes(state.filterSearch) ||
                d.dst_ip.toLowerCase().includes(state.filterSearch) ||
                d.alert_type.toLowerCase().includes(state.filterSearch)
            );
        }

        // Sort
        data.sort((a, b) => {
            let valA = a[state.sortColumn];
            let valB = b[state.sortColumn];
            if (state.sortColumn === 'timestamp') {
                valA = new Date(valA).getTime();
                valB = new Date(valB).getTime();
            }
            if (valA < valB) return state.sortDirection === 'asc' ? -1 : 1;
            if (valA > valB) return state.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });

        // Render
        // Instead of replacing innerHTML entirely which causes flicker, we can do it if few, but better to build robustly.
        tbody.innerHTML = '';

        const flagMap = {
            'Germany': '🇩🇪',
            'United States': '🇺🇸',
            'Netherlands': '🇳🇱',
            'Switzerland': '🇨🇭',
            'Russia': '🇷🇺',
            'China': '🇨🇳',
            'Iran': '🇮🇷'
        };

        data.forEach(d => {
            const tr = document.createElement('tr');
            tr.className = `severity-${d.severity}`;

            const timeStr = new Date(d.timestamp).toLocaleTimeString();

            let riskPct = Math.min(100, d.final_score);
            let riskColor = CONFIG.COLORS.low;
            if (riskPct >= 75) riskColor = CONFIG.COLORS.high;
            else if (riskPct >= 45) riskColor = CONFIG.COLORS.medium;

            const flag = d.geo_country && flagMap[d.geo_country] ? flagMap[d.geo_country] + ' ' : '';

            tr.innerHTML = `
                <td>${timeStr}</td>
                <td>${flag}${d.src_ip}</td>
                <td>${d.dst_ip}</td>
                <td>${d.protocol}</td>
                <td>${d.port}</td>
                <td>${d.severity}</td>
                <td>
                    <div class="risk-bar-container"><div class="risk-bar" style="width:${riskPct}%; background:${riskColor}"></div></div>
                    ${d.final_score.toFixed(1)}
                </td>
                <td><span style="border-radius:10px; padding:2px 8px; font-size:0.8rem; background:rgba(255,255,255,0.1)">${d.confidence.split(' ')[0]}</span></td>
                <td>${d.status}</td>
                <td>
                    <button class="btn btn-outline" onclick="DrawerModule.open(${d.id})" style="padding:2px 8px; font-size:0.8rem">Details →</button>
                    ${d.status === 'Open' ? `<button class="btn btn-primary" onclick="TableModule.investigate(${d.id})" style="padding:2px 8px; font-size:0.8rem">Investigate</button>` : ''}
                </td>
            `;
            tbody.appendChild(tr);
        });
    },

    async investigate(id) {
        try {
            await fetchAPI('/investigate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id })
            });
            this.update();
        } catch (e) { }
    }
};

// ============ DRAWER MODULE =====
const DrawerModule = {
    init() {
        document.getElementById('drawer-close')?.addEventListener('click', () => {
            document.getElementById('explain-drawer').classList.remove('open');
            state.selectedDetectionId = null;
        });

        // Simple modal bindings
        document.querySelectorAll('.fc-close').forEach(btn => btn.addEventListener('click', () => this.closeSimple()));
        document.getElementById('fc-flip-btn')?.addEventListener('click', () => {
            document.getElementById('flashcard-flipper').classList.add('is-flipped');
        });
        document.getElementById('fc-unflip-btn')?.addEventListener('click', () => {
            document.getElementById('flashcard-flipper').classList.remove('is-flipped');
        });
    },

    open(id) {
        const detection = state.currentDetections.find(d => d.id === id);
        if (!detection) return;
        state.selectedDetectionId = id;

        let ctx;
        try {
            ctx = typeof detection.analyst_context === 'string' ? JSON.parse(detection.analyst_context) : detection.analyst_context;
        } catch (e) { ctx = {}; }

        const body = document.getElementById('drawer-body');
        if (!body) return;

        body.innerHTML = `
            <div class="drawer-section">
                <h4>Detection Summary</h4>
                <div style="font-size:1.1rem; color:var(--text-primary); margin-bottom:8px">${detection.alert_type}</div>
                <div class="text-sm">From: <span style="font-family:var(--font-mono)">${detection.src_ip}</span></div>
                <div class="text-sm">To: <span style="font-family:var(--font-mono)">${detection.dst_ip}:${detection.port}</span></div>
            </div>
            
            <div class="drawer-section">
                <h4>Rule Details</h4>
                <p class="text-sm">${ctx.rule_explanation || 'No details'}</p>
            </div>
            
            <div class="drawer-section">
                <h4>Score Breakdown</h4>
                <div class="drawer-item"><span>Rule Score</span> <span class="text-primary">${(ctx.score_breakdown?.rule_score || 0).toFixed(1)}</span></div>
                <div class="drawer-item"><span>Anomaly Score</span> <span class="text-primary">${(ctx.score_breakdown?.anomaly_score || 0).toFixed(1)}</span></div>
                <div class="drawer-item" style="border-top:1px solid var(--border); padding-top:8px">
                    <strong>Final Risk</strong> 
                    <strong class="text-red">${detection.final_score.toFixed(1)}</strong>
                </div>
                <div class="text-sm" style="margin-top:4px; opacity:0.7">${ctx.score_breakdown?.formula || ''}</div>
            </div>
            
            <div class="drawer-section">
                <h4>Confidence</h4>
                <p class="text-sm">${ctx.confidence_explanation || detection.confidence}</p>
            </div>
            
            <div class="drawer-section">
                <h4>MITRE ATT&CK</h4>
                <div class="drawer-item"><span>Tactic</span> <span class="text-primary">${ctx.mitre?.tactic_id ? ctx.mitre.tactic_id + ' - ' : ''}${ctx.mitre?.tactic || 'N/A'}</span></div>
                <div class="drawer-item"><span>Technique</span> 
                    <a href="${ctx.mitre?.url || '#'}" target="_blank" class="text-accent" style="color:var(--accent)">
                        ${ctx.mitre?.technique_id} - ${ctx.mitre?.technique_name}
                    </a>
                </div>
                ${ctx.mitre?.subtechnique && ctx.mitre.subtechnique !== 'None' ? `<div class="drawer-item"><span>Subtechnique</span> <span class="text-primary">${ctx.mitre.subtechnique}</span></div>` : ''}
                ${ctx.mitre?.guidance ? `<div class="drawer-item" style="margin-top:8px; display:block"><span>Detection Guidance</span><div style="color:var(--text-primary); margin-top:4px; font-size:0.85rem">${ctx.mitre.guidance}</div></div>` : ''}
            </div>
            
            <div class="drawer-section">
                <h4>IDS Signature Match</h4>
                <div style="font-family:var(--font-mono); font-size:0.85rem; color:var(--text-primary); background:rgba(0,0,0,0.3); padding:8px; border-radius:4px; border:1px solid var(--border)">
                    ${ctx.signature_matched || 'No exact signature matched'}
                </div>
            </div>
            
            <div class="drawer-section">
                <h4>Recommended Actions</h4>
                <ul class="text-sm" style="padding-left:20px">
                    ${(ctx.mitigation || []).map(m => `<li>${m}</li>`).join('')}
                </ul>
            </div>
            
            <div class="drawer-section">
                <button class="btn btn-primary" style="width:100%" onclick="TableModule.investigate(${detection.id})">Investigate Now</button>
            </div>
        `;

        document.getElementById('explain-drawer').classList.add('open');
    },

    openSimple(detection) {
        let ctx;
        try {
            ctx = typeof detection.simple_context === 'string' ? JSON.parse(detection.simple_context) : detection.simple_context;
        } catch (e) { ctx = {}; }

        document.getElementById('flashcard-flipper').classList.remove('is-flipped');
        document.getElementById('fc-front-title').innerText = ctx.front || 'What happened?';
        document.getElementById('fc-front-summary').innerText = ctx.front_summary || '';
        document.getElementById('fc-back-details').innerText = ctx.what_happened || '';
        document.getElementById('fc-back-analogy').innerText = ctx.real_world_analogy || '';

        const cveEl = document.getElementById('fc-back-cve');
        if (cveEl) cveEl.innerText = ctx.related_cves || '';

        const ul = document.getElementById('fc-back-actions');
        if (ul) {
            ul.innerHTML = (ctx.what_to_do || []).map(a => `<li>${a}</li>`).join('');
        }

        document.getElementById('simple-flashcard').classList.remove('hidden');
    },

    closeSimple() {
        document.getElementById('simple-flashcard').classList.add('hidden');
    }
};

// ============ STORY MODULE ======
const StoryModule = {
    async update() {
        if (state.currentMode !== 'simple') return;
        try {
            const data = await fetchAPI('/story');
            const feed = document.getElementById('simple-story-feed');
            if (feed) {
                feed.style.display = 'block';
                feed.innerHTML = '';
                data.forEach(s => {
                    const el = document.createElement('div');
                    el.className = 'story-entry';
                    el.innerHTML = `<div class="story-dot ${s.severity.toLowerCase()}"></div><div class="story-content"><div class="story-time">${s.time}</div><div class="story-text">${s.text}</div></div>`;
                    feed.appendChild(el);
                });
            }
        } catch(e) {}
        try {
            const alerts = await fetchAPI('/alerts?limit=10');
            const arr = Array.isArray(alerts) ? alerts : (alerts.alerts || []);
            const container = document.getElementById('incidents-container');
            if (container) {
                container.innerHTML = '';
                arr.forEach(a => {
                    const sev = a.severity || 'low';
                    const col = sev==='high'?'#ef4444':sev==='medium'?'#f59e0b':'#10b981';
                    const div = document.createElement('div');
                    div.style.cssText = 'padding:10px 14px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px;color:#94a3b8;display:flex;justify-content:space-between;align-items:center';
                    div.innerHTML = `<span>${a.attack_name||'Alert'} — ${a.src_ip||'unknown'}</span><span style="color:${col};font-size:11px;font-weight:700">${a.time_ago||''}</span>`;
                    container.appendChild(div);
                });
                const cnt = document.getElementById('incidents-count');
                if (cnt) cnt.textContent = arr.length;
            }
        } catch(e) {}
    },

    // updateIncidents obsolete -> Replaced by loadAlerts
};

// ============ SIMULATOR MODULE ==
const SimulatorModule = {
    pollInterval: null,

    init() {
        // Initialize simple mode buttons
        document.querySelectorAll('#simple-sim-grid .attack-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const type = btn.dataset.attack;
                this.start(type, 'simple');
            });
        });

        // Initialize analyst mode buttons
        document.querySelectorAll('#analyst-sim-grid .attack-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const type = btn.dataset.attack;
                this.start(type, 'analyst');
            });
        });

        document.getElementById('analyst-sim-cancel')?.addEventListener('click', () => this.cancel());
        document.getElementById('simple-sim-cancel')?.addEventListener('click', () => this.cancel());

        // Collapsible logic for Analyst Mode Sim Panel
        const toggle = document.getElementById('analyst-sim-toggle');
        if (toggle) {
            toggle.addEventListener('click', function () {
                const content = document.getElementById('analyst-simulator-container');
                if (content) {
                    content.classList.toggle('hidden');
                    const chevron = this.querySelector('.chevron');
                    if (chevron) {
                        chevron.style.transform = content.classList.contains('hidden') ? 'rotate(0deg)' : 'rotate(180deg)';
                    }
                }
            });
        }
    },

    async start(attackType, modeContext) {
        if (state.activeSimulation) return;

        try {
            // Send start request
            const res = await fetchAPI('/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attack_type: attackType })
            });

            if (res.status === 'started') {
                state.activeSimulation = {
                    id: res.simulation_id,
                    type: attackType,
                    mode: modeContext
                };

                this.prepareUI(modeContext, attackType);
                this.startPolling();

                // Force an immediate PollingEngine update so the dashboard catches the first spike
                setTimeout(() => PollingEngine.forceUpdate(), 500);
            }
        } catch (e) {
            console.error("Failed to start simulation:", e);
        }
    },

    prepareUI(mode, attackType) {
        const grid = document.getElementById(`${mode}-sim-grid`);
        const statusPanel = document.getElementById(`${mode}-sim-status`);
        const debriefPanel = document.getElementById(`${mode}-sim-debrief`);

        if (grid) grid.style.display = 'none';
        if (debriefPanel) debriefPanel.classList.add('hidden');
        if (statusPanel) {
            statusPanel.classList.remove('hidden');

            // Set title specific to analyst mode if it exists
            const titleEl = document.getElementById(`${mode}-sim-title`);
            if (titleEl) {
                const attackNames = {
                    'dos': '🌊 Server Flood',
                    'portscan': '🔍 Network Spy',
                    'bruteforce': '🔐 Password Guesser',
                    'suspdns': '📡 Hidden Signals',
                    'lateral': '🕵️ Internal Intruder'
                };
                titleEl.innerText = `${attackNames[attackType] || 'Simulation'} In Progress`;
            }

            // Reset Progress UI
            const progFill = document.getElementById(`${mode}-sim-progress`);
            const timer = document.getElementById(`${mode}-sim-timer`);
            const alerts = document.getElementById(`${mode}-sim-alerts`);
            const txt = document.getElementById(`${mode}-sim-status-text`);

            if (progFill) {
                progFill.style.transition = 'none';
                progFill.style.width = '0%';
                progFill.style.background = 'var(--accent)';
                // Force reflow
                void progFill.offsetWidth;
                progFill.style.transition = 'width 1s linear, background 1s';
            }

            if (timer) timer.innerText = `0s / 60s`;
            if (alerts) alerts.innerText = mode === 'simple' ? `Threats caught so far: 0` : `0`;
            if (txt) txt.innerText = mode === 'simple' ? `System analyzing traffic patterns...` : `Status: Initializing...`;
        }
    },

    startPolling() {
        if (this.pollInterval) clearInterval(this.pollInterval);

        // Poll every 1 second
        this.pollInterval = setInterval(async () => {
            try {
                const status = await fetchAPI('/simulate/status');

                if (!status.active) {
                    // Simulation finished naturally on the backend
                    this.finishSimulation();
                    return;
                }

                this.updateUI(status);

            } catch (e) {
                console.error("Simulation poll error:", e);
            }
        }, 1000);
    },

    updateUI(status) {
        if (!state.activeSimulation) return;
        const mode = state.activeSimulation.mode;

        const progFill = document.getElementById(`${mode}-sim-progress`);
        const timer = document.getElementById(`${mode}-sim-timer`);
        const alerts = document.getElementById(`${mode}-sim-alerts`);
        const txtText = document.getElementById(`${mode}-sim-status-text`);

        const pct = Math.min(100, Math.max(0, (status.elapsed_seconds / 60) * 100));

        if (progFill) {
            progFill.style.width = `${pct}%`;
            // Change color as it progresses
            if (pct > 75) progFill.style.background = 'var(--high)';
            else if (pct > 40) progFill.style.background = 'var(--medium)';
        }

        if (timer) timer.innerText = `${status.elapsed_seconds}s / 60s`;
        if (alerts) alerts.innerText = mode === 'simple' ? `Threats caught so far: ${status.alerts_generated}` : `${status.alerts_generated}`;

        if (txtText) {
            let msg = "Analyzing traffic...";
            if (status.elapsed_seconds > 45) msg = "Threat contained. Compiling report...";
            else if (status.elapsed_seconds > 20) msg = "Defenses actively blocking malicious packets...";
            else if (status.elapsed_seconds > 5) msg = "Signatures match known attack patterns...";

            txtText.innerText = mode === 'simple' ? msg : `Status: ${msg}`;
        }
    },

    async finishSimulation() {
        const simData = state.activeSimulation;
        if (!simData) return;

        const simId = simData.id;
        const mode = simData.mode;

        // Stop polling and clear state
        if (this.pollInterval) clearInterval(this.pollInterval);
        state.activeSimulation = null;

        // Hide status, show grid again (so they can run another one later)
        const statusPanel = document.getElementById(`${mode}-sim-status`);
        const grid = document.getElementById(`${mode}-sim-grid`);
        if (statusPanel) statusPanel.classList.add('hidden');
        if (grid) grid.style.display = 'grid';

        // Wait briefly to ensure backend DB wrote the final debrief row
        setTimeout(async () => {
            try {
                const debrief = await fetchAPI(`/debrief/${simId}`);
                if (debrief && !debrief.error) {
                    this.renderDebrief(mode, debrief);
                }
            } catch (e) {
                console.error("Failed to load debrief:", e);
            }
        }, 1500);

        // Force a final update to clear the dashboard of the attack
        PollingEngine.forceUpdate();
    },

    async cancel() {
        if (!state.activeSimulation) return;

        const mode = state.activeSimulation.mode;

        // API call to cancel
        try {
            await fetchAPI('/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attack_type: 'cancel' })
            });
        } catch (e) { }

        if (this.pollInterval) clearInterval(this.pollInterval);
        state.activeSimulation = null;

        const statusPanel = document.getElementById(`${mode}-sim-status`);
        const grid = document.getElementById(`${mode}-sim-grid`);
        const debriefPanel = document.getElementById(`${mode}-sim-debrief`);

        if (statusPanel) statusPanel.classList.add('hidden');
        if (grid) grid.style.display = 'grid';
        if (debriefPanel) debriefPanel.classList.add('hidden');

        PollingEngine.forceUpdate();
    },

    renderDebrief(mode, debrief) {
        const debriefPanel = document.getElementById(`${mode}-sim-debrief`);
        if (!debriefPanel) return;

        const stepsHtml = (debrief.protection_steps || []).map(s => `<li>${s}</li>`).join('');

        debriefPanel.innerHTML = `
            <div class="debrief-header">
                <div class="debrief-title">Simulation Analysis Complete</div>
                <div class="debrief-grade ${debrief.detection_grade}">
                    ${debrief.detection_grade_icon} Grade: ${debrief.detection_grade}
                </div>
            </div>
            
            <div class="debrief-stats">
                <div>
                    <div class="debrief-stat-label">Total Caught</div>
                    <div class="debrief-stat-val">${debrief.total_alerts}</div>
                </div>
                <div>
                    <div class="debrief-stat-label">Critical</div>
                    <div class="debrief-stat-val" style="color:var(--high)">${debrief.high_alerts}</div>
                </div>
                <div>
                    <div class="debrief-stat-label">Medium</div>
                    <div class="debrief-stat-val" style="color:var(--medium)">${debrief.medium_alerts}</div>
                </div>
                <div>
                    <div class="debrief-stat-label">Response Time</div>
                    <div class="debrief-stat-val">${debrief.first_detection_seconds.toFixed(1)}s</div>
                </div>
            </div>
            
            <div class="debrief-section">
                <h4><span style="font-size:16px">🎯</span> What Happened</h4>
                <p>${debrief.what_happened}</p>
            </div>
            
            <div class="debrief-section">
                <h4><span style="font-size:16px">🌍</span> Real World Impact</h4>
                <p>${debrief.real_world_example}</p>
            </div>
            
            <div class="debrief-section" style="margin-bottom:0">
                <h4><span style="font-size:16px">🛡️</span> How To Protect</h4>
                <ul class="debrief-steps">
                    ${stepsHtml}
                </ul>
            </div>
            
            <button class="btn btn-outline" style="width:100%; margin-top:24px;" onclick="document.getElementById('${mode}-sim-debrief').classList.add('hidden')">Close Report</button>
        `;

        debriefPanel.classList.remove('hidden');
    }
};

// ============ REPORT MODULE ============

async function generateAndDownloadReport() {
    const btn = document.getElementById(
        'report-btn'
    );
    if (btn) {
        btn.textContent = '⏳ Generating...';
        btn.disabled = true;
    }

    try {
        // Use /api/report which already has
        // correct status calculated by backend
        const res = await fetch('/api/report');
        const data = await res.json();

        const reportData = {
            status: data.status,
            status_desc: data.status_desc,
            statusColor:
                data.status === 'CRITICAL' ? '#ff4d6d' :
                    data.status === 'HIGH RISK' ? '#ff4d6d' :
                        data.status === 'MODERATE' ? '#ff9f43' :
                            '#00d4aa',
            total_flows: data.total_flows || 0,
            total_det: data.total_detections || 0,
            high: data.high || 0,
            medium: data.medium || 0,
            low: data.low || 0,
            avg_risk: data.avg_risk || '0.0',
            summary_text: data.summary_text || '',
            recommendations: data.recommendations || [],
            positive_note: data.positive_note || '',
            time_window: data.time_window ||
                'Last 24 Hours'
        };

        const html = buildReportHTML(reportData);
        const blob = new Blob(
            [html], { type: 'text/html' }
        );
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.target = '_blank';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(
            () => URL.revokeObjectURL(url), 60000
        );

    } catch (err) {
        console.error('Report error:', err);
        alert('Report failed: ' + err.message);
    } finally {
        if (btn) {
            btn.textContent = '📄 GENERATE REPORT';
            btn.disabled = false;
        }
    }
}

function buildSummaryText(kpi) {
    const total = kpi.total_flows || 0;
    const high = kpi.high || 0;
    const med = kpi.medium || 0;
    const low = kpi.low || 0;

    if (high > 0) {
        return `In the last 24 hours your network 
    processed ${total.toLocaleString()} traffic 
    flows. ${high} required urgent attention, 
    ${med} were worth reviewing, and ${low} 
    were routine activity.`;
    }
    return `In the last 24 hours your network 
  processed ${total.toLocaleString()} traffic 
  flows. No critical threats were detected. 
  ${med} medium severity events were logged 
  and automatically monitored.`;
}

function buildTopConcern(live) {
    if (!live || live.length === 0) return null;
    const top = live.find(d => d.severity === 'high')
        || live.find(d => d.severity === 'medium');
    if (!top) return null;
    return `${top.attack_category || 'Suspicious activity'} 
  was detected from ${top.src_ip} targeting 
  ${top.dst_ip}. Risk score: ${top.final_score}. 
  Status: ${top.status}.`;
}

function buildRecommendations(kpi) {
    const recs = [];
    if ((kpi.high || 0) > 0) {
        recs.push(
            'Immediately review all high severity ' +
            'detections in the Analyst dashboard'
        );
        recs.push(
            'Isolate any internal devices flagged ' +
            'as attack sources'
        );
    }
    if ((kpi.medium || 0) > 0) {
        recs.push(
            'Review medium severity detections ' +
            'and investigate unusual patterns'
        );
    }
    recs.push(
        'Ensure all server software is ' +
        'up to date with security patches'
    );
    recs.push(
        'Review firewall rules and block ' +
        'any flagged external IP addresses'
    );
    return recs.slice(0, 5);
}

function buildPositiveNote(kpi) {
    if ((kpi.high || 0) === 0) {
        return 'Your system automatically detected ' +
            'and logged all suspicious activity. ' +
            'No critical threats required ' +
            'manual intervention.';
    }
    return 'Your detection system is actively ' +
        'monitoring all network traffic ' +
        'and flagging threats in real time.';
}

function buildBreakdown(live) {
    if (!live || live.length === 0) return [];

    const counts = {};
    live.forEach(d => {
        const cat = d.attack_category || 'Unknown';
        if (!counts[cat]) {
            counts[cat] = {
                name: cat,
                count: 0,
                severity: d.severity,
                first_seen: d.timestamp
            };
        }
        counts[cat].count++;
    });

    return Object.values(counts)
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);
}

function buildReportHTML(data) {
    const now = new Date();
    const dateStr = now.toLocaleDateString(
        'en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    }
    );
    const timeStr = now.toLocaleTimeString();

    return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>VNT Security Report — ${dateStr}</title>
  <style>
    * { margin:0; padding:0; 
        box-sizing:border-box; }
    body {
      font-family: Arial, sans-serif;
      background: #fff;
      color: #1a1a2e;
      padding: 48px;
      max-width: 860px;
      margin: 0 auto;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding-bottom: 24px;
      border-bottom: 2px solid #e2e8f0;
      margin-bottom: 32px;
    }
    .logo-wrap {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .logo-icon {
      width: 48px; height: 48px;
      background: #0a1628;
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
    }
    .logo-title {
      font-size: 20px;
      font-weight: 900;
      color: #0a1628;
    }
    .logo-sub {
      font-size: 10px;
      color: #94a3b8;
      letter-spacing: 0.10em;
      text-transform: uppercase;
      margin-top: 3px;
    }
    .meta {
      text-align: right;
      font-size: 12px;
      color: #64748b;
      line-height: 1.9;
    }
    .status-box {
      text-align: center;
      padding: 36px;
      background: #f8fafc;
      border-radius: 16px;
      border: 1px solid #e2e8f0;
      margin-bottom: 28px;
    }
    .status-label {
      font-size: 10px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: #94a3b8;
      margin-bottom: 16px;
    }
    .status-badge {
      display: inline-block;
      font-size: 34px;
      font-weight: 900;
      font-family: 'Arial Black', Arial;
      padding: 14px 44px;
      border-radius: 12px;
      letter-spacing: 0.06em;
      color: ${data.statusColor};
      background: ${data.statusColor}18;
      border: 2px solid ${data.statusColor}40;
      margin-bottom: 14px;
    }
    .status-desc {
      font-size: 14px;
      color: #64748b;
      line-height: 1.6;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(4,1fr);
      gap: 14px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 20px 14px;
      text-align: center;
    }
    .stat-num {
      font-size: 36px;
      font-weight: 900;
      font-family: 'Arial Black', Arial;
      line-height: 1;
      margin-bottom: 8px;
    }
    .stat-num.total  { color: #0a1628; }
    .stat-num.high   { color: #ff4d6d; }
    .stat-num.medium { color: #ff9f43; }
    .stat-num.low    { color: #00d4aa; }
    .stat-lbl {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #94a3b8;
    }
    .section {
      margin-bottom: 24px;
    }
    .section-title {
      font-size: 13px;
      font-weight: 700;
      color: #0a1628;
      padding: 0 0 10px 12px;
      border-left: 3px solid #00d4ff;
      border-bottom: 1px solid #e2e8f0;
      margin-bottom: 14px;
    }
    .section-body {
      font-size: 14px;
      color: #475569;
      line-height: 1.7;
    }
    .rec-list {
      padding-left: 20px;
    }
    .rec-list li {
      font-size: 14px;
      color: #475569;
      line-height: 1.7;
      margin-bottom: 8px;
    }
    .rec-list li::marker {
      color: #00d4ff;
      font-weight: 700;
    }
    .positive {
      background: #f0fdf9;
      border-left: 4px solid #00d4aa;
      border-radius: 8px;
      padding: 14px 18px;
      font-size: 14px;
      color: #065f46;
      line-height: 1.6;
    }
    .footer {
      margin-top: 48px;
      padding-top: 20px;
      border-top: 1px solid #e2e8f0;
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: #94a3b8;
    }
    @media print {
      body { padding: 24px; }
    }
  </style>
</head>
<body>

  <div class="header">
    <div class="logo-wrap">
      <div class="logo-icon">🛡️</div>
      <div>
        <div class="logo-title">
          Visual Network Tracker
        </div>
        <div class="logo-sub">
          Explainable Threat Intelligence
        </div>
      </div>
    </div>
    <div class="meta">
      <div>${dateStr}</div>
      <div>${timeStr}</div>
      <div style="font-size:11px;
           color:#94a3b8;
           letter-spacing:0.10em;
           text-transform:uppercase;
           margin-top:6px">
        ${data.time_window}
      </div>
    </div>
  </div>

  <div class="status-box">
    <div class="status-label">
      Overall Network Status
    </div>
    <div class="status-badge">
      ${data.status}
    </div>
    <div class="status-desc">
      ${data.status_desc}
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-num total">
        ${data.total_flows.toLocaleString()}
      </div>
      <div class="stat-lbl">Flows (24h)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num high">
        ${data.high.toLocaleString()}
      </div>
      <div class="stat-lbl">High (24h)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num medium">
        ${data.medium.toLocaleString()}
      </div>
      <div class="stat-lbl">Medium (24h)</div>
    </div>
    <div class="stat-card">
      <div class="stat-num low">
        ${data.low.toLocaleString()}
      </div>
      <div class="stat-lbl">Low (24h)</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">
      Network Summary
    </div>
    <div class="section-body">
      ${data.summary_text}
    </div>
  </div>

  <div class="section">
    <div class="section-title">
      Recommended Actions
    </div>
    <ol class="rec-list">
      ${data.recommendations.map(r => `<li>${r}</li>`).join('')}
    </ol>
  </div>

  <div class="section">
    <div class="positive">
      ✓ ${data.positive_note}
    </div>
  </div>

  <div class="footer">
    <span>
      Generated by Visual Network Tracker • 
      Explainable Threat Intelligence Platform
    </span>
    <span>Report ID: VNT-${Date.now()}</span>
  </div>

</body>
</html>`;
}

function showReportFallback() {
    // If backend offline, generate minimal report from current state
    const data = {
        status: 'UNKNOWN',
        summary_text: 'Backend offline during report generation. Please start the Flask server and try again.',
        total_flows: 0, high: 0, medium: 0, low: 0,
        recommendations: [
            'Start the Flask backend: cd backend && python app.py',
            'Visit http://localhost:5000 instead of opening HTML directly',
            'Check that all Python dependencies are installed'
        ],
        positive_note: 'Once connected, full report data will be available.'
    };
    const win = window.open('', '_blank');
    win.document.write(buildReportHTML(data));
    win.document.close();
}

const ReportModule = {
    init() {
        // init is currently intentionally isolated. Button click generates logic natively defined in index.html.
    }
};

// ============ DEVICE RISK =======
const DeviceRiskModule = {
    async update() {
        if (state.currentMode !== 'analyst') return;
        try {
            const data = await fetchAPI('/device_risk');
            const container = document.getElementById('device-risk-content');
            if (!container) return;

            container.innerHTML = '';
            data.slice(0, 10).forEach(d => {
                const bars = (d.risk_history || []).map(r => {
                    let color = CONFIG.COLORS.low;
                    if (r >= 75) color = CONFIG.COLORS.high;
                    else if (r >= 45) color = CONFIG.COLORS.medium;
                    return `< div class="dr-segment" style = "background:${color}" ></div > `;
                }).join('');

                const sevClass = d.total_detections >= 20 ? 'high' : '';

                const el = document.createElement('div');
                el.className = `device - risk - card ${sevClass} `;
                el.innerHTML = `
        < div class="device-risk-info" >
                        <strong style="font-family:var(--font-mono)">${d.ip}</strong>
                        <span class="text-sm">${d.nickname}</span>
                    </div >
        <div>
            <div class="text-sm" style="margin-bottom:2px">Risk Trend</div>
            <div class="device-risk-history-bar">${bars}</div>
            <div class="text-sm" style="margin-top:2px">${d.total_detections} flags today</div>
        </div>
    `;
                container.appendChild(el);
            });
        } catch (e) { }
    }
};

// ============ TOUR MODULE =======
const TourModule = {
    steps: [
        { el: null, txt: "Welcome to Visual Network Tracker. This platform monitors your network and explains threats in plain English.", m: 'simple' },
        { el: '#simple-health-banner', txt: "This is your Network Health Score. Think of it like a doctor checking your network's pulse.", m: 'simple' },
        { el: '.incident-cards-container', txt: "These cards show recent suspicious activity. Red means urgent, yellow means worth a look.", m: 'simple' },
        { el: '.incident-cards-container', txt: "Click any incident to learn exactly what happened and what to do about it.", m: 'simple' },
        { el: '.simple-simulator-card', txt: "Use the simulator to test how your network responds to real attack types — safely.", m: 'simple' },
        { el: '.mode-toggle-group', txt: "Switch between Simple, Executive, and Analyst mode using the toggle at the top.", m: 'simple' }
    ],

    init() {
        document.getElementById('btn-tour')?.addEventListener('click', () => this.start());
        document.getElementById('tour-skip')?.addEventListener('click', () => this.end());
        document.getElementById('tour-next')?.addEventListener('click', () => this.next());
        document.getElementById('tour-prev')?.addEventListener('click', () => {
            if (state.tourStep > 0) { state.tourStep--; this.render(); }
        });

        if (!localStorage.getItem('vnt_tour_seen')) {
            setTimeout(() => this.start(), 1500);
            localStorage.setItem('vnt_tour_seen', 'true');
        }
    },

    start() {
        state.tourActive = true;
        state.tourStep = 0;
        switchMode('simple');
        document.getElementById('tour-overlay').classList.remove('hidden');
        this.render();
    },

    end() {
        state.tourActive = false;
        document.getElementById('tour-overlay').classList.add('hidden');
    },

    next() {
        if (state.tourStep < this.steps.length - 1) {
            state.tourStep++;
            this.render();
        } else {
            this.end();
        }
    },

    render() {
        const step = this.steps[state.tourStep];
        if (state.currentMode !== step.m) {
            switchMode(step.m);
        }

        const text = document.getElementById('tour-text');
        const counter = document.getElementById('tour-counter');
        const spotlight = document.getElementById('tour-spotlight');
        const tooltip = document.getElementById('tour-tooltip');

        if (text) text.innerText = step.txt;
        if (counter) counter.innerText = `${state.tourStep + 1} of ${this.steps.length} `;

        if (step.el) {
            const target = document.querySelector(step.el);
            if (target) {
                const rect = target.getBoundingClientRect();
                spotlight.style.opacity = 1;
                spotlight.style.top = `${rect.top - 10} px`;
                spotlight.style.left = `${rect.left - 10} px`;
                spotlight.style.width = `${rect.width + 20} px`;
                spotlight.style.height = `${rect.height + 20} px`;

                tooltip.style.top = `${rect.bottom + 20} px`;
                tooltip.style.left = `${rect.left} px`;

                // Keep tooltip on screen
                if (rect.bottom + 150 > window.innerHeight) {
                    tooltip.style.top = `${rect.top - 150} px`;
                }
            }
        } else {
            spotlight.style.opacity = 0;
            tooltip.style.top = '50%';
            tooltip.style.left = '50%';
            tooltip.style.transform = 'translate(-50%, -50%)';
        }
    }
};

function showSimpleContent() {
    var hero = document.getElementById(
        'simple-scan-hero');
    var content = document.getElementById(
        'simple-mode-content');
    var splash = document.getElementById(
        'splash-section');

    if (hero) hero.style.display = 'none';

    if (content) {
        content.style.display = 'block';
        setTimeout(function () {
            content.style.opacity = '1';
        }, 50);
    }

    if (splash) {
        splash.style.display = 'block';
        splash.style.opacity = '0';
        splash.style.transition =
            'opacity 600ms ease';
        setTimeout(function () {
            splash.style.opacity = '1';
        }, 400);
    }

    setTimeout(function () {
        if (typeof loadDashboardData ===
            'function') loadDashboardData();
    }, 500);
    setTimeout(function () {
        if (typeof loadDashboardData ===
            'function') loadDashboardData();
    }, 2000);
}

// ============ MODE MANAGER ======
function switchMode(mode) {
    state.currentMode = mode;

    // 1. Highlight active tab
    document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
    const ab = document.querySelector('.mode-btn[data-mode="' + mode + '"]');
    if (ab) ab.classList.add('active');

    // 2. Hide everything
    ['simple-mode-content','executive-mode-content','analyst-mode-content',
     'simple-scan-bar-top','splash-section','analyst-buttons-row'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });

    // 3. Mode logic
    if (mode === 'simple') {
        const hero    = document.getElementById('simple-scan-hero');
        const content = document.getElementById('simple-mode-content');
        const scanBar = document.getElementById('simple-scan-bar-top');
        const splash  = document.getElementById('splash-section');
        const scanned = content && content.dataset.scanned === 'true';
        if (scanned) {
            if (hero)    hero.style.display    = 'none';
            if (scanBar) { scanBar.style.display = 'block'; scanBar.style.opacity = '1'; }
            if (splash)  { splash.style.display  = 'block'; splash.style.opacity  = '1'; }
            if (content) { content.style.display = 'block'; content.style.opacity = '1'; }
            ['simple-health-banner','simple-kpi-section','simple-incident-list','simple-story-feed'].forEach(id => {
                const el = document.getElementById(id);
                if (el) { el.style.display = 'block'; el.style.opacity = '1'; }
            });
        } else {
            if (hero) hero.style.display = 'block';
        }
    }

    if (mode === 'executive') {
        const el = document.getElementById('executive-mode-content');
        if (el) el.style.display = 'block';
    }

    if (mode === 'analyst') {
        const el = document.getElementById('analyst-mode-content');
        if (el) el.style.display = 'block';

        // Show buttons row
        const btns = document.getElementById('analyst-buttons-row');
        if (btns) btns.style.display = 'flex';

        // Hide result sections if not yet scanned
        const resultsPanel = document.getElementById('analyst-scan-results-panel');
        const scanned = resultsPanel && resultsPanel.style.display === 'block';
        if (!scanned) {
            ['analyst-kpi-section','analyst-actions-section','analyst-simulator-section',
             'analyst-charts-section','analyst-detections-section','analyst-scan-results-panel'
            ].forEach(id => {
                const el = document.getElementById(id);
                if (el) { el.style.display = 'none'; el.style.opacity = '0'; }
            });
        }
    }

    // 4. Save & refresh
    localStorage.setItem('vnt-mode', mode);
    setTimeout(() => { if (typeof PollingEngine !== 'undefined') PollingEngine.forceUpdate(); }, 100);
}

function _finishSimpleScan() {
    var progress=document.getElementById('simple-scan-progress');
    var bar=document.getElementById('simple-scan-bar');
    var msg=document.getElementById('simple-scan-message');
    if(bar) bar.style.width='100%';
    if(msg){ msg.textContent='Scan complete!'; msg.style.color='#10b981'; }
    setTimeout(function(){
        if(progress) progress.style.display='none';
        if(bar) bar.style.width='0%';
        if(msg){ msg.textContent='Checking your network...'; msg.style.color=''; }
        var hero=document.getElementById('simple-scan-hero');
        if(hero) hero.style.display='none';
        ['splash-section','simple-scan-bar-top','simple-mode-content','simple-health-banner',
         'simple-kpi-section','simple-incident-list','simple-story-feed'].forEach(function(id,i){
            setTimeout(function(){
                var el=document.getElementById(id);
                if(!el) return;
                el.style.display='block'; el.style.opacity='0';
                el.style.transition='opacity 0.5s ease';
                setTimeout(function(){ el.style.opacity='1'; },50);
            },i*150);
        });
        var ls=document.getElementById('last-scan-time');
        if(ls) ls.textContent=(function(){var n=new Date();return n.getHours().toString().padStart(2,'0')+':'+n.getMinutes().toString().padStart(2,'0')+':'+n.getSeconds().toString().padStart(2,'0');})();
        var sc=document.getElementById('simple-mode-content');
        if(sc) sc.dataset.scanned='true';
        if(typeof loadDashboardData==='function') loadDashboardData();
        if(typeof loadSystemStats==='function') loadSystemStats();
    },600);
}

window.runSimpleRescan = async function() {
    var fill=document.getElementById('rescan-btn-fill');
    var label=document.getElementById('rescan-btn-label');
    var btn=document.getElementById('simple-rescan-btn');
    var msg=document.getElementById('scan-status-text');
    if(btn){ btn.disabled=true; btn.style.cursor='not-allowed'; }

    // Reset KPI cards with animation
    ['simple-incident-count','simple-health-pct','simple-top-threat','simple-last-threat-time'].forEach(function(id,i){
        var el=document.getElementById(id);
        if(!el) return;
        el.style.transition='opacity 0.3s ease, transform 0.3s ease';
        el.style.opacity='0';
        el.style.transform='translateY(-8px)';
        setTimeout(function(){
            el.textContent='—';
            el.style.color='#334155';
            el.style.opacity='0.4';
            el.style.transform='translateY(0)';
        }, 200 + i*60);
    });

    // Reset splash cards
    ['splash-active-hosts','splash-packets','splash-data','splash-uptime'].forEach(function(id){
        var el=document.getElementById(id);
        if(el){ el.style.opacity='0.3'; el.textContent='—'; }
    });
    ['simple-health-banner','simple-kpi-section','simple-incident-list','simple-story-feed'].forEach(function(id){
        var el=document.getElementById(id);
        if(el){ el.style.transition='opacity 0.4s ease'; el.style.opacity='0'; }
    });

    // Show progress bar below button
    var rbar=document.getElementById('rescan-bar');
    var rprog=document.getElementById('rescan-progress');
    if(rprog){ rprog.style.display='block'; }
    if(rbar){ rbar.style.width='0%'; rbar.style.transition='width 0.3s ease'; }

    var stages=[
        {pct:'15%', bpct:'15%', label:'Connecting...',delay:0},
        {pct:'35%', bpct:'35%', label:'Re-scanning devices...',delay:900},
        {pct:'60%', bpct:'60%', label:'Checking threats...',delay:2000},
        {pct:'80%', bpct:'80%', label:'Updating data...',delay:3200},
        {pct:'93%', bpct:'93%', label:'Almost done...',delay:4400}
    ];
    stages.forEach(function(s){
        setTimeout(function(){
            if(fill){ fill.style.transition='width 1s ease'; fill.style.width=s.pct; }
            if(rbar){ rbar.style.transition='width 1s ease'; rbar.style.width=s.bpct; }
            if(label) label.textContent=s.label;
            if(msg){ msg.style.opacity='0'; setTimeout(function(){ msg.textContent=s.label; msg.style.opacity='1'; },120); }
        },s.delay);
    });

    var done=false, scanStart=Date.now();
    setTimeout(function(){ if(!done){done=true;_finishRescan();} },9000);
    try {
        await fetch('/api/quick_scan');
        if(!done){ done=true; var rem=Math.max(0,5500-(Date.now()-scanStart)); setTimeout(_finishRescan,rem); }
    } catch(e){ if(!done){done=true;_finishRescan();} }

    function _finishRescan(){
        if(fill){ fill.style.transition='width 0.4s ease'; fill.style.width='100%';
            fill.style.background='linear-gradient(90deg,rgba(16,185,129,0.3),rgba(16,185,129,0.1))'; }
        if(label){ label.textContent='✓ Complete!'; }
        if(btn){ btn.style.borderColor='#10b981'; btn.style.color='#10b981'; }
        setTimeout(function(){
            if(fill){ fill.style.transition='width 0.5s ease'; fill.style.width='0%';
                fill.style.background='linear-gradient(90deg,rgba(0,212,255,0.15),rgba(167,139,250,0.15))'; }
            var rprog2=document.getElementById('rescan-progress');
            if(rprog2){ rprog2.style.display='none'; }
            if(label) label.textContent='🔄 RESCAN NETWORK';
            if(btn){ btn.disabled=false; btn.style.cursor='pointer'; btn.style.borderColor='#00d4ff'; btn.style.color='#00d4ff'; }
            if(msg){ msg.textContent='Ready'; msg.style.color='#00d4ff'; }
            var ls=document.getElementById('last-scan-time');
            if(ls) ls.textContent=(function(){var n=new Date();return n.getHours().toString().padStart(2,'0')+':'+n.getMinutes().toString().padStart(2,'0')+':'+n.getSeconds().toString().padStart(2,'0');})();
            // Restore KPI styles
            ['simple-incident-count','simple-health-pct','simple-top-threat','simple-last-threat-time'].forEach(function(id){
                var el=document.getElementById(id);
                if(el){ el.style.opacity='1'; el.style.color=''; el.style.transform=''; el.textContent='...'; }
            });
            // Restore splash cards
            ['splash-active-hosts','splash-packets','splash-data','splash-uptime'].forEach(function(id){
                var el=document.getElementById(id); if(el) el.style.opacity='1';
            });
            ['simple-health-banner','simple-kpi-section','simple-incident-list','simple-story-feed'].forEach(function(id,i){
                setTimeout(function(){
                    var el=document.getElementById(id);
                    if(el){ el.style.transition='opacity 0.5s ease'; el.style.opacity='1'; }
                },i*120);
            });
            if(typeof loadDashboardData==='function') loadDashboardData();
            if(typeof loadSystemStats==='function') loadSystemStats();
        },800);
    }
};

window.runAnalystFullScan = async function() {

        var btn = document.getElementById(
            'analyst-main-scan-btn');
        var progress = document.getElementById(
            'analyst-main-progress');
        var bar = document.getElementById(
            'analyst-main-bar');
        var statusEl = document.getElementById(
            'analyst-main-status');
        var statusText = document.getElementById(
            'analyst-scan-status-text');
        var lastScan = document.getElementById(
            'analyst-last-scan');

        // ── BUTTON STATE ──
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '⏳ Scanning...';
            btn.style.opacity = '0.6';
            btn.style.cursor = 'not-allowed';
        }
        if (statusText) {
            statusText.textContent = 'Scanning...';
            statusText.style.color = '#f59e0b';
        }

        // ── SHOW PROGRESS ──
        if (progress) {
            progress.style.display = 'block';
        }

        // ── STAGED MESSAGES ──
        var stages = [
            {
                msg: '🔍 Initializing scanner...',
                pct: '8%', delay: 0
            },
            {
                msg: '📡 Probing network interfaces...',
                pct: '22%', delay: 1000
            },
            {
                msg: '🔎 Resolving hostnames...',
                pct: '38%', delay: 2500
            },
            {
                msg: '⚡ Checking threat database...',
                pct: '55%', delay: 4000
            },
            {
                msg: '🛡️ Running MITRE ATT&CK checks...',
                pct: '72%', delay: 5500
            },
            {
                msg: '📊 Analyzing connections...',
                pct: '88%', delay: 7000
            },
            {
                msg: '✅ Compiling results...',
                pct: '95%', delay: 8500
            }
        ];

        stages.forEach(function (s) {
            setTimeout(function () {
                if (bar) bar.style.width = s.pct;
                if (statusEl) {
                    statusEl.style.opacity = '0';
                    setTimeout(function () {
                        statusEl.textContent = s.msg;
                        statusEl.style.opacity = '1';
                    }, 150);
                }
            }, s.delay);
        });

        // ── WAIT MIN 9 SECONDS ──
        var scanStart = Date.now();

        // Run both APIs simultaneously
        var done = false;
        var hardTimeout = setTimeout(
            function () {
                if (!done) {
                    done = true;
                    finishFullScan({ hosts: [] }, {});
                }
            }, 14000
        );

        try {
            // Run both scans at same time
            var results = await Promise.all([
                fetch('/api/scan')
                    .then(function (r) {
                        return r.json();
                    })
                    .catch(function () {
                        return { hosts: [] };
                    }),
                fetch('/api/quick_scan')
                    .then(function (r) {
                        return r.json();
                    })
                    .catch(function () {
                        return {};
                    })
            ]);

            if (!done) {
                done = true;
                clearTimeout(hardTimeout);
                var elapsed = Date.now() - scanStart;
                var remaining = Math.max(
                    0, 9000 - elapsed);
                setTimeout(function () {
                    finishFullScan(
                        results[0], results[1]);
                }, remaining);
            }
        } catch (err) {
            if (!done) {
                done = true;
                clearTimeout(hardTimeout);
                finishFullScan({ hosts: [] }, {});
            }
        }

        function finishFullScan(
            scanData, quickData) {

            // Complete bar
            if (bar) bar.style.width = '100%';
            if (statusEl) {
                statusEl.textContent =
                    '✅ Scan Complete';
                statusEl.style.color = '#10b981';
            }

            setTimeout(function () {

                // Hide progress
                if (progress) {
                    progress.style.display = 'none';
                }
                if (bar) bar.style.width = '0%';

                // Restore button
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '🔍 SCAN NETWORK';
                    btn.style.opacity = '1';
                    btn.style.cursor = 'pointer';
                }

                // Update status + time
                if (statusText) {
                    statusText.textContent = 'Live';
                    statusText.style.color = '#10b981';
                }
                if (lastScan) {
                    lastScan.textContent =
                        (function(){var n=new Date();return n.getHours().toString().padStart(2,'0')+':'+n.getMinutes().toString().padStart(2,'0')+':'+n.getSeconds().toString().padStart(2,'0');})();
                }

                // Update pills
                var hosts = [];
                if (scanData) {
                    if (Array.isArray(scanData.hosts)) {
                        hosts = scanData.hosts;
                    } else if (Array.isArray(
                        scanData.connections)) {
                        hosts = scanData.connections;
                    } else if (Array.isArray(
                        scanData.results)) {
                        hosts = scanData.results;
                    } else if (Array.isArray(
                        scanData.flagged)) {
                        hosts = scanData.flagged;
                    } else if (scanData.data &&
                        Array.isArray(scanData.data)) {
                        hosts = scanData.data;
                    }
                }

                console.log('Scan data received:',
                    JSON.stringify(scanData));
                console.log('Hosts found:',
                    hosts.length);
                var suspicious = hosts.filter(
                    function (h) {
                        return h.status === 'SUSPICIOUS' ||
                            h.status === 'suspicious' ||
                            h.status === 'MALICIOUS' ||
                            h.status === 'malicious' ||
                            h.threat_level === 'high' ||
                            h.is_suspicious === true;
                    }).length;
                var safe = hosts.length - suspicious;

                var hostsPill = document.getElementById(
                    'analyst-hosts-pill');
                var suspPill = document.getElementById(
                    'analyst-suspicious-pill');
                var safePill = document.getElementById(
                    'analyst-safe-pill');

                if (hostsPill)
                    hostsPill.textContent =
                        hosts.length || '—';
                if (suspPill)
                    suspPill.textContent =
                        suspicious || '0';
                if (safePill)
                    safePill.textContent =
                        safe || '0';

                // Show results panel
                var panel = document.getElementById(
                    'analyst-scan-results-panel');
                var grid = document.getElementById(
                    'analyst-results-grid');
                var summary = document.getElementById(
                    'analyst-scan-summary');

                if (panel) {
                    panel.style.display = 'block';
                    panel.style.opacity = '0';
                    panel.style.transition =
                        'opacity 0.6s ease';
                    setTimeout(function () {
                        panel.style.opacity = '1';
                    }, 50);
                }

                if (summary) {
                    summary.textContent =
                        hosts.length + ' connections · ' +
                        suspicious + ' flagged';
                }

                // Render connection cards
                if (grid && hosts.length > 0) {
                    grid.innerHTML = '';
                    hosts.forEach(function (host, i) {
                        var isSusp =
                            host.status === 'SUSPICIOUS' ||
                            host.status === 'suspicious' ||
                            host.status === 'MALICIOUS' ||
                            host.status === 'malicious' ||
                            host.threat_level === 'high' ||
                            host.is_suspicious === true;
                        var color = isSusp
                            ? '#ef4444' : '#10b981';
                        var bg = isSusp
                            ? 'rgba(239,68,68,0.08)'
                            : 'rgba(16,185,129,0.08)';
                        var border = isSusp
                            ? 'rgba(239,68,68,0.25)'
                            : 'rgba(16,185,129,0.25)';

                        var card = document.createElement(
                            'div');
                        card.style.cssText =
                            'background:' + bg + ';' +
                            'border:1px solid ' + border + ';' +
                            'border-radius:10px;' +
                            'padding:12px 14px;' +
                            'opacity:0;' +
                            'transform:translateY(10px);' +
                            'transition:all 0.4s ease;';

                        card.innerHTML =
                            '<div style="display:flex;' +
                            'justify-content:space-between;' +
                            'align-items:center;' +
                            'margin-bottom:6px">' +
                            '<span style="font-family:' +
                            'Space Grotesk,sans-serif;' +
                            'font-size:13px;font-weight:700;' +
                            'color:#f0f4f8">' +
                            (host.ip || host.host ||
                                host.address || host.remote_ip ||
                                host.raddr || '—') +
                            '</span>' +
                            '<span style="font-size:11px;' +
                            'font-weight:700;color:' +
                            color + ';padding:2px 8px;' +
                            'background:' + bg + ';' +
                            'border:1px solid ' + border +
                            ';border-radius:4px">' +
                            (isSusp ? '⚠ SUSPICIOUS'
                                : '✓ SAFE') +
                            '</span></div>' +
                            '<div style="font-family:' +
                            'Space Grotesk,sans-serif;' +
                            'font-size:11px;color:#475569">' +
                            (host.hostname || host.location ||
                                host.country || host.org ||
                                host.isp || '') +
                            '</div>';

                        grid.appendChild(card);

                        // Staggered reveal
                        setTimeout(function () {
                            card.style.opacity = '1';
                            card.style.transform =
                                'translateY(0px)';
                        }, 100 + (i * 80));
                    });
                }

                // Reveal sections one by one
                var revealOrder = [
                    {
                        id: 'analyst-scan-results-panel',
                        delay: 0
                    },
                    {
                        id: 'analyst-kpi-section',
                        delay: 600
                    },
                    {
                        id: 'analyst-actions-section',
                        delay: 1000
                    },
                    {
                        id: 'analyst-charts-section',
                        delay: 1400
                    },
                    {
                        id: 'analyst-detections-section',
                        delay: 1800
                    },
                    {
                        id: 'analyst-simulator-section',
                        delay: 2200
                    }
                ];

                revealOrder.forEach(function (item) {
                    setTimeout(function () {
                        var el = document.getElementById(
                            item.id);
                        if (el) {
                            // Preserve original display type
                            el.style.removeProperty('display');
                            el.style.display = '';
                            if (el.style.display === '' ||
                                el.style.display === 'none') {
                                if (item.id === 'analyst-kpi-section') {
                                    el.style.display = 'grid';
                                } else {
                                    el.style.display = 'block';
                                }
                            }
                            el.style.opacity = '0';
                            el.style.transition =
                                'opacity 600ms ease, ' +
                                'transform 600ms ease';
                            el.style.transform =
                                'translateY(20px)';
                            setTimeout(function () {
                                el.style.opacity = '1';
                                el.style.transform =
                                    'translateY(0px)';
                            }, 50);
                        }
                    }, item.delay);
                });

                // Refresh all dashboard data
                if (typeof loadDashboardData
                    === 'function')
                    loadDashboardData();

            }, 500);
        }
    }


window.toggleAttackPanel = function() {
        var panel = document.getElementById(
            'attack-sim-panel');
        var btn = document.getElementById(
            'attack-sim-btn');
        if (!panel) return;

        var isOpen =
            panel.style.display === 'block';

        if (isOpen) {
            panel.style.opacity = '0';
            panel.style.transition =
                'opacity 0.3s ease';
            setTimeout(function () {
                panel.style.display = 'none';
            }, 300);
            if (btn) btn.style.boxShadow =
                '0 0 28px rgba(167,139,250,0.2)';
        } else {
            panel.style.display = 'block';
            panel.style.opacity = '0';
            panel.style.transition =
                'opacity 0.3s ease';
            setTimeout(function () {
                panel.style.opacity = '1';
            }, 50);
            if (btn) btn.style.boxShadow =
                '0 0 40px rgba(167,139,250,0.5)';
        }
    }


window.runSimpleScan = async function() {
    var progress=document.getElementById('simple-scan-progress');
    var bar=document.getElementById('simple-scan-bar');
    var msg=document.getElementById('simple-scan-message');
    if(progress) progress.style.display='block';
    if(bar) bar.style.width='0%';
    var stages=[
        {msg:'Connecting to network...',pct:'15%',delay:0},
        {msg:'Discovering devices...',pct:'35%',delay:900},
        {msg:'Scanning for threats...',pct:'58%',delay:2000},
        {msg:'Checking threat database...',pct:'78%',delay:3200},
        {msg:'Almost done...',pct:'93%',delay:4400}
    ];
    stages.forEach(function(s){
        setTimeout(function(){
            if(bar){bar.style.transition='width 1s ease';bar.style.width=s.pct;}
            if(msg){msg.style.opacity='0';setTimeout(function(){msg.textContent=s.msg;msg.style.opacity='1';},150);}
        },s.delay);
    });
    var done=false,scanStart=Date.now();
    setTimeout(function(){if(!done){done=true;_finishSimpleScan();}},9000);
    try{
        await fetch('/api/quick_scan');
        if(!done){done=true;var rem=Math.max(0,5500-(Date.now()-scanStart));setTimeout(_finishSimpleScan,rem);}
    }catch(e){if(!done){done=true;_finishSimpleScan();}}
};

window.runSimpleRescan = async function() {
    var fill=document.getElementById('rescan-btn-fill');
    var label=document.getElementById('rescan-btn-label');
    var btn=document.getElementById('simple-rescan-btn');
    var msg=document.getElementById('scan-status-text');
    if(btn){btn.disabled=true;btn.style.cursor='not-allowed';}
    ['simple-incident-count','simple-health-pct','simple-top-threat','simple-last-threat-time'].forEach(function(id,i){
        var el=document.getElementById(id);
        if(!el)return;
        el.style.transition='opacity 0.3s ease,transform 0.3s ease';
        el.style.opacity='0';el.style.transform='translateY(-8px)';
        setTimeout(function(){el.textContent='—';el.style.color='#334155';el.style.opacity='0.4';el.style.transform='translateY(0)';},200+i*60);
    });
    ['splash-active-hosts','splash-packets','splash-data','splash-uptime'].forEach(function(id){
        var el=document.getElementById(id);if(el){el.style.opacity='0.3';el.textContent='—';}
    });
    ['simple-health-banner','simple-kpi-section','simple-incident-list','simple-story-feed'].forEach(function(id){
        var el=document.getElementById(id);if(el){el.style.transition='opacity 0.4s ease';el.style.opacity='0';}
    });
    var rbar=document.getElementById('rescan-bar');
    var rprog=document.getElementById('rescan-progress');
    if(rprog)rprog.style.display='block';
    if(rbar){rbar.style.width='0%';rbar.style.transition='width 0.3s ease';}
    var stages=[
        {pct:'15%',label:'Connecting...',delay:0},
        {pct:'35%',label:'Re-scanning devices...',delay:900},
        {pct:'60%',label:'Checking threats...',delay:2000},
        {pct:'80%',label:'Updating data...',delay:3200},
        {pct:'93%',label:'Almost done...',delay:4400}
    ];
    stages.forEach(function(s){
        setTimeout(function(){
            if(fill){fill.style.transition='width 1s ease';fill.style.width=s.pct;}
            if(rbar){rbar.style.transition='width 1s ease';rbar.style.width=s.pct;}
            if(label)label.textContent=s.label;
            if(msg){msg.style.opacity='0';setTimeout(function(){msg.textContent=s.label;msg.style.opacity='1';},120);}
        },s.delay);
    });
    var done=false,scanStart=Date.now();
    setTimeout(function(){if(!done){done=true;_finishRescan();}},9000);
    try{
        await fetch('/api/quick_scan');
        if(!done){done=true;var rem=Math.max(0,5500-(Date.now()-scanStart));setTimeout(_finishRescan,rem);}
    }catch(e){if(!done){done=true;_finishRescan();}}
    function _finishRescan(){
        if(fill){fill.style.transition='width 0.4s ease';fill.style.width='100%';fill.style.background='linear-gradient(90deg,rgba(16,185,129,0.3),rgba(16,185,129,0.1))';}
        if(label){label.textContent='✓ Complete!';}
        if(btn){btn.style.borderColor='#10b981';btn.style.color='#10b981';}
        setTimeout(function(){
            if(fill){fill.style.transition='width 0.5s ease';fill.style.width='0%';fill.style.background='linear-gradient(90deg,rgba(0,212,255,0.15),rgba(167,139,250,0.15))';}
            var rprog2=document.getElementById('rescan-progress');if(rprog2)rprog2.style.display='none';
            if(label)label.textContent='🔄 RESCAN NETWORK';
            if(btn){btn.disabled=false;btn.style.cursor='pointer';btn.style.borderColor='#00d4ff';btn.style.color='#00d4ff';}
            if(msg){msg.textContent='Ready';msg.style.color='#00d4ff';}
            var ls=document.getElementById('last-scan-time');if(ls)ls.textContent=(function(){var n=new Date();return n.getHours().toString().padStart(2,'0')+':'+n.getMinutes().toString().padStart(2,'0')+':'+n.getSeconds().toString().padStart(2,'0');})();
            ['simple-incident-count','simple-health-pct','simple-top-threat','simple-last-threat-time'].forEach(function(id){
                var el=document.getElementById(id);if(el){el.style.opacity='1';el.style.color='';el.style.transform='';el.textContent='...';}
            });
            ['splash-active-hosts','splash-packets','splash-data','splash-uptime'].forEach(function(id){
                var el=document.getElementById(id);if(el)el.style.opacity='1';
            });
            ['simple-health-banner','simple-kpi-section','simple-incident-list','simple-story-feed'].forEach(function(id,i){
                setTimeout(function(){var el=document.getElementById(id);if(el){el.style.transition='opacity 0.5s ease';el.style.opacity='1';}},i*120);
            });
            if(typeof loadDashboardData==='function')loadDashboardData();
            if(typeof loadSystemStats==='function')loadSystemStats();
        },800);
    }
};

window.showAttackDebrief = function(d) {

        var resultEl = document.getElementById(
            'attack-float-result');
        if (!resultEl) return;

        // Grade color
        var gradeColor = '#10b981';
        if (d.detection_grade === 'Good')
            gradeColor = '#00d4ff';
        if (d.detection_grade === 'Fair')
            gradeColor = '#f59e0b';
        if (d.detection_grade === 'Poor')
            gradeColor = '#ef4444';

        // Protection steps HTML
        var stepsHtml = '';
        if (d.protection_steps &&
            d.protection_steps.length) {
            stepsHtml = d.protection_steps
                .map(function (s) {
                    return '<div style="' +
                        'display:flex;gap:8px;' +
                        'align-items:flex-start;' +
                        'margin-bottom:4px">' +
                        '<span style="color:#10b981">✓' +
                        '</span>' +
                        '<span style="color:#94a3b8">' +
                        s + '</span></div>';
                }).join('');
        }

        resultEl.style.display = 'block';
        resultEl.style.textAlign = 'left';
        resultEl.style.background =
            'rgba(10,15,30,0.8)';
        resultEl.style.border =
            '1px solid rgba(255,255,255,0.08)';
        resultEl.style.borderRadius = '12px';
        resultEl.style.padding = '16px';

        resultEl.innerHTML =

            // Header
            '<div style="display:flex;' +
            'justify-content:space-between;' +
            'align-items:center;' +
            'margin-bottom:14px">' +
            '<div style="font-family:Syne,' +
            'sans-serif;font-size:14px;' +
            'font-weight:700;color:#f0f4f8">' +
            '📋 ' + (d.attack_name || 'Attack') +
            ' — DEBRIEF</div>' +
            '<div style="font-family:Space Grotesk,' +
            'sans-serif;font-size:13px;' +
            'font-weight:700;color:' +
            gradeColor + ';padding:4px 10px;' +
            'border:1px solid ' + gradeColor +
            ';border-radius:6px">' +
            (d.detection_grade_icon || '✅') +
            ' ' + (d.detection_grade || 'Good') +
            '</div></div>' +

            // Stats row
            '<div style="display:grid;' +
            'grid-template-columns:' +
            'repeat(3,1fr);gap:8px;' +
            'margin-bottom:14px">' +

            '<div style="text-align:center;' +
            'padding:8px;' +
            'background:rgba(239,68,68,0.08);' +
            'border:1px solid ' +
            'rgba(239,68,68,0.2);' +
            'border-radius:8px">' +
            '<div style="font-size:18px;' +
            'font-weight:700;color:#ef4444">' +
            (d.high_alerts || 0) + '</div>' +
            '<div style="font-size:10px;' +
            'color:#475569">HIGH</div></div>' +

            '<div style="text-align:center;' +
            'padding:8px;' +
            'background:rgba(245,158,11,0.08);' +
            'border:1px solid ' +
            'rgba(245,158,11,0.2);' +
            'border-radius:8px">' +
            '<div style="font-size:18px;' +
            'font-weight:700;color:#f59e0b">' +
            (d.medium_alerts || 0) + '</div>' +
            '<div style="font-size:10px;' +
            'color:#475569">MEDIUM</div></div>' +

            '<div style="text-align:center;' +
            'padding:8px;' +
            'background:rgba(0,212,255,0.08);' +
            'border:1px solid ' +
            'rgba(0,212,255,0.2);' +
            'border-radius:8px">' +
            '<div style="font-size:18px;' +
            'font-weight:700;color:#00d4ff">' +
            (d.first_detection_seconds || 0) +
            's</div>' +
            '<div style="font-size:10px;' +
            'color:#475569">DETECTED</div>' +
            '</div></div>' +

            // What happened
            '<div style="margin-bottom:12px">' +
            '<div style="font-family:Syne,' +
            'sans-serif;font-size:11px;' +
            'font-weight:700;color:#475569;' +
            'letter-spacing:0.08em;' +
            'margin-bottom:6px">' +
            'WHAT HAPPENED</div>' +
            '<div style="font-family:Space Grotesk,' +
            'sans-serif;font-size:12px;' +
            'color:#94a3b8;line-height:1.5">' +
            (d.what_happened || '') +
            '</div></div>' +

            // Real world
            '<div style="margin-bottom:12px">' +
            '<div style="font-family:Syne,' +
            'sans-serif;font-size:11px;' +
            'font-weight:700;color:#475569;' +
            'letter-spacing:0.08em;' +
            'margin-bottom:6px">' +
            'REAL WORLD EXAMPLE</div>' +
            '<div style="font-family:Space Grotesk,' +
            'sans-serif;font-size:12px;' +
            'color:#94a3b8;line-height:1.5">' +
            (d.real_world_example || '') +
            '</div></div>' +

            // Protection steps
            '<div>' +
            '<div style="font-family:Syne,' +
            'sans-serif;font-size:11px;' +
            'font-weight:700;color:#475569;' +
            'letter-spacing:0.08em;' +
            'margin-bottom:6px">' +
            'PROTECTION STEPS</div>' +
            stepsHtml +
            '</div>' +

            // Scan button
            '<div style="margin-top:14px;' +
            'text-align:center">' +
            '<button onclick="' +
            'runAnalystFullScan()" style="' +
            'padding:10px 24px;' +
            'background:rgba(0,212,255,0.12);' +
            'border:1px solid #00d4ff;' +
            'border-radius:8px;color:#00d4ff;' +
            'font-family:Syne,sans-serif;' +
            'font-size:12px;font-weight:700;' +
            'cursor:pointer;' +
            'letter-spacing:0.06em">' +
            '🔍 SCAN NOW TO SEE THREATS' +
            '</button></div>';
    }

window.runFloatingAttack = function(type) {
        var progress = document.getElementById(
            'attack-float-progress');
        var bar = document.getElementById(
            'attack-float-bar');
        var statusEl = document.getElementById(
            'attack-float-status');
        var resultEl = document.getElementById(
            'attack-float-result');

        if (resultEl) {
            resultEl.style.display = 'none';
            resultEl.innerHTML = '';
        }
        if (progress) {
            progress.style.display = 'block';
        }
        if (bar) bar.style.width = '0%';
        if (statusEl) {
            statusEl.textContent =
                '⚠️ Starting simulation...';
        }

        document.querySelectorAll(
            '.attack-float-btn')
            .forEach(function (b) {
                b.disabled = true;
                b.style.opacity = '0.6';
            });

        // Correct attack type mapping
        var attackTypeMap = {
            'server_flood': 'dos',
            'network_spy': 'portscan',
            'brute_force': 'bruteforce',
            'dns_tunnel': 'suspdns'
        };

        var mappedType =
            attackTypeMap[type] || type;

        fetch('/api/simulate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                attack_type: mappedType
            })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.error) {
                    console.error('Attack error:',
                        data.error);
                }
                var simId = data.simulation_id;

                // Poll status every 3 seconds
                var pollInterval = setInterval(
                    function () {
                        fetch('/api/simulate/status')
                            .then(function (r) {
                                return r.json();
                            })
                            .then(function (status) {
                                if (status.active) {
                                    var pct = Math.round(
                                        (status.elapsed_seconds
                                            / 60) * 100);
                                    if (bar) {
                                        bar.style.width =
                                            pct + '%';
                                    }
                                    if (statusEl) {
                                        statusEl.textContent =
                                            '🔥 ' +
                                            status.attack_name +
                                            ' running... ' +
                                            status.alerts_generated +
                                            ' alerts generated';
                                    }
                                } else {
                                    // Simulation complete
                                    clearInterval(pollInterval);
                                    finishAttack(simId);
                                }
                            })
                            .catch(function () {
                                clearInterval(pollInterval);
                                finishAttack(simId);
                            });
                    }, 3000
                );

                // Hard stop after 70 seconds
                setTimeout(function () {
                    clearInterval(pollInterval);
                    finishAttack(simId);
                }, 70000);

            })
            .catch(function (err) {
                console.error('Simulate error:',
                    err);
                finishAttack(null);
            });

        function finishAttack(simId) {
            if (bar) bar.style.width = '100%';

            setTimeout(function () {
                if (progress) {
                    progress.style.display = 'none';
                }
                if (bar) bar.style.width = '0%';

                // Re-enable buttons
                document.querySelectorAll(
                    '.attack-float-btn')
                    .forEach(function (b) {
                        b.disabled = false;
                        b.style.opacity = '1';
                    });

                // Fetch debrief if simId exists
                if (simId) {
                    fetch('/api/debrief/' + simId)
                        .then(function (r) {
                            return r.json();
                        })
                        .then(function (d) {
                            showAttackDebrief(d);
                        })
                        .catch(function () {
                            showBasicResult();
                        });
                } else {
                    showBasicResult();
                }

                if (typeof loadDashboardData
                    === 'function')
                    loadDashboardData();

            }, 500);
        }

        function showBasicResult() {
            var attackNames = {
                server_flood: 'Server Flood',
                network_spy: 'Network Spy',
                brute_force: 'Password Guesser',
                dns_tunnel: 'Hidden Signals'
            };
            var resultEl = document.getElementById(
                'attack-float-result');
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.innerHTML =
                    '✅ ' +
                    (attackNames[type] || type) +
                    ' complete!<br>' +
                    '<span style="color:#94a3b8">' +
                    'Click SCAN NETWORK to see ' +
                    'detected threats.' +
                    '</span>';
            }
        }
    }


// ── CLOCK ──────────────────────────────────────────
function startClock() {
        function updateClock() {
            const now = new Date();
            const h = String(now.getHours())
                .padStart(2, '0');
            const m = String(now.getMinutes())
                .padStart(2, '0');
            const s = String(now.getSeconds())
                .padStart(2, '0');
            const time = `${h}:${m}:${s}`;

            const el = document.getElementById(
                'nav-clock'
            );
            if (el) el.textContent = time;
        }

        // Update immediately then every second
        updateClock();
        setInterval(updateClock, 1000);
    }

// ── INIT ON DOM READY ──────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
        startClock();

        // Simple mode initial state
        var hero = document.getElementById(
            'simple-scan-hero'
        );
        var scanBar = document.getElementById(
            'simple-scan-bar-top'
        );
        var content = document.getElementById(
            'simple-mode-content'
        );
        var splash = document.getElementById(
            'splash-section'
        );

        // On load: show ONLY hero button
        if (hero) hero.style.display = 'block';
        if (scanBar) scanBar.style.display = 'none';
        if (content) {
            content.style.display = 'none';
            content.style.opacity = '0';
        }
        if (splash) splash.style.display = 'none';

        // Hide simple KPI cards and content on load
        var simpleCards = document.getElementById(
            'simple-kpi-section') ||
            document.querySelector(
                '.simple-kpi-cards');
        if (simpleCards) {
            simpleCards.style.display = 'none';
        }
        var smc = document.getElementById(
            'simple-mode-content');
        if (smc) smc.style.display = 'none';

        // Hide all analyst sections
        // on page load
        var analystSections = [
            'analyst-kpi-section',
            'analyst-actions-section',
            'analyst-simulator-section',
            'analyst-charts-section',
            'analyst-detections-section',
            'analyst-scan-results-panel'
        ];
        analystSections.forEach(function (id) {
            var el = document.getElementById(id);
            if (el) {
                el.style.display = 'none';
                el.style.opacity = '0';
            }
        });

        // Initialize KPI cards with 0
        ['kpi-flows', 'kpi-high', 'kpi-medium',
            'kpi-low', 'kpi-risk', 'kpi-today']
            .forEach(id => {
                const el = document.getElementById(id);
                if (el && !el.textContent.trim()) {
                    el.textContent = '0';
                }
            });

        loadSystemStats();
        loadDashboardData();
    });

    // Also refresh every 5 seconds
    setInterval(loadDashboardData, 5000);
    setInterval(loadSystemStats, 5000);


// ── POLLING ENGINE ─────────────────────────────────
const PollingEngine = {
        timer: null,

        async run() {
            if (!state.tourActive) {
                await Promise.all([
                    KPIModule.update(),
                    ChartModule.update(),
                    HeatmapModule.update(),
                    TableModule.update(),
                    AlertModule.update(),
                    StoryModule.update(),
                    // StoryModule.updateIncidents(),
                    DeviceRiskModule.update()
                ]);
            }

            // Clock
            // clock handled by startClock() setInterval

            this.timer = setTimeout(() => this.run(), CONFIG.POLL_INTERVAL_MS);
        },

        forceUpdate() {
            clearTimeout(this.timer);
            this.run();
        }
    };

// ── DASHBOARD INIT ─────────────────────────────────
// Wait for fonts before any rendering
    document.fonts.ready.then(() => {
        initDashboard();
    });

    // Fallback if fonts take too long
    setTimeout(() => {
        if (!window.dashboardInitialized) {
            initDashboard();
        }
    }, 3000);

    function initDashboard() {
        if (window.dashboardInitialized) return;
        window.dashboardInitialized = true;

        ChartModule.init();
        TableModule.init();
        DrawerModule.init();
        SimulatorModule.init();
        ReportModule.init();

        // Initialize mode
        const savedMode = localStorage.getItem('vnt-mode') || 'simple';
        switchMode(savedMode);
        TourModule.init();
        ContactModule.init();

        // Start Splash Call removed to rely on global polling update logic

        // Start engine
        PollingEngine.run();
    }

// ── RESET DATABASE ──────────────────────────────
function resetDatabase() {
        const modal = document.getElementById(
            'reset-modal'
        );
        modal.style.display = 'flex';
    }

    function closeReset() {
        const modal = document.getElementById(
            'reset-modal'
        );
        modal.style.display = 'none';
    }

    async function confirmReset() {
        const btn = document.getElementById(
            'confirm-reset-btn'
        );
        btn.textContent = 'Resetting...';
        btn.disabled = true;

        try {
            const res = await fetch('/api/reset', {
                method: 'POST'
            });
            const data = await res.json();

            if (data.status === 'success') {
                document.getElementById(
                    'reset-modal-content'
                ).innerHTML = `
        <div style="
          font-size:48px;
          color:#00d4aa;
          margin-bottom:16px">✓</div>
        <div style="
          font-family:'Syne',sans-serif;
          font-size:18px;font-weight:700;
          color:#00d4aa;margin-bottom:8px">
          Database Cleared
        </div>
        <div style="
          font-family:'Space Grotesk',
            sans-serif;
          font-size:14px;color:#64748b">
          Fresh data generating now...
        </div>`;

                setTimeout(() => {
                    closeReset();
                    location.reload();
                }, 2000);
            }

        } catch (err) {
            console.error('Reset failed:', err);
            btn.textContent = 'Reset Now';
            btn.disabled = false;
        }
    }

    // Hover effect for reset button
    const resetBtn = document.getElementById(
        'reset-btn'
    );
window.resetDatabase = resetDatabase;
window.closeReset = closeReset;
window.confirmReset = confirmReset;

// ══════════════════════════════════════════════════
// IP LOOKUP — Real data from ip-api.com + local alerts
// ══════════════════════════════════════════════════

window.lookupIP = function() {
    var input = document.getElementById('ip-lookup-input');
    if (!input) return;
    var ip = input.value.trim();
    if (!ip) {
        input.style.borderColor = 'rgba(255,77,109,0.5)';
        setTimeout(function(){ input.style.borderColor = 'rgba(255,255,255,0.1)'; }, 1000);
        return;
    }
    window.investigateIP(ip);
    input.value = '';
};

window.investigateIP = async function(ip) {
    var panel    = document.getElementById('ip-lookup-result');
    var loading  = document.getElementById('ip-lookup-loading');
    var content  = document.getElementById('ip-lookup-content');

    // Show panel in loading state
    if (panel)   { panel.style.display   = 'block'; }
    if (loading) { loading.style.display = 'block'; }
    if (content) { content.style.display = 'none'; }

    // Scroll input into view
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    // 1. Fetch real geo/ISP data from ip-api.com
    var geo = {};
    try {
        var geoRes = await fetch('http://ip-api.com/json/' + ip + '?fields=status,country,regionName,city,isp,org,as,query,proxy,hosting,mobile');
        geo = await geoRes.json();
    } catch(e) {
        geo = { status: 'fail', country: 'Unknown', city: 'Unknown', isp: 'Unknown' };
    }

    // 2. Cross-reference local alerts for threat data
    var alerts = [];
    try {
        var alertRes = await fetch('/api/alerts?limit=200');
        var alertData = await alertRes.json();
        alerts = Array.isArray(alertData) ? alertData : (alertData.alerts || []);
    } catch(e) {}

    var matches = alerts.filter(function(a){ return a.src_ip === ip || a.dst_ip === ip; });
    var timeSeen = matches.length;
    var maxScore = 0;
    var lastAttack = 'None detected';
    var lastMitre = '';

    matches.forEach(function(a) {
        var s = Number(a.score || a.risk_score || 0);
        if (s > maxScore) maxScore = s;
        if (a.attack_name) lastAttack = a.attack_name;
        if (a.mitre_technique) lastMitre = a.mitre_technique;
    });

    // 3. Determine risk level
    var riskLevel, riskColor, badgeBg;
    if (timeSeen > 0 || maxScore > 70) {
        riskLevel = 'HIGH RISK';  riskColor = '#ef4444';  badgeBg = 'rgba(239,68,68,0.15)';
    } else if (maxScore > 40 || geo.proxy || geo.hosting) {
        riskLevel = 'SUSPICIOUS'; riskColor = '#f59e0b';  badgeBg = 'rgba(245,158,11,0.15)';
    } else {
        riskLevel = 'CLEAN';      riskColor = '#10b981';  badgeBg = 'rgba(16,185,129,0.15)';
    }

    // Flag emoji
    var countryFlag = '';
    if (geo.country) {
        // Convert country name to flag if we can guess the code from common ones
        var flagMap = {'United States':'🇺🇸','Russia':'🇷🇺','China':'🇨🇳','Germany':'🇩🇪',
            'United Kingdom':'🇬🇧','France':'🇫🇷','Netherlands':'🇳🇱','Ukraine':'🇺🇦',
            'India':'🇮🇳','Brazil':'🇧🇷','Canada':'🇨🇦','Japan':'🇯🇵','South Korea':'🇰🇷',
            'Singapore':'🇸🇬','Australia':'🇦🇺','Romania':'🇷🇴','Iran':'🇮🇷','North Korea':'🇰🇵'};
        countryFlag = flagMap[geo.country] || '🌐';
    }

    // 4. Render result
    if (loading) loading.style.display = 'none';
    if (content) content.style.display = 'block';

    var el = function(id){ return document.getElementById(id); };

    if (el('ip-result-addr'))   el('ip-result-addr').textContent  = geo.query || ip;
    if (el('ip-result-badge')) {
        el('ip-result-badge').textContent        = riskLevel;
        el('ip-result-badge').style.color        = riskColor;
        el('ip-result-badge').style.background   = badgeBg;
        el('ip-result-badge').style.border       = '1px solid ' + riskColor;
    }
    if (el('ip-result-country')) el('ip-result-country').textContent = countryFlag + ' ' + (geo.country || 'Unknown');
    if (el('ip-result-city'))    el('ip-result-city').textContent    = (geo.city || '') + (geo.regionName ? ', ' + geo.regionName : '');
    if (el('ip-result-isp'))     el('ip-result-isp').textContent     = geo.org || geo.isp || 'Unknown';

    if (el('ip-result-score')) {
        el('ip-result-score').textContent  = maxScore > 0 ? maxScore + '/100' : (timeSeen > 0 ? '?' : '0/100');
        el('ip-result-score').style.color  = riskColor;
    }
    if (el('ip-result-seen'))  el('ip-result-seen').textContent  = timeSeen > 0 ? timeSeen + 'x' : '0x';
    if (el('ip-result-mitre')) el('ip-result-mitre').textContent = lastAttack + (lastMitre ? ' — ' + lastMitre : '');

    // Wire up Add to Blocklist button
    var blockBtn = document.getElementById('ip-block-btn');
    if (blockBtn) {
        blockBtn.onclick = function() { _quickBlockIP(ip, riskLevel); };
    }

    // Change panel border color by risk
    if (panel) panel.style.borderColor = riskColor.replace(')', ',0.3)').replace('rgb', 'rgba');
};

function _quickBlockIP(ip, riskLevel) {
    var reason = riskLevel === 'HIGH RISK' ? 'Malicious' : riskLevel === 'SUSPICIOUS' ? 'Suspicious' : 'Manual Block';
    fetch('/api/blocklist/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, reason: reason })
    }).then(function() {
        var btn = document.getElementById('ip-block-btn');
        if (btn) { btn.textContent = '✓ BLOCKED'; btn.style.color = '#10b981'; btn.style.borderColor = 'rgba(16,185,129,0.3)'; btn.disabled = true; }
        if (typeof loadBlocklist === 'function') loadBlocklist();
    }).catch(function(){});
}


// ══════════════════════════════════════════════════
// IP BLOCKLIST — Enhanced with counts, auto-suggest, confirm
// ══════════════════════════════════════════════════

window.addToBlocklist = async function() {
    var ip = document.getElementById('block-ip').value.trim();
    var reason = document.getElementById('block-reason').value;
    if (!ip) {
        document.getElementById('block-ip').style.borderColor = 'rgba(255,77,109,0.5)';
        setTimeout(function(){ document.getElementById('block-ip').style.borderColor = 'rgba(255,255,255,0.1)'; }, 1000);
        return;
    }
    try {
        await fetch('/api/blocklist/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip, reason: reason })
        });
        document.getElementById('block-ip').value = '';
        loadBlocklist();
    } catch(err) { console.error('Blocklist error:', err); }
};

var _blockRemoveTarget = null;

window.removeFromBlocklist = function(ip) {
    _blockRemoveTarget = ip;
    var modal = document.getElementById('block-confirm-modal');
    var label = document.getElementById('block-confirm-ip');
    var btn   = document.getElementById('block-confirm-btn');
    if (label) label.textContent = ip;
    if (btn)   btn.onclick = _confirmBlockRemove;
    if (modal) modal.style.display = 'flex';
};

async function _confirmBlockRemove() {
    if (!_blockRemoveTarget) return;
    var modal = document.getElementById('block-confirm-modal');
    if (modal) modal.style.display = 'none';
    try {
        await fetch('/api/blocklist/remove', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: _blockRemoveTarget })
        });
        _blockRemoveTarget = null;
        loadBlocklist();
    } catch(err) { console.error('Remove error:', err); }
}

window.cancelBlockRemove = function() {
    _blockRemoveTarget = null;
    var modal = document.getElementById('block-confirm-modal');
    if (modal) modal.style.display = 'none';
};

window.loadBlocklist = async function() {
    try {
        var res  = await fetch('/api/blocklist');
        var data = await res.json();

        // Also get alert counts per IP
        var alertCounts = {};
        try {
            var ar = await fetch('/api/alerts?limit=200');
            var alerts = await ar.json();
            var arr = Array.isArray(alerts) ? alerts : (alerts.alerts || []);
            arr.forEach(function(a) {
                if (a.src_ip) alertCounts[a.src_ip] = (alertCounts[a.src_ip] || 0) + 1;
            });
        } catch(e) {}

        var container = document.getElementById('blocklist-container');
        if (!container) return;

        if (!data || data.length === 0) {
            container.innerHTML = '<div style="font-family:\'Space Grotesk\',sans-serif;font-size:12px;color:#334155;text-align:center;padding:14px;">No IPs blocked yet</div>';
            _renderBlocklistSuggestions(alertCounts, []);
            return;
        }

        var reasonColors = {
            'Malicious':    { border: 'rgba(239,68,68,0.25)',  bg: 'rgba(239,68,68,0.06)',  color: '#ef4444' },
            'Suspicious':   { border: 'rgba(245,158,11,0.25)', bg: 'rgba(245,158,11,0.06)', color: '#f59e0b' },
            'Brute Force':  { border: 'rgba(245,158,11,0.25)', bg: 'rgba(245,158,11,0.06)', color: '#f59e0b' },
            'Port Scan':    { border: 'rgba(167,139,250,0.25)',bg: 'rgba(167,139,250,0.06)',color: '#a78bfa' },
            'Manual Block': { border: 'rgba(255,255,255,0.12)',bg: 'rgba(255,255,255,0.03)',color: '#64748b' }
        };

        var blockedIPs = data.map(function(d){ return d.ip; });

        container.innerHTML = data.map(function(item) {
            var c = reasonColors[item.reason] || reasonColors['Manual Block'];
            var seen = alertCounts[item.ip] || 0;
            return '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:' + c.bg + ';border:1px solid ' + c.border + ';border-radius:8px;margin-bottom:6px;">' +
                '<div>' +
                    '<div style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:' + c.color + ';">' + item.ip + '</div>' +
                    '<div style="font-family:\'Space Grotesk\',sans-serif;font-size:10px;color:#475569;margin-top:2px;">' +
                        item.reason +
                        (seen > 0 ? ' · <span style="color:#a78bfa">seen ' + seen + 'x in alerts</span>' : '') +
                        ' · ' + (item.blocked_at || '') +
                    '</div>' +
                '</div>' +
                '<button onclick="removeFromBlocklist(\'' + item.ip + '\')" style="background:none;border:1px solid rgba(255,255,255,0.08);border-radius:6px;color:#475569;padding:3px 8px;cursor:pointer;font-size:11px;">✕</button>' +
            '</div>';
        }).join('');

        _renderBlocklistSuggestions(alertCounts, blockedIPs);

    } catch(err) { console.error('Blocklist load error:', err); }
};

function _renderBlocklistSuggestions(alertCounts, blockedIPs) {
    var suggestEl = document.getElementById('blocklist-suggestions');
    if (!suggestEl) return;

    // Top IPs from alerts not already blocked
    var suggestions = Object.entries(alertCounts)
        .filter(function(e){ return !blockedIPs.includes(e[0]) && e[1] >= 2; })
        .sort(function(a,b){ return b[1]-a[1]; })
        .slice(0, 3);

    if (suggestions.length === 0) {
        suggestEl.style.display = 'none';
        return;
    }

    suggestEl.style.display = 'block';
    suggestEl.innerHTML = '<div style="font-family:\'Space Grotesk\',sans-serif;font-size:10px;color:#475569;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">⚡ Suggested from recent alerts</div>' +
        suggestions.map(function(e) {
            return '<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 10px;background:rgba(245,158,11,0.05);border:1px solid rgba(245,158,11,0.15);border-radius:8px;margin-bottom:4px;">' +
                '<span style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#f59e0b;">' + e[0] + ' <span style="color:#475569;font-size:10px;">(' + e[1] + 'x)</span></span>' +
                '<button onclick="document.getElementById(\'block-ip\').value=\'' + e[0] + '\';document.getElementById(\'block-ip\').focus();" style="background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.25);border-radius:6px;color:#f59e0b;padding:3px 8px;cursor:pointer;font-size:10px;font-weight:700;">+ Block</button>' +
            '</div>';
        }).join('');
}

// Start blocklist on load
loadBlocklist();
setInterval(loadBlocklist, 30000);
