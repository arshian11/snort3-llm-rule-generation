// app.js — Snort 3 Live Console Client Application
'use strict';

const App = (() => {
  let _activeTab = 'dashboard';
  let _autoScroll = true;
  let _paused = false;
  let _alerts = [];
  let _filterQuery = '';
  let _filterPriority = '';
  let _filterProto = '';
  let _filterGroundTruth = 'threats'; // default: show suspicious or malicious alerts
  let _filterFlowId = '';
  let _currentPage = 1;
  let _pageSize = 100;
  let _totalPages = 1;
  let _totalMatching = 0;
  let _totalAlerts = 0;
  let _signaturesCount = 0;
  let _allSignatures = [];
  let _sigsSearchQuery = '';
  let _matchingSignaturesCount = null;
  let _correlatedCount = 0;
  let _totalFlows = 0;
  let _isLoadingAlerts = false;
  let _filterDebounceTimer = null;
  let _currentStats = null;
  let _selectedAlert = null;
  let _alertRateCounter = 0;
  let _alertsPerSec = 0;

  // Initialize application
  function init() {
    initTheme();
    syncAlertsTableHeaders();
    setupNavigation();
    setupSSE();
    setupControls();
    setupFilters();
    setupPaginationControls();
    setupModal();
    setupFileUpload();

    // Rate calculation timer
    setInterval(() => {
      _alertsPerSec = _alertRateCounter;
      _alertRateCounter = 0;
      const rateEl = document.getElementById('stream-rate-badge');
      if (rateEl) {
        if (_alertsPerSec > 0) {
          rateEl.style.display = 'inline-block';
          rateEl.textContent = `${_alertsPerSec} alerts/sec`;
        } else {
          rateEl.style.display = 'none';
        }
      }
    }, 1000);

    // Initial fetch of data
    fetchInitialData();
  }

  // ── Theme Management ──────────────────────────────────────────────────────────

  function initTheme() {
    const saved = localStorage.getItem('snort.theme') || 'cobalt';
    document.documentElement.setAttribute('data-theme', saved);
    const select = document.getElementById('theme-select');
    if (select) {
      select.value = saved;
      select.addEventListener('change', (e) => {
        const t = e.target.value;
        document.documentElement.setAttribute('data-theme', t);
        localStorage.setItem('snort.theme', t);
        showToast(`Theme switched to ${t}`, 'info');
      });
    }
  }

  // ── Navigation ───────────────────────────────────────────────────────────────

  function setupNavigation() {
    const navBtns = document.querySelectorAll('.view-btn');
    navBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        switchTab(tab);
      });
    });

    // KPI Cards pivot to tabs
    document.querySelectorAll('.dash-kpi-card[data-pivot-tab]').forEach(card => {
      card.addEventListener('click', () => {
        const tab = card.getAttribute('data-tab') || card.getAttribute('data-pivot-tab');
        const prio = card.getAttribute('data-pivot-prio');
        const gt = card.getAttribute('data-pivot-gt');
        if (prio) setFilterPriority(prio);
        if (gt) setFilterGroundTruth(gt);
        switchTab(tab, { keepFilters: true });
      });
    });
  }

  function switchTab(tab, options = {}) {
    // When switching to alerts tab from another tab without a flow filter, remove all filters so all alerts show
    if (tab === 'alerts' && _activeTab !== 'alerts' && !options.keepFilters && !options.isFlowFilter) {
      resetAllAlertFilters();
      _currentPage = 1;
    }

    _activeTab = tab;
    document.querySelectorAll('.view-btn').forEach(btn => {
      if (btn.getAttribute('data-tab') === tab) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    document.querySelectorAll('.tab-panel').forEach(panel => {
      if (panel.id === `tab-${tab}`) {
        panel.classList.add('active');
      } else {
        panel.classList.remove('active');
      }
    });

    // Refresh tab content if needed
    if (tab === 'correlations') {
      loadCorrelations();
    } else if (tab === 'signatures') {
      loadSignatures();
    } else if (tab === 'alerts') {
      loadAlerts(_currentPage);
    }

    updateViewCounts();
  }

  // ── Server-Sent Events (SSE) ─────────────────────────────────────────────────

  function setupSSE() {
    const dot = document.getElementById('stream-health-dot');
    const statusText = document.getElementById('stream-status-text');

    SSE.on('state_change', ({ state }) => {
      if (dot && statusText) {
        if (state === SSE.State.CONNECTED) {
          dot.className = 'health-dot health-live';
          dot.title = 'Dataset Synchronized';
          statusText.textContent = 'PCAP Analysis Active (Offline)';
        } else if (state === SSE.State.RETRYING || state === SSE.State.CONNECTING) {
          dot.className = 'health-dot health-retrying';
          dot.title = 'Connecting to server...';
          statusText.textContent = 'Connecting...';
        } else {
          dot.className = 'health-dot health-unknown';
          dot.title = 'Server Disconnected';
          statusText.textContent = 'Offline';
        }
      }
    });

    SSE.on('alert', (data) => {
      if (!data || !data.alert) return;
      _alertRateCounter++;
      const alert = data.alert;

      // Check if matches active filter
      if (matchesFilter(alert)) {
        _totalMatching++;
        _totalAlerts++;
        if (_currentPage === 1 && !_paused && _activeTab === 'alerts') {
          _alerts.unshift(alert);
          if (_alerts.length > _pageSize) _alerts.pop();
          renderAlertsTable();
          renderPagination();
        }
      } else {
        _totalAlerts++;
      }

      // Update counters
      updateViewCounts();

      // Update stats if attached
      if (data.stats) {
        renderStats(data.stats);
      }
    });

    SSE.on('stats', (data) => {
      const stats = data.stats || data;
      renderStats(stats);
    });

    SSE.on('clear', () => {
      _alerts = [];
      const tbody = document.getElementById('alerts-table-body');
      if (tbody) tbody.innerHTML = '';
      fetchInitialData();
      showToast('Alert storage cleared', 'info');
    });

    // Connect to /events
    SSE.connect();
  }

  // ── API Fetching ─────────────────────────────────────────────────────────────

  async function fetchInitialData() {
    try {
      const [statsRes] = await Promise.all([
        fetch('/api/stats'),
        loadAlerts(1)
      ]);

      if (statsRes.ok) {
        const stats = await statsRes.json();
        renderStats(stats);
      }
    } catch (err) {
      console.error('Failed to fetch initial data:', err);
    }
  }

  // ── Render Statistics & KPIs ─────────────────────────────────────────────────

  function renderStats(stats) {
    if (!stats) return;
    _currentStats = stats;

    // 1. Total Alert count
    const totalEl = document.getElementById('dash-alerts-total');
    if (totalEl) totalEl.textContent = stats.total_alerts.toLocaleString();

    // 2. Unique Signatures
    const sigsEl = document.getElementById('dash-sigs-total');
    if (sigsEl) sigsEl.textContent = stats.unique_signatures_count.toLocaleString();

    // 3. Priority 1 (High/Critical) Alerts
    const p1El = document.getElementById('dash-p1-total');
    const p1Sub = document.getElementById('dash-p1-sub');
    if (p1El) p1El.textContent = (stats.priority_distribution?.p1 || 0).toLocaleString();
    if (p1Sub) p1Sub.textContent = `${stats.priority_distribution?.p1_pct || 0}% of total`;

    // 4. Correlated Connections (Flows with >1 alert)
    const corrEl = document.getElementById('dash-corr-total');
    const corrSub = document.getElementById('dash-corr-sub');
    if (corrEl) corrEl.textContent = (stats.correlated_flows_count || 0).toLocaleString();
    if (corrSub) corrSub.textContent = `Across ${stats.total_flows || 0} active flows`;

    // 5. Ground Truth (Malicious %)
    const gtEl = document.getElementById('dash-gt-total');
    const gtSub = document.getElementById('dash-gt-sub');
    if (gtEl) gtEl.textContent = `${stats.ground_truth?.malicious_pct || 0}%`;
    if (gtSub) gtSub.textContent = `${stats.ground_truth?.malicious || 0} Malicious · ${stats.ground_truth?.suspicious || 0} Suspicious · ${stats.ground_truth?.benign || 0} Benign`;

    // Render Priority Segmented Meter
    renderPriorityMeter(stats.priority_distribution, stats.total_alerts);

    // Render Protocol Bars
    renderProtocolBars(stats.protocol_distribution, stats.total_alerts);

    // Render Top Sources
    renderTopSources(stats.top_sources);

    // Render Top Destinations
    renderTopDestinations(stats.top_destinations);

    // Render Ground Truth Matrix
    renderGroundTruthMatrix(stats.ground_truth, stats.total_alerts);

    // Update navigation counts
    updateViewCounts();
  }

  function updateViewCounts() {
    const totalAlerts = _totalAlerts || (_currentStats ? _currentStats.total_alerts : _alerts.length) || 0;
    const sigs = _signaturesCount || (_currentStats ? _currentStats.unique_signatures_count : 0);
    const corr = _correlatedCount || (_currentStats ? _currentStats.correlated_flows_count : 0);
    const mal = _currentStats ? _currentStats.ground_truth?.malicious : 0;
    const ben = _currentStats ? _currentStats.ground_truth?.benign : 0;
    const sus = _currentStats ? _currentStats.ground_truth?.suspicious : 0;
    const totalFlows = _totalFlows || (_currentStats ? _currentStats.total_flows : 0);
    const totalGt = _currentStats ? (_currentStats.ground_truth?.total_evaluated || (mal + ben + sus)) : (mal + ben + sus);

    // 1. PCAP Alerts Badge (#nav-count-alerts)
    const countAlerts = document.getElementById('nav-count-alerts');
    if (countAlerts) {
      const isFiltered = Boolean(
        _filterPriority ||
        _filterProto ||
        (_filterGroundTruth && _filterGroundTruth !== 'all') ||
        _filterFlowId ||
        _filterQuery
      );
      if (isFiltered) {
        countAlerts.textContent = _totalMatching.toLocaleString();
        countAlerts.title = `${_totalMatching.toLocaleString()} matching alerts (filtered from ${totalAlerts.toLocaleString()} total)`;
      } else {
        countAlerts.textContent = totalAlerts.toLocaleString();
        countAlerts.title = `${totalAlerts.toLocaleString()} total alerts`;
      }
    }

    // 2. Alert Correlation Badge (#nav-count-corr)
    const countCorr = document.getElementById('nav-count-corr');
    if (countCorr) {
      if (_corrFilter === 'all') {
        countCorr.textContent = totalFlows.toLocaleString();
        countCorr.title = `${totalFlows.toLocaleString()} total connection flows (all)`;
      } else {
        countCorr.textContent = corr.toLocaleString();
        countCorr.title = `${corr.toLocaleString()} multi-alert correlated sessions (>1 alert)`;
      }
    }

    // 3. Unique Signatures Badge (#nav-count-sigs)
    const countSigs = document.getElementById('nav-count-sigs');
    if (countSigs) {
      const displaySigs = _matchingSignaturesCount !== null ? _matchingSignaturesCount : sigs;
      countSigs.textContent = displaySigs.toLocaleString();
      if (_matchingSignaturesCount !== null && _matchingSignaturesCount !== sigs) {
        countSigs.title = `${displaySigs.toLocaleString()} matching signatures (filtered from ${sigs.toLocaleString()} total)`;
      } else {
        countSigs.title = `${displaySigs.toLocaleString()} unique signatures`;
      }
    }

    // 4. Ground Truth Badge (#nav-count-gt)
    const countGt = document.getElementById('nav-count-gt');
    if (countGt) {
      const gt = (_filterGroundTruth || 'all').toLowerCase();
      if (gt === 'malicious') {
        countGt.textContent = mal.toLocaleString();
        countGt.title = `${mal.toLocaleString()} Malicious True Positives (filtered)`;
      } else if (gt === 'suspicious') {
        countGt.textContent = sus.toLocaleString();
        countGt.title = `${sus.toLocaleString()} Suspicious alerts (filtered)`;
      } else if (gt === 'benign') {
        countGt.textContent = ben.toLocaleString();
        countGt.title = `${ben.toLocaleString()} Benign False Positives (filtered)`;
      } else if (gt === 'threats' || gt === 'suspicious_malicious') {
        countGt.textContent = (mal + sus).toLocaleString();
        countGt.title = `${(mal + sus).toLocaleString()} Threats (Malicious + Suspicious filtered)`;
      } else {
        countGt.textContent = mal.toLocaleString();
        countGt.title = `${mal.toLocaleString()} Malicious True Positives out of ${totalGt.toLocaleString()} evaluated`;
      }
    }

    // Also update view headers if present
    const alertsHeader = document.getElementById('alerts-header-count');
    if (alertsHeader) {
      const isFiltered = Boolean(_filterPriority || _filterProto || (_filterGroundTruth && _filterGroundTruth !== 'all') || _filterFlowId || _filterQuery);
      if (isFiltered) {
        alertsHeader.textContent = `${_totalMatching.toLocaleString()} / ${totalAlerts.toLocaleString()} Alerts`;
      } else {
        alertsHeader.textContent = `${totalAlerts.toLocaleString()} Alerts`;
      }
    }

    const corrHeaderCount = document.getElementById('corr-header-count');
    const corrHeaderTotal = document.getElementById('corr-header-total');
    if (corrHeaderCount) corrHeaderCount.textContent = `${corr.toLocaleString()} Correlated Sessions`;
    if (corrHeaderTotal) corrHeaderTotal.textContent = `${totalFlows.toLocaleString()} Total Active Flows`;

    const chipMulti = document.getElementById('corr-chip-multi-count');
    const chipAll = document.getElementById('corr-chip-all-count');
    if (chipMulti) chipMulti.textContent = corr.toLocaleString();
    if (chipAll) chipAll.textContent = totalFlows.toLocaleString();

    const sigsHeader = document.getElementById('sigs-header-count');
    if (sigsHeader) sigsHeader.textContent = `${sigs.toLocaleString()} Unique Signatures`;

    const gtHeaderMal = document.getElementById('gt-header-mal');
    const gtHeaderBen = document.getElementById('gt-header-ben');
    const gtHeaderTotal = document.getElementById('gt-header-total');
    if (gtHeaderMal) gtHeaderMal.textContent = `${mal.toLocaleString()} Malicious (True Positives)`;
    if (gtHeaderBen) gtHeaderBen.textContent = `${ben.toLocaleString()} Benign (False Alarms)`;
    if (gtHeaderTotal) gtHeaderTotal.textContent = `${totalGt.toLocaleString()} Total Evaluated`;
  }

  // ── Priority Distribution ────────────────────────────────────────────────────

  function renderPriorityMeter(prio, total) {
    if (!prio) return;
    const p1Bar = document.getElementById('seg-p1');
    const p2Bar = document.getElementById('seg-p2');
    const p3Bar = document.getElementById('seg-p3');

    if (p1Bar) p1Bar.style.width = `${prio.p1_pct || 0}%`;
    if (p2Bar) p2Bar.style.width = `${prio.p2_pct || 0}%`;
    if (p3Bar) p3Bar.style.width = `${prio.p3_pct || 0}%`;

    const c1 = document.getElementById('p1-count');
    const c2 = document.getElementById('p2-count');
    const c3 = document.getElementById('p3-count');

    if (c1) c1.textContent = (prio.p1 || 0).toLocaleString();
    if (c2) c2.textContent = (prio.p2 || 0).toLocaleString();
    if (c3) c3.textContent = (prio.p3 || 0).toLocaleString();
  }

  // ── Protocol Distribution ────────────────────────────────────────────────────

  function renderProtocolBars(proto, total) {
    if (!proto) return;
    const tcpBar = document.getElementById('meter-tcp');
    const udpBar = document.getElementById('meter-udp');
    const icmpBar = document.getElementById('meter-icmp');

    if (tcpBar) tcpBar.style.width = `${proto.tcp_pct || 0}%`;
    if (udpBar) udpBar.style.width = `${proto.udp_pct || 0}%`;
    if (icmpBar) icmpBar.style.width = `${proto.icmp_pct || 0}%`;

    const tcpVal = document.getElementById('val-tcp');
    const udpVal = document.getElementById('val-udp');
    const icmpVal = document.getElementById('val-icmp');

    if (tcpVal) tcpVal.textContent = `${(proto.tcp || 0).toLocaleString()} (${proto.tcp_pct || 0}%)`;
    if (udpVal) udpVal.textContent = `${(proto.udp || 0).toLocaleString()} (${proto.udp_pct || 0}%)`;
    if (icmpVal) icmpVal.textContent = `${(proto.icmp || 0).toLocaleString()} (${proto.icmp_pct || 0}%)`;
  }

  // ── Top Sources & Destinations ───────────────────────────────────────────────

  function renderTopSources(sources) {
    const container = document.getElementById('top-sources-list');
    if (!container) return;

    if (!sources || sources.length === 0) {
      container.innerHTML = '<div style="color:var(--fg-muted);font-size:12px;padding:8px;">No source alerts recorded</div>';
      return;
    }

    container.innerHTML = sources.map((s, idx) => `
      <div class="rank-row" onclick="App.filterBySource('${escapeHtml(s.ip)}')">
        <div class="rank-ip-group">
          <div class="rank-badge top${idx + 1}">${idx + 1}</div>
          <div>
            <div class="rank-ip">${escapeHtml(s.ip)}</div>
            <div class="rank-sub">Attacking Source</div>
          </div>
        </div>
        <div class="rank-stats">
          <div class="rank-count">${s.count} alerts</div>
          <div class="rank-pct">${s.pct}%</div>
        </div>
      </div>
    `).join('');
  }

  function renderTopDestinations(destinations) {
    const container = document.getElementById('top-destinations-list');
    if (!container) return;

    if (!destinations || destinations.length === 0) {
      container.innerHTML = '<div style="color:var(--fg-muted);font-size:12px;padding:8px;">No destination targets recorded</div>';
      return;
    }

    container.innerHTML = destinations.map((d, idx) => `
      <div class="rank-row" onclick="App.filterByDestination('${escapeHtml(d.ip)}')">
        <div class="rank-ip-group">
          <div class="rank-badge top${idx + 1}">${idx + 1}</div>
          <div>
            <div class="rank-ip">${escapeHtml(d.ip)}</div>
            <div class="rank-sub">Target Host</div>
          </div>
        </div>
        <div class="rank-stats">
          <div class="rank-count">${d.count} alerts</div>
          <div class="rank-pct">${d.pct}%</div>
        </div>
      </div>
    `).join('');
  }

  // ── Ground Truth Matrix ──────────────────────────────────────────────────────

  function renderGroundTruthMatrix(gt, total) {
    if (!gt) return;
    const malVal = document.getElementById('gt-malicious-count');
    const benVal = document.getElementById('gt-benign-count');
    const susVal = document.getElementById('gt-suspicious-count');
    const headerMal = document.getElementById('gt-header-mal');
    const headerSus = document.getElementById('gt-header-sus');
    const headerBen = document.getElementById('gt-header-ben');
    const headerTotal = document.getElementById('gt-header-total');

    const malCount = gt.malicious || 0;
    const benCount = gt.benign || 0;
    const susCount = gt.suspicious || 0;
    const totalGt = gt.total_evaluated || (malCount + benCount + susCount);

    if (malVal) malVal.textContent = malCount.toLocaleString();
    if (benVal) benVal.textContent = benCount.toLocaleString();
    if (susVal) susVal.textContent = susCount.toLocaleString();

    if (headerMal) headerMal.textContent = `${malCount.toLocaleString()} Malicious (True Positives)`;
    if (headerSus) headerSus.textContent = `${susCount.toLocaleString()} Suspicious (Unclassified)`;
    if (headerBen) headerBen.textContent = `${benCount.toLocaleString()} Benign (False Alarms)`;
    if (headerTotal) headerTotal.textContent = `${totalGt.toLocaleString()} Total Evaluated`;

    const malPct = totalGt > 0 ? (malCount / totalGt * 100) : 0;
    const susPct = totalGt > 0 ? (susCount / totalGt * 100) : 0;
    const benPct = totalGt > 0 ? (benCount / totalGt * 100) : 0;

    const malBar = document.getElementById('gt-bar-malicious');
    const susBar = document.getElementById('gt-bar-suspicious');
    const benBar = document.getElementById('gt-bar-benign');
    if (malBar) {
      malBar.style.width = `${malPct.toFixed(1)}%`;
      malBar.title = `Malicious: ${malCount.toLocaleString()} (${malPct.toFixed(1)}%)`;
    }
    if (susBar) {
      susBar.style.width = `${susPct.toFixed(1)}%`;
      susBar.title = `Suspicious: ${susCount.toLocaleString()} (${susPct.toFixed(1)}%)`;
    }
    if (benBar) {
      benBar.style.width = `${benPct.toFixed(1)}%`;
      benBar.title = `Benign: ${benCount.toLocaleString()} (${benPct.toFixed(1)}%)`;
    }
  }

  // ── Alerts Table & Pagination ─────────────────────────────────────────────────

  async function loadAlerts(page = _currentPage) {
    _isLoadingAlerts = true;
    _currentPage = page;

    const params = new URLSearchParams();
    params.set('page', _currentPage);
    params.set('limit', _pageSize);
    if (_filterPriority) params.set('priority', _filterPriority);
    if (_filterProto) params.set('protocol', _filterProto);
    if (_filterGroundTruth && _filterGroundTruth !== 'all') {
      params.set('ground_truth', _filterGroundTruth);
    }
    if (_filterFlowId) params.set('flow_id', _filterFlowId);
    if (_filterQuery) params.set('q', _filterQuery);

    try {
      const res = await fetch(`/api/alerts?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load alerts');
      const data = await res.json();
      _alerts = data.alerts || [];
      _currentPage = data.page || _currentPage;
      _pageSize = data.limit || _pageSize;
      _totalPages = data.total_pages || 1;
      _totalMatching = data.total_matching !== undefined ? data.total_matching : _alerts.length;
      _totalAlerts = data.total_alerts || _totalMatching;

      renderAlertsTable();
      renderPagination();
      updateViewCounts();
    } catch (err) {
      console.error('Error fetching alerts:', err);
    } finally {
      _isLoadingAlerts = false;
    }
  }

  function goToPage(page) {
    const target = Math.max(1, Math.min(page, _totalPages));
    if (target === _currentPage && _alerts.length > 0) return;
    loadAlerts(target);
    const mainEl = document.getElementById('main');
    if (mainEl) mainEl.scrollTop = 0;
  }

  function syncAlertsTableHeaders() {
    const tbody = document.getElementById('alerts-table-body');
    if (!tbody) return;
    const table = tbody.closest('table') || tbody.parentElement;
    if (!table) return;
    const thead = table.querySelector('thead');
    if (!thead) return;

    const ths = thead.querySelectorAll('th');
    const headerTexts = Array.from(ths).map(th => th.textContent.trim().toLowerCase());
    // If "timestamp" is found or headers count is not 6, overwrite thead to guarantee exact column alignment
    if (headerTexts.some(h => h.includes('timestamp')) || ths.length !== 6) {
      thead.innerHTML = `
        <tr>
          <th style="width:70px;">Priority</th>
          <th style="width:110px;">GID:SID</th>
          <th>Rule Message / Signature</th>
          <th>Source → Destination</th>
          <th style="width:70px;">Proto</th>
          <th style="width:110px;">Ground Truth</th>
        </tr>
      `;
    }
  }

  function renderAlertsTable() {
    syncAlertsTableHeaders();
    const tbody = document.getElementById('alerts-table-body');
    if (!tbody) return;

    const tableCount = document.getElementById('alerts-table-count');
    const headerCount = document.getElementById('alerts-header-count');

    const startNum = _totalMatching === 0 ? 0 : (_currentPage - 1) * _pageSize + 1;
    const endNum = Math.min(_currentPage * _pageSize, _totalMatching);

    if (tableCount) {
      if (_filterFlowId) {
        tableCount.innerHTML = `Showing alerts for <strong>Flow #${escapeHtml(_filterFlowId)}</strong> (${_totalMatching.toLocaleString()} alerts) <button id="btn-clear-flow-filter" class="chip active" style="margin-left:8px;padding:2px 8px;font-size:11px;cursor:pointer;background:var(--accent);color:var(--on-accent);border:none;border-radius:4px;" title="Clear Flow Filter">✕ Clear Flow Filter</button>`;
        const clearFlowBtn = document.getElementById('btn-clear-flow-filter');
        if (clearFlowBtn) {
          clearFlowBtn.onclick = (e) => {
            e.stopPropagation();
            _filterFlowId = '';
            _currentPage = 1;
            loadAlerts(1);
          };
        }
      } else if (_totalMatching === 0) {
        tableCount.textContent = 'Showing 0 alerts (filtered)';
      } else if (_totalMatching === _totalAlerts) {
        if (_totalMatching <= _pageSize) {
          tableCount.textContent = `Showing all ${_totalMatching.toLocaleString()} alerts`;
        } else {
          tableCount.textContent = `Showing ${startNum.toLocaleString()}–${endNum.toLocaleString()} of ${_totalMatching.toLocaleString()} alerts`;
        }
      } else {
        tableCount.textContent = `Showing ${startNum.toLocaleString()}–${endNum.toLocaleString()} of ${_totalMatching.toLocaleString()} alerts (filtered)`;
      }
    }

    if (headerCount) {
      const countDisplay = _totalMatching !== _totalAlerts
        ? `${_totalMatching.toLocaleString()} / ${_totalAlerts.toLocaleString()} Alerts`
        : `${_totalAlerts.toLocaleString()} Alerts`;
      headerCount.textContent = countDisplay;
    }

    if (_alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--fg-muted);">No alerts match the active filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = _alerts.map(a => createAlertRowHtml(a)).join('');
  }

  function renderPagination() {
    const startNum = _totalMatching === 0 ? 0 : (_currentPage - 1) * _pageSize + 1;
    const endNum = Math.min(_currentPage * _pageSize, _totalMatching);

    // Top Controls
    const prevTop = document.getElementById('alerts-prev-top');
    const nextTop = document.getElementById('alerts-next-top');
    const indicatorTop = document.getElementById('alerts-page-indicator-top');

    if (indicatorTop) indicatorTop.textContent = `Page ${_currentPage} of ${_totalPages}`;
    if (prevTop) prevTop.disabled = (_currentPage <= 1);
    if (nextTop) nextTop.disabled = (_currentPage >= _totalPages);

    // Bottom Summary
    const summary = document.getElementById('alerts-pagination-summary');
    if (summary) {
      if (_totalMatching === 0) {
        summary.textContent = `0 alerts matching active filters (from ${_totalAlerts.toLocaleString()} total)`;
      } else if (_totalMatching === _totalAlerts) {
        summary.textContent = `Showing ${startNum.toLocaleString()}–${endNum.toLocaleString()} of ${_totalAlerts.toLocaleString()} alerts`;
      } else {
        summary.textContent = `Showing ${startNum.toLocaleString()}–${endNum.toLocaleString()} of ${_totalMatching.toLocaleString()} alerts (filtered from ${_totalAlerts.toLocaleString()} total)`;
      }
    }

    // Bottom Controls
    const firstBtn = document.getElementById('alerts-first-btn');
    const prevBtn = document.getElementById('alerts-prev-btn');
    const nextBtn = document.getElementById('alerts-next-btn');
    const lastBtn = document.getElementById('alerts-last-btn');
    const jumpInput = document.getElementById('alerts-jump-input');
    const pageSizeSelect = document.getElementById('alerts-page-size');

    if (firstBtn) firstBtn.disabled = (_currentPage <= 1);
    if (prevBtn) prevBtn.disabled = (_currentPage <= 1);
    if (nextBtn) nextBtn.disabled = (_currentPage >= _totalPages);
    if (lastBtn) lastBtn.disabled = (_currentPage >= _totalPages);

    if (jumpInput) {
      jumpInput.max = _totalPages;
      jumpInput.value = _currentPage;
    }

    if (pageSizeSelect && parseInt(pageSizeSelect.value, 10) !== _pageSize) {
      pageSizeSelect.value = String(_pageSize);
    }

    // Numbers
    const numbersContainer = document.getElementById('alerts-page-numbers');
    if (numbersContainer) {
      numbersContainer.innerHTML = '';
      const pagesToShow = getPageWindow(_currentPage, _totalPages, 5);
      pagesToShow.forEach(item => {
        if (item === '...') {
          const dots = document.createElement('span');
          dots.textContent = '…';
          dots.style.cssText = 'padding:0 4px;color:var(--fg-muted);font-size:12px;';
          numbersContainer.appendChild(dots);
        } else {
          const btn = document.createElement('button');
          btn.className = `page-btn ${item === _currentPage ? 'active' : ''}`;
          btn.textContent = String(item);
          btn.style.padding = '4px 8px';
          btn.addEventListener('click', () => goToPage(item));
          numbersContainer.appendChild(btn);
        }
      });
    }
  }

  function getPageWindow(curr, total, maxVisible = 5) {
    if (total <= maxVisible + 2) {
      return Array.from({ length: total }, (_, i) => i + 1);
    }
    const pages = [];
    pages.push(1);
    let start = Math.max(2, curr - 1);
    let end = Math.min(total - 1, curr + 1);

    if (curr <= 3) {
      end = Math.min(total - 1, 4);
    } else if (curr >= total - 2) {
      start = Math.max(2, total - 3);
    }

    if (start > 2) pages.push('...');
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }
    if (end < total - 1) pages.push('...');
    pages.push(total);
    return pages;
  }

  function setupPaginationControls() {
    const prevTop = document.getElementById('alerts-prev-top');
    const nextTop = document.getElementById('alerts-next-top');
    const firstBtn = document.getElementById('alerts-first-btn');
    const prevBtn = document.getElementById('alerts-prev-btn');
    const nextBtn = document.getElementById('alerts-next-btn');
    const lastBtn = document.getElementById('alerts-last-btn');
    const jumpInput = document.getElementById('alerts-jump-input');
    const jumpBtn = document.getElementById('alerts-jump-btn');
    const pageSizeSelect = document.getElementById('alerts-page-size');

    if (prevTop) prevTop.addEventListener('click', () => goToPage(_currentPage - 1));
    if (nextTop) nextTop.addEventListener('click', () => goToPage(_currentPage + 1));
    if (firstBtn) firstBtn.addEventListener('click', () => goToPage(1));
    if (prevBtn) prevBtn.addEventListener('click', () => goToPage(_currentPage - 1));
    if (nextBtn) nextBtn.addEventListener('click', () => goToPage(_currentPage + 1));
    if (lastBtn) lastBtn.addEventListener('click', () => goToPage(_totalPages));

    if (jumpBtn && jumpInput) {
      jumpBtn.addEventListener('click', () => {
        const val = parseInt(jumpInput.value, 10);
        if (!isNaN(val)) goToPage(val);
      });
      jumpInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          const val = parseInt(jumpInput.value, 10);
          if (!isNaN(val)) goToPage(val);
        }
      });
    }

    if (pageSizeSelect) {
      pageSizeSelect.addEventListener('change', () => {
        const val = parseInt(pageSizeSelect.value, 10);
        if (!isNaN(val) && val > 0) {
          _pageSize = val;
          _currentPage = 1;
          loadAlerts(1);
        }
      });
    }
  }

  function prependAlertRow(alert) {
    const tbody = document.getElementById('alerts-table-body');
    if (!tbody) return;

    if (!matchesFilter(alert)) return;

    const rowHtml = createAlertRowHtml(alert);
    const temp = document.createElement('tbody');
    temp.innerHTML = rowHtml;
    const newRow = temp.firstElementChild;

    tbody.insertBefore(newRow, tbody.firstChild);

    // Limit visible rows to page size
    while (tbody.children.length > _pageSize) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  function createAlertRowHtml(a) {
    const pClass = a.priority === 1 ? 'crit' : a.priority === 2 ? 'high' : 'med';
    const gtClass = (a.ground_truth || 'Suspicious').toLowerCase();

    return `
      <tr onclick="App.inspectAlert(${a.id})" style="cursor:pointer;">
        <td><span class="kpi-pill ${pClass}">P${a.priority}</span></td>
        <td><span class="badge-sig">${escapeHtml(a.sig_key)}</span></td>
        <td style="font-weight:600;max-width:320px;overflow:hidden;text-overflow:ellipsis;" title="${escapeHtml(a.msg)}">${escapeHtml(a.msg)}</td>
        <td style="font-family:monospace;">
          ${escapeHtml(a.src_ip)}${a.src_port ? ':' + a.src_port : ''}
          <span style="color:var(--accent);">→</span>
          ${escapeHtml(a.dst_ip)}${a.dst_port ? ':' + a.dst_port : ''}
        </td>
        <td><span class="proto-badge">${escapeHtml(a.proto)}</span></td>
        <td><span class="badge-ground ${gtClass}">${escapeHtml(a.ground_truth || 'Suspicious')}</span></td>
      </tr>
    `;
  }

  // ── Alert Correlation View ───────────────────────────────────────────────────

  let _corrFilter = 'correlated'; // 'correlated' | 'all'

  async function loadCorrelations() {
    const container = document.getElementById('correlations-list');
    if (!container) return;

    container.innerHTML = '<div style="color:var(--fg-muted);padding:16px;">Loading correlated connection flows...</div>';

    try {
      const res = await fetch(`/api/correlations?filter=${_corrFilter}`);
      if (!res.ok) throw new Error('Failed to load correlations');
      const data = await res.json();
      const flows = data.flows || [];
      const correlatedCount = data.correlated_count !== undefined ? data.correlated_count : flows.filter(f => f.alert_count > 1).length;
      const totalFlows = data.total_flows !== undefined ? data.total_flows : flows.length;
      _correlatedCount = correlatedCount;
      _totalFlows = totalFlows;
      updateViewCounts();

      // Update header badges
      const headerCount = document.getElementById('corr-header-count');
      const headerTotal = document.getElementById('corr-header-total');
      if (headerCount) headerCount.textContent = `${correlatedCount.toLocaleString()} Correlated Sessions`;
      if (headerTotal) headerTotal.textContent = `${totalFlows.toLocaleString()} Total Active Flows`;

      const chipMulti = document.getElementById('corr-chip-multi-count');
      const chipAll = document.getElementById('corr-chip-all-count');
      if (chipMulti) chipMulti.textContent = correlatedCount.toLocaleString();
      if (chipAll) chipAll.textContent = totalFlows.toLocaleString();

      const filterHint = document.getElementById('corr-filter-hint');
      if (filterHint) {
        if (_corrFilter === 'correlated') {
          filterHint.textContent = `Displaying ${flows.length} multi-alert correlated sessions matching sidebar count (${correlatedCount})`;
        } else {
          filterHint.textContent = `Displaying all ${flows.length} connection flows (${correlatedCount} multi-alert correlated sessions)`;
        }
      }

      if (flows.length === 0) {
        container.innerHTML = `<div style="color:var(--fg-muted);padding:16px;">No ${_corrFilter === 'correlated' ? 'correlated connection flows (>1 alert)' : 'connection flows'} recorded yet.</div>`;
        return;
      }

      container.innerHTML = flows.map(f => {
        const pClass = f.max_priority === 1 ? 'crit' : f.max_priority === 2 ? 'high' : 'med';
        const isMulti = f.alert_count > 1;
        const tagText = isMulti ? `${f.alert_count} alerts correlated` : `1 alert (single event)`;
        const tagClass = isMulti ? 'conn-flow-tag' : 'conn-flow-tag single';

        return `
          <div class="corr-flow-card" onclick="App.filterByFlow(${f.flow_id})">
            <div class="corr-header">
              <div class="corr-tuple">
                <span class="proto-badge">${escapeHtml(f.proto)}</span>
                <span>${escapeHtml(f.src_ip)}:${f.src_port} → ${escapeHtml(f.dst_ip)}:${f.dst_port}</span>
              </div>
              <div style="display:flex;align-items:center;gap:8px;">
                <span class="kpi-pill ${pClass}">P${f.max_priority}</span>
                <span class="${tagClass}">${tagText}</span>
                <span class="badge-ground ${f.ground_truth.toLowerCase()}">${f.ground_truth}</span>
              </div>
            </div>
            <div style="font-size:11.5px;color:var(--fg-muted);display:flex;gap:14px;margin-bottom:6px;">
              <span>First seen: ${escapeHtml(f.first_seen)}</span>
              <span>Last seen: ${escapeHtml(f.last_seen)}</span>
              <span>Distinct SIDs: ${(f.unique_sids || []).length}</span>
            </div>
            <div class="corr-timeline">
              ${(f.signatures || []).map(sig => `
                <div class="corr-step">
                  <span class="corr-step-msg">⚡ ${escapeHtml(sig)}</span>
                </div>
              `).join('')}
            </div>
          </div>
        `;
      }).join('');
    } catch (err) {
      container.innerHTML = `<div style="color:var(--sev-critical);padding:16px;">Error: ${err.message}</div>`;
    }
  }

  // ── Signatures View ──────────────────────────────────────────────────────────

  async function loadSignatures() {
    const tbody = document.getElementById('signatures-table-body');
    if (!tbody) return;

    tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;color:var(--fg-muted);">Loading unique signatures...</td></tr>';

    try {
      const res = await fetch('/api/signatures');
      if (!res.ok) throw new Error('Failed to load signatures');
      const data = await res.json();
      _allSignatures = data.signatures || [];
      _signaturesCount = _allSignatures.length;

      renderSignaturesTable();
      updateViewCounts();
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" style="color:var(--sev-critical);padding:16px;">Error: ${err.message}</td></tr>`;
    }
  }

  function renderSignaturesTable() {
    const tbody = document.getElementById('signatures-table-body');
    if (!tbody) return;

    const query = (_sigsSearchQuery || '').toLowerCase().trim();
    const sigs = query
      ? _allSignatures.filter(s =>
          (s.sig_key || '').toLowerCase().includes(query) ||
          (s.msg || '').toLowerCase().includes(query) ||
          (s.classification || '').toLowerCase().includes(query) ||
          (s.ground_truth || '').toLowerCase().includes(query)
        )
      : _allSignatures;

    _matchingSignaturesCount = sigs.length;

    const headerCount = document.getElementById('sigs-header-count');
    const tableCount = document.getElementById('sigs-table-count');
    if (headerCount) headerCount.textContent = `${sigs.length.toLocaleString()} Unique Signatures`;
    if (tableCount) {
      if (query) {
        tableCount.textContent = `Showing ${sigs.length.toLocaleString()} of ${_allSignatures.length.toLocaleString()} distinct signatures (filtered)`;
      } else {
        tableCount.textContent = `Showing all ${sigs.length.toLocaleString()} distinct signatures detected across network traffic`;
      }
    }

    if (sigs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="padding:16px;color:var(--fg-muted);">No signatures match search criteria.</td></tr>';
      return;
    }

    tbody.innerHTML = sigs.map(s => {
      const pClass = s.priority === 1 ? 'crit' : s.priority === 2 ? 'high' : 'med';
      return `
        <tr onclick="App.filterBySignature('${escapeHtml(s.sig_key)}')" style="cursor:pointer;">
          <td><span class="badge-sig">${escapeHtml(s.sig_key)}</span></td>
          <td style="font-weight:600;">${escapeHtml(s.msg)}</td>
          <td><span class="kpi-pill ${pClass}">P${s.priority}</span></td>
          <td style="color:var(--fg-secondary);font-size:12px;">${escapeHtml(s.classification)}</td>
          <td><span class="badge-ground ${s.ground_truth.toLowerCase()}">${s.ground_truth}</span></td>
          <td style="font-weight:700;font-variant-numeric:tabular-nums;">${s.count.toLocaleString()}</td>
        </tr>
      `;
    }).join('');
  }

  // ── Filtering Logic ──────────────────────────────────────────────────────────

  function setupFilters() {
    const searchInput = document.getElementById('filter-query');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        clearTimeout(_filterDebounceTimer);
        _filterDebounceTimer = setTimeout(() => {
          _filterQuery = e.target.value.toLowerCase().trim();
          _currentPage = 1;
          loadAlerts(1);
        }, 250);
      });
    }

    document.querySelectorAll('.chip[data-filter-prio]').forEach(chip => {
      chip.addEventListener('click', () => {
        const val = chip.getAttribute('data-filter-prio');
        setFilterPriority(val === _filterPriority ? '' : val);
      });
    });

    document.querySelectorAll('.chip[data-filter-proto]').forEach(chip => {
      chip.addEventListener('click', () => {
        const val = chip.getAttribute('data-filter-proto');
        setFilterProto(val === _filterProto ? '' : val);
      });
    });

    document.querySelectorAll('.chip[data-filter-gt]').forEach(chip => {
      chip.addEventListener('click', () => {
        const val = chip.getAttribute('data-filter-gt');
        setFilterGroundTruth(val);
      });
    });

    // Correlation Filter Buttons
    document.querySelectorAll('[data-corr-filter]').forEach(btn => {
      btn.addEventListener('click', () => {
        const val = btn.getAttribute('data-corr-filter');
        _corrFilter = val;
        document.querySelectorAll('[data-corr-filter]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        loadCorrelations();
        updateViewCounts();
      });
    });

    // Unique Signatures Table Search
    const sigsSearch = document.getElementById('sigs-search-input');
    if (sigsSearch) {
      sigsSearch.addEventListener('input', (e) => {
        _sigsSearchQuery = e.target.value.toLowerCase().trim();
        renderSignaturesTable();
        updateViewCounts();
      });
    }

    const resetBtn = document.getElementById('reset-filter-btn');
    if (resetBtn) {
      resetBtn.addEventListener('click', clearAllFilters);
    }
  }

  function matchesFilter(a) {
    if (_filterPriority && String(a.priority) !== _filterPriority) return false;
    if (_filterProto && (a.proto || '').toUpperCase() !== _filterProto.toUpperCase()) return false;
    if (_filterGroundTruth && _filterGroundTruth !== 'all') {
      const gt = (a.ground_truth || 'Suspicious').toLowerCase();
      if (_filterGroundTruth === 'threats' || _filterGroundTruth === 'suspicious_malicious') {
        if (gt !== 'malicious' && gt !== 'suspicious') return false;
      } else if (gt !== _filterGroundTruth.toLowerCase()) {
        return false;
      }
    }
    if (_filterFlowId && String(a.flow_id) !== _filterFlowId) return false;

    if (_filterQuery) {
      const q = _filterQuery;
      const haystack = `${a.msg} ${a.sig_key} ${a.src_ip} ${a.dst_ip} ${a.classification} ${a.proto} ${a.sid || ''}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  }

  function getFilteredAlerts() {
    return _alerts.filter(matchesFilter);
  }

  function setFilterPriority(prio) {
    _filterPriority = prio;
    document.querySelectorAll('.chip[data-filter-prio]').forEach(c => {
      if (c.getAttribute('data-filter-prio') === prio) c.classList.add('active');
      else c.classList.remove('active');
    });
    _currentPage = 1;
    loadAlerts(1);
  }

  function setFilterProto(proto) {
    _filterProto = proto;
    document.querySelectorAll('.chip[data-filter-proto]').forEach(c => {
      if (c.getAttribute('data-filter-proto') === proto) c.classList.add('active');
      else c.classList.remove('active');
    });
    _currentPage = 1;
    loadAlerts(1);
  }

  function setFilterGroundTruth(gt) {
    _filterGroundTruth = gt;
    document.querySelectorAll('.chip[data-filter-gt]').forEach(c => {
      if (c.getAttribute('data-filter-gt').toLowerCase() === gt.toLowerCase()) c.classList.add('active');
      else c.classList.remove('active');
    });
    _currentPage = 1;
    loadAlerts(1);
  }

  function resetAllAlertFilters(options = {}) {
    _filterPriority = '';
    _filterProto = '';
    _filterGroundTruth = options.toAll ? 'all' : 'threats';
    _filterQuery = '';
    if (!options.keepFlowId) {
      _filterFlowId = '';
    }

    const input = document.getElementById('filter-query');
    if (input) input.value = '';

    document.querySelectorAll('.query-chips .chip[data-filter-prio]').forEach(c => c.classList.remove('active'));
    document.querySelectorAll('.query-chips .chip[data-filter-proto]').forEach(c => c.classList.remove('active'));
    document.querySelectorAll('.query-chips .chip[data-filter-gt]').forEach(c => {
      const gtVal = c.getAttribute('data-filter-gt').toLowerCase();
      if (options.toAll && gtVal === 'all') c.classList.add('active');
      else if (!options.toAll && (gtVal === 'threats' || gtVal === 'suspicious_malicious')) c.classList.add('active');
      else c.classList.remove('active');
    });
  }

  function clearAllFilters() {
    resetAllAlertFilters({ toThreats: true });
    _currentPage = 1;
    loadAlerts(1);
    showToast('Filters reset to default threats (Suspicious & Malicious)', 'info');
  }

  function filterBySource(ip) {
    resetAllAlertFilters({ toAll: true });
    _filterQuery = ip;
    const input = document.getElementById('filter-query');
    if (input) input.value = ip;
    _currentPage = 1;
    switchTab('alerts', { keepFilters: true });
    loadAlerts(1);
    showToast(`Filtered by source: ${ip}`, 'info');
  }

  function filterByDestination(ip) {
    resetAllAlertFilters({ toAll: true });
    _filterQuery = ip;
    const input = document.getElementById('filter-query');
    if (input) input.value = ip;
    _currentPage = 1;
    switchTab('alerts', { keepFilters: true });
    loadAlerts(1);
    showToast(`Filtered by destination: ${ip}`, 'info');
  }

  function filterBySignature(sigKey) {
    resetAllAlertFilters({ toAll: true });
    _filterQuery = sigKey;
    const input = document.getElementById('filter-query');
    if (input) input.value = sigKey;
    _currentPage = 1;
    switchTab('alerts', { keepFilters: true });
    loadAlerts(1);
    showToast(`Filtered by signature: ${sigKey}`, 'info');
  }

  function filterByFlow(flowId) {
    // When switching from correlation, clear all other filters and set Ground Truth to 'all' so all flow-related alerts show properly
    resetAllAlertFilters({ keepFlowId: true, toAll: true });
    _filterFlowId = String(flowId);
    _currentPage = 1;
    switchTab('alerts', { isFlowFilter: true, keepFilters: true });
    loadAlerts(1);
    showToast(`Showing all alerts for Flow #${flowId}`, 'info');
  }

  function filterByGroundTruth(gt) {
    resetAllAlertFilters();
    setFilterGroundTruth(gt);
    switchTab('alerts', { keepFilters: true });
  }

  // ── Controls: Tailing & Actions ──────────────────────────────────────────────

  function setupControls() {
    const clearBtn = document.getElementById('clear-alerts-btn');
    if (clearBtn) {
      clearBtn.addEventListener('click', async () => {
        if (!confirm('Clear all in-memory alerts and reset counters?')) return;
        try {
          await fetch('/api/clear', { method: 'POST' });
        } catch (err) {
          showToast('Failed to clear alerts', 'error');
        }
      });
    }

    const pauseBtn = document.getElementById('pause-stream-btn');
    if (pauseBtn) {
      pauseBtn.addEventListener('click', () => {
        _paused = !_paused;
        pauseBtn.textContent = _paused ? 'Resume Table' : 'Pause Table';
        pauseBtn.classList.toggle('primary', _paused);
        showToast(_paused ? 'Table streaming paused' : 'Table streaming resumed', 'info');
      });
    }

    const exportBtn = document.getElementById('export-alerts-btn');
    if (exportBtn) {
      exportBtn.addEventListener('click', exportAlerts);
    }
  }

  async function exportAlerts() {
    showToast('Exporting filtered alert log...', 'info');
    try {
      const params = new URLSearchParams();
      params.set('limit', '0'); // Return all matching
      if (_filterPriority) params.set('priority', _filterPriority);
      if (_filterProto) params.set('protocol', _filterProto);
      if (_filterGroundTruth && _filterGroundTruth !== 'all') {
        params.set('ground_truth', _filterGroundTruth);
      }
      if (_filterFlowId) params.set('flow_id', _filterFlowId);
      if (_filterQuery) params.set('q', _filterQuery);

      const res = await fetch(`/api/alerts?${params.toString()}`);
      let exportList = _alerts;
      if (res.ok) {
        const data = await res.json();
        exportList = data.alerts || _alerts;
      }

      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportList, null, 2));
      const dlAnchor = document.createElement('a');
      dlAnchor.setAttribute("href", dataStr);
      dlAnchor.setAttribute("download", `snort_alerts_${new Date().toISOString().slice(0, 19)}.json`);
      dlAnchor.click();
      showToast(`Exported ${exportList.length.toLocaleString()} alerts to JSON`, 'success');
    } catch (err) {
      showToast('Export error: ' + err, 'error');
    }
  }

  // ── File Upload ──────────────────────────────────────────────────────────────

  function setupFileUpload() {
    const uploadInput = document.getElementById('log-file-input');
    const uploadBtn = document.getElementById('upload-log-btn');

    if (uploadBtn && uploadInput) {
      uploadBtn.addEventListener('click', () => uploadInput.click());
      uploadInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        showToast(`Uploading ${file.name}...`, 'info');
        try {
          const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData
          });
          const data = await res.json();
          if (res.ok) {
            showToast(`Ingested ${data.alerts_ingested} alerts from ${file.name}`, 'success');
            fetchInitialData();
          } else {
            showToast(`Upload failed: ${data.error}`, 'error');
          }
        } catch (err) {
          showToast(`Upload error: ${err.message}`, 'error');
        }
        uploadInput.value = '';
      });
    }
  }

  // ── Modal Alert Inspector ────────────────────────────────────────────────────

  function setupModal() {
    const modal = document.getElementById('alert-modal');
    const closeBtn = document.getElementById('modal-close-btn');

    if (closeBtn) {
      closeBtn.addEventListener('click', closeModal);
    }

    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
      });
    }

    // Ground truth override buttons
    document.querySelectorAll('.gt-override-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (!_selectedAlert) return;
        const newGt = btn.getAttribute('data-gt');
        try {
          const res = await fetch('/api/ground_truth/override', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert_id: _selectedAlert.id, ground_truth: newGt })
          });
          if (res.ok) {
            _selectedAlert.ground_truth = newGt;
            // update local alert in list
            const local = _alerts.find(a => a.id === _selectedAlert.id);
            if (local) local.ground_truth = newGt;
            inspectAlert(_selectedAlert.id);
            renderAlertsTable();
            showToast(`Ground truth marked as ${newGt}`, 'success');
          }
        } catch (err) {
          showToast('Failed to update ground truth', 'error');
        }
      });
    });
  }

  async function inspectAlert(alertId) {
    let alert = _alerts.find(a => a.id === alertId);
    if (!alert) {
      try {
        const res = await fetch(`/api/alert/${alertId}`);
        if (res.ok) {
          const data = await res.json();
          alert = data.alert;
        }
      } catch (e) {}
    }
    if (!alert) return;
    _selectedAlert = alert;

    const modal = document.getElementById('alert-modal');
    if (!modal) return;

    document.getElementById('modal-alert-id').textContent = `#${alert.id}`;
    document.getElementById('modal-alert-time').textContent = alert.timestamp;
    document.getElementById('modal-alert-msg').textContent = alert.msg;
    document.getElementById('modal-alert-sig').textContent = alert.sig_key;
    document.getElementById('modal-alert-prio').textContent = `Priority ${alert.priority}`;
    document.getElementById('modal-alert-class').textContent = alert.classification;
    document.getElementById('modal-alert-proto').textContent = alert.proto;
    document.getElementById('modal-alert-src').textContent = `${alert.src_ip}${alert.src_port ? ':' + alert.src_port : ''}`;
    document.getElementById('modal-alert-dst').textContent = `${alert.dst_ip}${alert.dst_port ? ':' + alert.dst_port : ''}`;
    document.getElementById('modal-alert-conn').textContent = alert.conn_key;
    document.getElementById('modal-alert-gt').textContent = alert.ground_truth || 'Suspicious';
    document.getElementById('modal-raw-payload').textContent = alert.raw || JSON.stringify(alert, null, 2);

    modal.classList.add('open');
  }

  function closeModal() {
    const modal = document.getElementById('alert-modal');
    if (modal) modal.classList.remove('open');
    _selectedAlert = null;
  }

  // ── Helper Utilities ─────────────────────────────────────────────────────────

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function showToast(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span>${escapeHtml(msg)}</span>`;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, 3200);
  }

  // Public Interface
  return {
    init,
    filterBySource,
    filterByDestination,
    filterBySignature,
    filterByFlow,
    filterByGroundTruth,
    inspectAlert,
    closeModal
  };
})();

// Bootstrap on DOM loaded
document.addEventListener('DOMContentLoaded', () => {
  App.init();
});
