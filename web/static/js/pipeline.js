/**
 * Autonomous Snort 3 Rule Studio & Investigation Engine Frontend
 */

(function() {
  let currentDataset = [];
  let currentReport = null;
  let currentCandidate = null;
  let currentValidation = null;

  // Correlation Graph Viewport Transform State
  let graphZoom = 1;
  let graphPanX = 0;
  let graphPanY = 0;

  // Graph View Mode & Threat Cluster Filter State
  let currentGraphMode = "condensed"; // "condensed" or "full"
  let currentClusterFilter = "all";

  document.addEventListener("DOMContentLoaded", () => {
    initPipelineUI();
  });

  function initPipelineUI() {
    loadDataset();
    loadCandidates();

    // Event Listeners for Toolbar Controls
    const pcapSelect = document.getElementById("pipeline-pcap-select");
    if (pcapSelect) {
      pcapSelect.addEventListener("change", (e) => {
        const cid = e.target.value;
        if (cid) loadReport(cid);
      });
    }

    const runAllBtn = document.getElementById("btn-run-full-pipeline");
    if (runAllBtn) {
      runAllBtn.addEventListener("click", runFullPipeline);
    }

    const refreshDatasetBtn = document.getElementById("btn-refresh-dataset");
    if (refreshDatasetBtn) {
      refreshDatasetBtn.addEventListener("click", refreshDataset);
    }

    const taskABtn = document.getElementById("btn-run-task-a");
    if (taskABtn) {
      taskABtn.addEventListener("click", () => runTaskA(false));
    }

    const taskBBtn = document.getElementById("btn-run-task-b");
    if (taskBBtn) {
      taskBBtn.addEventListener("click", () => runTaskB(false));
    }

    const hdircS1Btn = document.getElementById("btn-run-hdirc-stage1");
    if (hdircS1Btn) {
      hdircS1Btn.addEventListener("click", () => runHdircStage1());
    }

    const advanceS2Btn = document.getElementById("btn-advance-hdirc-stage2");
    if (advanceS2Btn) {
      advanceS2Btn.addEventListener("click", () => runHdircStage2());
    }

    const advanceS3Btn = document.getElementById("btn-advance-hdirc-stage3");
    if (advanceS3Btn) {
      advanceS3Btn.addEventListener("click", () => runHdircStage3());
    }

    const advanceS4Btn = document.getElementById("btn-advance-hdirc-stage4");
    if (advanceS4Btn) {
      advanceS4Btn.addEventListener("click", () => runHdircStage4());
    }

    const advanceS5Btn = document.getElementById("btn-advance-hdirc-stage5");
    if (advanceS5Btn) {
      advanceS5Btn.addEventListener("click", () => runHdircStage5());
    }

    const advanceS6Btn = document.getElementById("btn-advance-hdirc-stage6");
    if (advanceS6Btn) {
      advanceS6Btn.addEventListener("click", () => runHdircStage6());
    }

    const advanceS7Btn = document.getElementById("btn-advance-hdirc-stage7");
    if (advanceS7Btn) {
      advanceS7Btn.addEventListener("click", () => runHdircStage7());
    }

    const viewReportsBtn = document.getElementById("btn-view-generated-reports");
    if (viewReportsBtn) {
      viewReportsBtn.addEventListener("click", openGeneratedReportsModal);
    }

    // Task A Modal refresh button
    const taskARefresh = document.getElementById("task-a-modal-btn-refresh");
    if (taskARefresh) {
      taskARefresh.addEventListener("click", () => runTaskA(true));
    }

    // Task B Modal refresh button
    const taskBRefresh = document.getElementById("task-b-modal-btn-refresh");
    if (taskBRefresh) {
      taskBRefresh.addEventListener("click", () => runTaskB(true));
    }

    // Generated Reports Modal Search Input
    const repSearch = document.getElementById("rep-modal-search");
    if (repSearch) {
      repSearch.addEventListener("input", filterReportsModalOptions);
    }

    // Generated Reports Modal Dropdown Select
    const repSelect = document.getElementById("rep-modal-select");
    if (repSelect) {
      repSelect.addEventListener("change", (e) => {
        const val = e.target.value;
        if (!val) return;
        const idx = generatedReportsList.findIndex(r => r.capture_id === val);
        if (idx >= 0) {
          currentReportIndex = idx;
          loadAndRenderTaskReportsForCapture(val);
        }
      });
    }

    // Generated Reports Prev / Next buttons
    const repPrevBtn = document.getElementById("rep-modal-btn-prev");
    if (repPrevBtn) {
      repPrevBtn.addEventListener("click", () => {
        if (currentReportIndex > 0) {
          currentReportIndex--;
          const cid = generatedReportsList[currentReportIndex].capture_id;
          if (repSelect) repSelect.value = cid;
          loadAndRenderTaskReportsForCapture(cid);
        }
      });
    }

    const repNextBtn = document.getElementById("rep-modal-btn-next");
    if (repNextBtn) {
      repNextBtn.addEventListener("click", () => {
        if (currentReportIndex >= 0 && currentReportIndex < generatedReportsList.length - 1) {
          currentReportIndex++;
          const cid = generatedReportsList[currentReportIndex].capture_id;
          if (repSelect) repSelect.value = cid;
          loadAndRenderTaskReportsForCapture(cid);
        }
      });
    }

    // Option Tab buttons inside Generated Reports modal (Task A vs Task B)
    const genTabBtnA = document.getElementById("gen-rep-tab-btn-a");
    const genTabBtnB = document.getElementById("gen-rep-tab-btn-b");
    const genPaneA = document.getElementById("gen-rep-pane-a");
    const genPaneB = document.getElementById("gen-rep-pane-b");

    if (genTabBtnA && genTabBtnB) {
      genTabBtnA.addEventListener("click", () => {
        currentModalTaskTab = "a";
        genTabBtnA.classList.add("active");
        genTabBtnB.classList.remove("active");
        if (genPaneA) genPaneA.style.display = "flex";
        if (genPaneB) genPaneB.style.display = "none";
      });

      genTabBtnB.addEventListener("click", () => {
        currentModalTaskTab = "b";
        genTabBtnB.classList.add("active");
        genTabBtnA.classList.remove("active");
        if (genPaneB) genPaneB.style.display = "flex";
        if (genPaneA) genPaneA.style.display = "none";
      });
    }

    // Refresh buttons inside Generated Reports modal panes
    const genRefreshA = document.getElementById("gen-rep-a-btn-refresh");
    if (genRefreshA) {
      genRefreshA.addEventListener("click", async () => {
        if (currentReportIndex >= 0 && currentReportIndex < generatedReportsList.length) {
          const cid = generatedReportsList[currentReportIndex].capture_id;
          genRefreshA.disabled = true;
          const origHtml = genRefreshA.innerHTML;
          genRefreshA.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Re-running...';
          try {
            await loadAndRenderTaskReportsForCapture(cid, "a");
          } finally {
            genRefreshA.disabled = false;
            genRefreshA.innerHTML = origHtml;
          }
        }
      });
    }

    const genRefreshB = document.getElementById("gen-rep-b-btn-refresh");
    if (genRefreshB) {
      genRefreshB.addEventListener("click", async () => {
        if (currentReportIndex >= 0 && currentReportIndex < generatedReportsList.length) {
          const cid = generatedReportsList[currentReportIndex].capture_id;
          genRefreshB.disabled = true;
          const origHtml = genRefreshB.innerHTML;
          genRefreshB.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Re-running...';
          try {
            await loadAndRenderTaskReportsForCapture(cid, "b");
          } finally {
            genRefreshB.disabled = false;
            genRefreshB.innerHTML = origHtml;
          }
        }
      });
    }

    const genRuleBtn = document.getElementById("btn-generate-rule");
    if (genRuleBtn) {
      genRuleBtn.addEventListener("click", generateRule);
    }

    const rollbackBtn = document.getElementById("btn-rollback-rules");
    if (rollbackBtn) {
      rollbackBtn.addEventListener("click", promptRollback);
    }

    // Modal Validation & Review Buttons (Inside Candidate Modal)
    const modalValBtn = document.getElementById("modal-btn-validate-rule");
    if (modalValBtn) {
      modalValBtn.onclick = validateRule;
    }
    const modalApproveBtn = document.getElementById("modal-btn-approve-rule");
    if (modalApproveBtn) {
      modalApproveBtn.onclick = () => reviewRule("approve");
    }
    const modalRejectBtn = document.getElementById("modal-btn-reject-rule");
    if (modalRejectBtn) {
      modalRejectBtn.onclick = () => reviewRule("reject");
    }

    // Universal Modal Dismissal: Cross buttons, Backdrop click, and ESC key
    document.addEventListener("click", (e) => {
      const closeBtn = e.target.closest(".modal-close");
      if (closeBtn) {
        const modal = closeBtn.closest(".modal-overlay");
        if (modal) modal.classList.remove("open");
      }
      if (e.target.classList.contains("modal-overlay")) {
        e.target.classList.remove("open");
      }
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        document.querySelectorAll(".modal-overlay.open").forEach(m => m.classList.remove("open"));
      }
    });

    // Correlation Graph Toggle (Visual Graph vs Story Cards)
    const btnGraph = document.getElementById("btn-toggle-corr-graph");
    const btnStory = document.getElementById("btn-toggle-corr-story");
    const graphContainer = document.getElementById("report-correlation-graph-container");
    const storyContainer = document.getElementById("report-correlations-list");
    if (btnGraph && btnStory) {
      btnGraph.onclick = () => {
        btnGraph.classList.add("active");
        btnStory.classList.remove("active");
        if (graphContainer) graphContainer.style.display = "block";
        if (storyContainer) storyContainer.style.display = "none";
      };
      btnStory.onclick = () => {
        btnStory.classList.add("active");
        btnGraph.classList.remove("active");
        if (graphContainer) graphContainer.style.display = "none";
        if (storyContainer) storyContainer.style.display = "flex";
      };
    }

    // Graph Mode Controls: Condensed (Supernodes) vs Full Telemetry
    const btnModeCondensed = document.getElementById("btn-graph-mode-condensed");
    const btnModeFull = document.getElementById("btn-graph-mode-full");
    if (btnModeCondensed && btnModeFull) {
      btnModeCondensed.onclick = () => {
        currentGraphMode = "condensed";
        btnModeCondensed.classList.add("active");
        btnModeFull.classList.remove("active");
        if (currentReport) renderCorrelationGraph(null, currentReport);
      };
      btnModeFull.onclick = () => {
        currentGraphMode = "full";
        btnModeFull.classList.add("active");
        btnModeCondensed.classList.remove("active");
        if (currentReport) renderCorrelationGraph(null, currentReport);
      };
    }

    // Executive SOC Report Controls
    const btnRefreshSoc = document.getElementById("btn-refresh-soc-report");
    if (btnRefreshSoc) {
      btnRefreshSoc.onclick = () => {
        if (!currentReport) return;
        fetchExecutiveSocReport(currentReport.capture_id, currentReport, true);
      };
    }
    const btnSocGenRule = document.getElementById("btn-soc-generate-rule");
    if (btnSocGenRule) {
      btnSocGenRule.onclick = () => {
        const btnMainGen = document.getElementById("btn-generate-rule");
        if (btnMainGen) btnMainGen.click();
      };
    }
    const btnSocHdircS1 = document.getElementById("btn-soc-hdirc-stage1");
    if (btnSocHdircS1) {
      btnSocHdircS1.onclick = () => runHdircStage1();
    }

    // Correlation Graph Zoom & Pan Controls
    const btnZoomIn = document.getElementById("btn-graph-zoom-in");
    const btnZoomOut = document.getElementById("btn-graph-zoom-out");
    const btnZoomReset = document.getElementById("btn-graph-zoom-reset");
    if (btnZoomIn) {
      btnZoomIn.onclick = () => {
        graphZoom = Math.min(graphZoom * 1.25, 3.0);
        applyGraphTransform();
      };
    }
    if (btnZoomOut) {
      btnZoomOut.onclick = () => {
        graphZoom = Math.max(graphZoom / 1.25, 0.4);
        applyGraphTransform();
      };
    }
    if (btnZoomReset) {
      btnZoomReset.onclick = () => {
        graphZoom = 1;
        graphPanX = 0;
        graphPanY = 0;
        applyGraphTransform();
      };
    }

    const svgWrap = document.getElementById("corr-graph-svg-wrapper");
    if (svgWrap) {
      let isDragging = false;
      let startX, startY;
      svgWrap.addEventListener("mousedown", (e) => {
        if (e.target.closest(".corr-graph-node")) return;
        isDragging = true;
        startX = e.clientX - graphPanX;
        startY = e.clientY - graphPanY;
        svgWrap.style.cursor = "grabbing";
      });
      window.addEventListener("mousemove", (e) => {
        if (!isDragging) return;
        graphPanX = e.clientX - startX;
        graphPanY = e.clientY - startY;
        applyGraphTransform();
      });
      window.addEventListener("mouseup", () => {
        if (isDragging) {
          isDragging = false;
          svgWrap.style.cursor = "grab";
        }
      });
    }
  }

  function applyGraphTransform() {
    const root = document.getElementById("corr-graph-root");
    if (root) {
      root.setAttribute("transform", `translate(${graphPanX}, ${graphPanY}) scale(${graphZoom})`);
    }
  }

  // 1. Dataset Management
  async function loadDataset() {
    try {
      const res = await fetch("/api/pipeline/dataset");
      const data = await res.json();
      if (data.status === "success") {
        currentDataset = data.captures || [];
        renderDatasetDropdown(currentDataset);
        renderDatasetTable(currentDataset);
      }
    } catch (err) {
      console.error("Failed to load dataset:", err);
    }
  }

  function renderDatasetDropdown(captures) {
    const sel = document.getElementById("pipeline-pcap-select");
    if (!sel) return;
    const currentVal = sel.value;
    sel.innerHTML = '<option value="">-- Select Ingested PCAP Capture --</option>';

    captures.forEach(c => {
      const opt = document.createElement("option");
      opt.value = c.capture_id;
      opt.textContent = `[${c.capture_id}] ${c.malware_family} (${c.ground_truth}) - ${c.filename}`;
      sel.appendChild(opt);
    });

    if (currentVal) sel.value = currentVal;
    else if (captures.length > 0) {
      sel.value = captures[0].capture_id;
      loadReport(captures[0].capture_id);
    }
  }

  // Requirement 3: PCAP Table without Action column, rows clickable to open popup
  function renderDatasetTable(captures) {
    const tbody = document.getElementById("pipeline-dataset-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const container = document.getElementById("pipeline-dataset-table-container");
    if (container) {
      container.style.overflowX = "auto";
      container.style.maxWidth = "100%";
      container.style.width = "100%";
    }

    if (captures.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No PCAP captures discovered in dataset.</td></tr>';
      return;
    }

    captures.forEach(c => {
      const tr = document.createElement("tr");
      tr.className = "clickable-row";
      tr.dataset.cid = c.capture_id;
      if (currentReport && currentReport.capture_id === c.capture_id) {
        tr.classList.add("active-pcap-row");
      }
      tr.title = "Click to inspect capture & load into Autonomous Studio";
      tr.onclick = () => window.showPcapModal(c);

      const gtBadge = c.ground_truth === "malicious"
        ? '<span class="kpi-pill crit">Malicious</span>'
        : '<span class="kpi-pill ok">Benign</span>';

      tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-weight:600;">${c.capture_id}</td>
        <td><strong>${c.malware_family}</strong></td>
        <td><span class="badge-sig">${c.threat_category}</span></td>
        <td><span class="kpi-pill dim">${c.split}</span></td>
        <td>${gtBadge}</td>
        <td style="font-family:var(--font-mono);">${c.packet_count || '—'}</td>
        <td style="font-size:12px;color:var(--fg-muted);">${c.filename}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  window.showPcapModal = function(c) {
    const modal = document.getElementById("pcap-modal");
    if (!modal) return;

    document.getElementById("pcap-modal-cid").textContent = c.capture_id;
    document.getElementById("pcap-modal-detail-cid").textContent = c.capture_id;
    document.getElementById("pcap-modal-family").textContent = c.malware_family || "Unknown PCAP";
    document.getElementById("pcap-modal-cat").textContent = c.threat_category || "—";
    
    const isMal = c.ground_truth === "malicious";
    const gtEl = document.getElementById("pcap-modal-gt");
    gtEl.textContent = isMal ? "Malicious" : "Benign";
    gtEl.className = isMal ? "kpi-pill crit" : "kpi-pill ok";
    document.getElementById("pcap-modal-detail-truth").textContent = isMal ? "Malicious (Known Attack Traffic)" : "Benign (Baseline Clean Traffic)";
    
    document.getElementById("pcap-modal-detail-split").textContent = (c.split || "training").toUpperCase();
    document.getElementById("pcap-modal-detail-packets").textContent = c.packet_count || "—";
    document.getElementById("pcap-modal-detail-file").textContent = c.filename || "—";

    const closeAndLoad = (force = true) => {
      modal.classList.remove("open");
      window.selectAndAnalyze(c.capture_id, force);
      const repHeader = document.querySelector(".studio-view-header");
      if (repHeader) repHeader.scrollIntoView({ behavior: "smooth" });
    };

    const btnAnalyze = document.getElementById("pcap-modal-btn-analyze");
    if (btnAnalyze) btnAnalyze.onclick = () => closeAndLoad(true);

    const btnInspect = document.getElementById("pcap-modal-btn-inspect-now");
    if (btnInspect) btnInspect.onclick = () => closeAndLoad(false);

    const btnTaskA = document.getElementById("pcap-modal-btn-task-a");
    if (btnTaskA) btnTaskA.onclick = async () => {
      modal.classList.remove("open");
      window.selectAndAnalyze(c.capture_id, false);
      await runTaskA();
    };

    const btnGen = document.getElementById("pcap-modal-btn-generate");
    if (btnGen) btnGen.onclick = async () => {
      modal.classList.remove("open");
      window.selectAndAnalyze(c.capture_id, false);
      await generateRule();
    };

    modal.classList.add("open");
  };

  window.selectAndAnalyze = function(cid, force = false) {
    const sel = document.getElementById("pipeline-pcap-select");
    if (sel) sel.value = cid;
    loadReport(cid, force);
  };

  async function refreshDataset() {
    setLoading(true, "Refreshing dataset and indexing PCAP captures...");
    try {
      const res = await fetch("/api/pipeline/dataset/discover", { method: "POST" });
      const data = await res.json();
      alert(data.message);
      await loadDataset();
    } catch (err) {
      alert("Error refreshing dataset: " + err);
    } finally {
      setLoading(false);
    }
  }

  // 2. Investigation Report & Feature Extraction
  async function loadReport(captureId, forceAnalyze = false) {
    setLoading(true, `Extracting deep features & running correlation on ${captureId}...`);
    try {
      const endpoint = forceAnalyze
        ? `/api/pipeline/analyze/${captureId}`
        : `/api/pipeline/report/${captureId}`;
      const method = forceAnalyze ? "POST" : "GET";
      const res = await fetch(endpoint, { method });
      const data = await res.json();
      if (data.status === "success" && data.report) {
        currentReport = data.report;
        renderInvestigationReport(currentReport);
      }
    } catch (err) {
      console.error("Error loading report:", err);
    } finally {
      setLoading(false);
    }
  }

  function updateActivePcapHighlight(activeCid) {
    const rows = document.querySelectorAll("#pipeline-dataset-tbody tr");
    rows.forEach(tr => {
      if (tr.dataset && tr.dataset.cid === activeCid) {
        tr.classList.add("active-pcap-row");
      } else {
        tr.classList.remove("active-pcap-row");
      }
    });
  }

  function renderInvestigationReport(rep) {
    // 0. Reset Correlation Graph Pan & Zoom and LLM Task Output Panels
    graphZoom = 1;
    graphPanX = 0;
    graphPanY = 0;

    const taskABox = document.getElementById("llm-task-a-output");
    if (taskABox) { taskABox.style.display = "none"; taskABox.innerHTML = ""; }
    const taskBBox = document.getElementById("llm-task-b-output");
    if (taskBBox) { taskBBox.style.display = "none"; taskBBox.innerHTML = ""; }

    updateActivePcapHighlight(rep.capture_id);

    // Reset list scroll positions
    ["report-alert-summary-list", "report-evidence-list", "report-zeek-telemetry-container", "report-network-indicators-list", "report-correlations-list"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.scrollTop = 0;
    });

    // Header Info
    const cidEl = document.getElementById("report-capture-id");
    if (cidEl) cidEl.textContent = rep.capture_id || "—";
    const famEl = document.getElementById("report-malware-family");
    if (famEl) famEl.textContent = rep.malware_family || "Unknown";
    const catEl = document.getElementById("report-threat-cat");
    if (catEl) catEl.textContent = rep.threat_category || "—";
    const snortVerEl = document.getElementById("report-snort-ver");
    if (snortVerEl) snortVerEl.textContent = rep.snort ? rep.snort.version : "3.13.2.0";
    const alertsCountEl = document.getElementById("report-alerts-count");
    if (alertsCountEl) alertsCountEl.textContent = rep.snort ? rep.snort.total_alerts : "0";
    const sigsCountEl = document.getElementById("report-sigs-count");
    if (sigsCountEl) sigsCountEl.textContent = rep.snort ? rep.snort.unique_signatures : "0";

    // 1. Snort Detections & Existing Signatures List (Clickable SID Modal Trigger)
    const alertsBox = document.getElementById("report-alert-summary-list");
    if (alertsBox) {
      alertsBox.innerHTML = "";
      (rep.alert_summary || []).forEach(a => {
        const div = document.createElement("div");
        div.className = "corr-event-item clickable";
        div.title = "Click to inspect actual Snort signature rule and triggering packet evidence";
        div.onclick = () => window.showSidModal(a, rep);
        div.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <strong style="color:var(--crit);">SID ${a.sid}: ${a.msg}</strong>
            <span class="badge-priority p${a.priority}">Priority ${a.priority}</span>
          </div>
          <div style="font-size:12px;color:var(--fg-muted);margin-top:4px;">
            Proto: ${a.protocol} | Count: <strong>${a.count}</strong> | Triggering Packets: [${(a.triggering_packets || []).slice(0, 5).join(", ")}]
            <span style="float:right;color:var(--accent);font-size:11px;">Inspect Rule &rarr;</span>
          </div>
        `;
        alertsBox.appendChild(div);
      });
      if (!rep.alert_summary || rep.alert_summary.length === 0) {
        alertsBox.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;">No Snort community rules triggered. Ready for new rule engineering.</div>';
      }
    }

    // 2. Network Behaviour KPI Gauges
    const flowsCount = rep.network_behaviour && rep.network_behaviour.tcp_connections ? rep.network_behaviour.tcp_connections.length : 0;
    const dnsCount = rep.network_behaviour && rep.network_behaviour.dns_queries ? rep.network_behaviour.dns_queries.length : 0;
    const httpCount = rep.network_behaviour && rep.network_behaviour.http_requests ? rep.network_behaviour.http_requests.length : 0;
    const beaconCount = rep.network_behaviour && rep.network_behaviour.periodic_connections ? rep.network_behaviour.periodic_connections.length : 0;

    const zeekData = (rep.network_behaviour && rep.network_behaviour.zeek) ? rep.network_behaviour.zeek : {};
    const zeekConns = zeekData.total_connections || 0;
    const zeekFiles = (zeekData.files_transferred || []).length;
    const zeekCerts = (zeekData.ssl_certificates || []).length;

    const fCountEl = document.getElementById("report-flows-count");
    if (fCountEl) fCountEl.textContent = flowsCount;
    const dCountEl = document.getElementById("report-dns-count");
    if (dCountEl) dCountEl.textContent = dnsCount;
    const hCountEl = document.getElementById("report-http-count");
    if (hCountEl) hCountEl.textContent = httpCount;
    const bCountEl = document.getElementById("report-beacon-count");
    if (bCountEl) bCountEl.textContent = beaconCount;

    const zcEl = document.getElementById("report-zeek-conns-count");
    if (zcEl) zcEl.textContent = zeekConns;
    const zfEl = document.getElementById("report-zeek-files-count");
    if (zfEl) zfEl.textContent = zeekFiles;
    const zcertEl = document.getElementById("report-zeek-certs-count");
    if (zcertEl) zcertEl.textContent = zeekCerts;

    // 3. Zeek Session & Artifact Telemetry Container (Clickable Zeek Modal Trigger)
    const zeekBox = document.getElementById("report-zeek-telemetry-container");
    if (zeekBox) {
      zeekBox.innerHTML = "";
      if (zeekConns === 0 && zeekFiles === 0 && zeekCerts === 0) {
        zeekBox.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;">No Zeek session telemetry extracted.</div>';
      } else {
        const statesHtml = Object.entries(zeekData.connection_states || {}).map(([s, cnt]) =>
          `<span class="kpi-pill dim badge-zeek-clickable" style="margin-right:4px;" title="Click to view Zeek conn.log for state ${s}" onclick="window.showZeekState('${s}')"><strong>${s}</strong>: ${cnt}</span>`
        ).join("");

        const svcHtml = Object.entries(zeekData.detected_services || {}).map(([svc, cnt]) =>
          `<span class="kpi-pill ok badge-zeek-clickable" style="margin-right:4px;" title="Click to view Zeek ${svc} protocol log" onclick="window.showZeekService('${svc}')"><strong>${svc.toUpperCase()}</strong>: ${cnt}</span>`
        ).join("");

        const statsDiv = document.createElement("div");
        statsDiv.className = "corr-event-item";
        statsDiv.innerHTML = `
          <div style="font-size:11.5px;color:var(--fg-muted);margin-bottom:4px;">Zeek States &amp; Protocols (Click to inspect log):</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px;">${statesHtml || '<span style="color:var(--fg-muted);">None</span>'}</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px;">${svcHtml || '<span style="color:var(--fg-muted);">None</span>'}</div>
        `;
        zeekBox.appendChild(statsDiv);

        (zeekData.files_transferred || []).slice(0, 5).forEach(f => {
          const fDiv = document.createElement("div");
          fDiv.className = "corr-event-item clickable";
          fDiv.style.borderLeft = "3px solid var(--warn)";
          fDiv.title = "Click to inspect Zeek files.log record";
          fDiv.onclick = () => window.showZeekModal("files.log", f, `Zeek Extracted File: ${f.filename || f.fuid}`);
          fDiv.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong style="color:var(--fg-bright);font-size:12px;">📁 ${f.filename || 'Unnamed Stream'}</strong>
              <span class="kpi-pill warn">${f.mime_type || 'Unknown MIME'}</span>
            </div>
            <div style="font-size:11px;color:var(--fg-muted);margin-top:2px;">
              Size: ${f.total_bytes ? (f.total_bytes / 1024).toFixed(1) + ' KB' : '0 B'} | Server: ${f.resp_h || '—'} | FUID: ${f.fuid}
              <span style="float:right;color:var(--accent);">Inspect &rarr;</span>
            </div>
          `;
          zeekBox.appendChild(fDiv);
        });

        (zeekData.ssl_certificates || []).slice(0, 3).forEach(c => {
          const cDiv = document.createElement("div");
          cDiv.className = "corr-event-item clickable";
          cDiv.style.borderLeft = "3px solid var(--accent)";
          cDiv.title = "Click to inspect Zeek x509.log / ssl.log record";
          cDiv.onclick = () => window.showZeekModal("ssl.log", c, `Zeek X.509 Certificate: ${c.subject || 'Certificate'}`);
          const selfSignedBadge = c.is_self_signed ? '<span class="badge-priority p1" style="font-size:10px;">SELF-SIGNED</span>' : '';
          cDiv.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong style="color:var(--accent);font-size:12px;">🔒 ${c.subject || 'Unknown Subject'}</strong>
              ${selfSignedBadge}
            </div>
            <div style="font-size:11px;color:var(--fg-muted);margin-top:2px;">
              Issuer: ${c.issuer || '—'} | Alg: ${c.sig_alg || '—'}
              <span style="float:right;color:var(--accent);">Inspect &rarr;</span>
            </div>
          `;
          zeekBox.appendChild(cDiv);
        });
      }
    }

    // 4. Render Visual Correlation Graph (Requirement 5: Full Horizontal Available Width)
    renderCorrelationGraph(rep.event_graph, rep);

    // Render Executive AI SOC Investigation Report
    if (rep.executive_soc_report) {
      renderExecutiveSocReport(rep.executive_soc_report, rep);
    } else {
      fetchExecutiveSocReport(rep.capture_id, rep, false);
    }

    const corrBox = document.getElementById("report-correlations-list");
    if (corrBox) {
      corrBox.innerHTML = "";
      (rep.correlations || []).forEach(c => {
        const div = document.createElement("div");
        div.className = "corr-chain-card";
        div.innerHTML = `
          <div class="corr-chain-title" style="display:flex;justify-content:space-between;">
            <span>${c.type}</span>
            <span class="kpi-pill warn">${(c.confidence || 'HIGH').toUpperCase()} CONFIDENCE</span>
          </div>
          <p style="font-size:12.5px;color:var(--fg-secondary);margin:6px 0;">${c.description}</p>
          <div style="font-size:11.5px;font-family:var(--font-mono);color:var(--ok);">
            Evidence: ${c.evidence_summary || 'Packets ' + JSON.stringify(c.evidence_packets || [])}
          </div>
        `;
        corrBox.appendChild(div);
      });
      if (!rep.correlations || rep.correlations.length === 0) {
        corrBox.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;">No automated attack chain correlations identified.</div>';
      }
    }

    // 5. Packet Evidence Drawer
    const evBox = document.getElementById("report-evidence-list");
    if (evBox) {
      evBox.innerHTML = "";
      (rep.packet_evidence || []).slice(0, 15).forEach(e => {
        const div = document.createElement("div");
        div.className = "corr-event-item";
        div.innerHTML = `
          <span style="font-family:var(--font-mono);font-weight:600;color:var(--fg-bright);">Packet #${e.pkt_num}</span>
          <span class="kpi-pill dim" style="margin-left:6px;">${e.proto}</span>
          <div style="font-size:12px;margin-top:3px;">${e.summary}</div>
        `;
        evBox.appendChild(div);
      });
    }

    // 6. Network Indicators & Behavioral Artifacts Drawer (Bottom-Right Panel)
    const indBox = document.getElementById("report-network-indicators-list");
    if (indBox) {
      indBox.innerHTML = "";
      const nb = rep.network_behaviour || {};
      const periodic = nb.periodic_connections || [];
      const httpReqs = nb.http_requests || [];
      const dnsQueries = nb.dns_queries || [];
      const tcpConns = nb.tcp_connections || [];

      const items = [];

      // 1. Periodic C2 Beaconing Indicators
      periodic.forEach(p => {
        items.push({
          badge: "C2 BEACONING",
          badgeCls: "kpi-pill crit",
          title: `Cadence: ${p.mean_interval_sec}s (±${p.std_dev || 0}s jitter)`,
          details: `Flow: <span class="badge-sig">${p.src_ip} &rarr; ${p.dst_ip}:${p.dst_port}</span> (${p.packet_count || (p.packets || []).length} pkts: [${(p.packets || []).slice(0, 8).join(', ')}])`,
          type: "beacon",
          data: p,
          logType: "conn.log",
          modalTitle: `C2 Periodic Beaconing: ${p.src_ip} &rarr; ${p.dst_ip}:${p.dst_port}`
        });
      });

      // 2. HTTP Request Indicators & Injected Payloads
      httpReqs.slice(0, 10).forEach(h => {
        const ua = h.user_agent ? `<div style="font-size:11px;color:var(--fg-muted);margin-top:2px;word-break:break-all;"><strong>UA:</strong> <code>${h.user_agent}</code></div>` : "";
        items.push({
          badge: `HTTP ${h.method || 'REQ'}`,
          badgeCls: "kpi-pill warn",
          title: `<strong>${h.method || 'GET'} ${h.uri || '/'}</strong> (Host: <code>${h.host || '—'}</code>)`,
          details: `5-Tuple: ${h.src_ip} &rarr; ${h.dst_ip}:${h.dst_port} ${h.pkt_num ? `(Packet #${h.pkt_num})` : ''}${ua}`,
          type: "http",
          data: h,
          logType: "http.log",
          modalTitle: `HTTP Transaction: ${h.method || 'GET'} ${h.uri || '/'}`
        });
      });

      // 3. DNS Resolutions
      const seenDns = new Set();
      dnsQueries.forEach(q => {
        if (q.query_name && !seenDns.has(q.query_name) && items.length < 20) {
          seenDns.add(q.query_name);
          const resolved = q.resolved_ip || "Pending / Unresolved";
          items.push({
            badge: "DNS LOOKUP",
            badgeCls: "kpi-pill dim",
            title: `<strong>${q.query_name}</strong> (Type ${q.query_type || 'A'})`,
            details: `Resolved: <span class="badge-sig">${resolved}</span> ${q.entropy ? `| Entropy: ${q.entropy}` : ''} ${q.pkt_num ? `(Pkt #${q.pkt_num})` : ''}`,
            type: "dns",
            data: q,
            logType: "dns.log",
            modalTitle: `DNS Query: ${q.query_name}`
          });
        }
      });

      // 4. Transport Connections (if list needs more context)
      if (items.length < 5) {
        tcpConns.slice(0, 5 - items.length).forEach(c => {
          items.push({
            badge: `${c.proto || 'TCP'} FLOW`,
            badgeCls: "kpi-pill ok",
            title: `<span class="badge-sig">${c.src_ip}:${c.src_port} &rarr; ${c.dst_ip}:${c.dst_port}</span>`,
            details: `Duration: ${c.duration_sec || 0}s | Packets: ${c.packet_count || 0} | Bytes: ${(c.byte_count || 0).toLocaleString()}`,
            type: "flow",
            data: c,
            logType: "conn.log",
            modalTitle: `Flow Telemetry: ${c.flow_id || `${c.src_ip} -> ${c.dst_ip}`}`
          });
        });
      }

      if (items.length === 0) {
        indBox.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;">No extracted network indicators in this capture.</div>';
      } else {
        items.forEach(it => {
          const div = document.createElement("div");
          div.className = "corr-event-item clickable";
          div.style.cursor = "pointer";
          div.title = "Click to inspect artifact log details in popup";
          div.onclick = () => window.showZeekModal(it.logType, it.data, it.modalTitle);
          div.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">
              <span style="font-size:12px;color:var(--fg-bright);">${it.title}</span>
              <span class="${it.badgeCls}">${it.badge}</span>
            </div>
            <div style="font-size:11.5px;color:var(--fg-secondary);line-height:1.4;">
              ${it.details}
            </div>
          `;
          indBox.appendChild(div);
        });
      }
    }
  }

  // -----------------------------------------------------------------
  // Executive AI SOC Investigation Report Component
  // -----------------------------------------------------------------
  async function fetchExecutiveSocReport(captureId, rep, forceRefresh = false) {
    const summaryEl = document.getElementById("soc-executive-summary-text");
    if (summaryEl) summaryEl.innerHTML = '<span style="color:var(--fg-muted);font-style:italic;">Synthesizing Executive AI SOC Report via Autonomous Engine...</span>';
    try {
      const url = `/api/pipeline/soc_report/${captureId}${forceRefresh ? '?refresh=true' : ''}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.status === "success" && data.soc_report) {
        rep.executive_soc_report = data.soc_report;
        renderExecutiveSocReport(data.soc_report, rep);
      }
    } catch (err) {
      console.error("Failed to fetch SOC report:", err);
      if (summaryEl) summaryEl.textContent = "Unable to load Executive AI SOC report.";
    }
  }

  function renderExecutiveSocReport(soc, rep) {
    if (!soc) return;

    // Verdict and Severity Pills
    const verdictPill = document.getElementById("soc-verdict-pill");
    if (verdictPill) {
      verdictPill.textContent = soc.verdict || "ANALYSIS COMPLETE";
      verdictPill.className = "kpi-pill " + (soc.verdict && soc.verdict.includes("MALICIOUS") ? "crit" : (soc.verdict && soc.verdict.includes("BENIGN") ? "ok" : "warn"));
    }

    const severityPill = document.getElementById("soc-severity-pill");
    if (severityPill) {
      const sev = (soc.severity || "MEDIUM").toUpperCase();
      severityPill.textContent = `${sev} SEVERITY`;
      severityPill.className = "kpi-pill " + (sev === "CRITICAL" ? "crit" : (sev === "HIGH" ? "warn" : "ok"));
    }

    const stageSubtitle = document.getElementById("soc-stage-subtitle");
    if (stageSubtitle) {
      stageSubtitle.textContent = `Attack Stage: ${soc.attack_stage || 'Unknown'} · Confidence: ${(soc.confidence || 'HIGH').toUpperCase()} · Patient Zero: ${soc.patient_zero || 'N/A'}`;
    }

    // Executive Summary Text
    const summaryText = document.getElementById("soc-executive-summary-text");
    if (summaryText) {
      summaryText.textContent = soc.executive_summary || "Investigation complete.";
    }

    // Pivots Container
    const pivotsBox = document.getElementById("soc-pivots-container");
    if (pivotsBox) {
      pivotsBox.innerHTML = "";
      let pivots = soc.top_pivots || [];
      if ((!pivots || pivots.length === 0) && soc.patient_zero) {
        pivots = [
          { label: soc.patient_zero, role: "Compromised Host (Patient Zero)", pagerank_score: 0.35 },
          { label: soc.primary_attacker_source || "External Threat", role: "Attacker Ingress", pagerank_score: 0.20 }
        ];
        (soc.c2_infrastructure || []).forEach(c => pivots.push({ label: c, role: "Command & Control", pagerank_score: 0.15 }));
      }
      pivots.slice(0, 4).forEach(p => {
        const div = document.createElement("div");
        div.style.cssText = "display:flex;justify-content:space-between;align-items:center;padding:5px 8px;background:var(--bg-elev-1);border-radius:4px;font-size:12px;";
        const isPz = p.role && (p.role.includes("Patient Zero") || p.role.includes("Target"));
        div.innerHTML = `
          <div>
            <span style="font-weight:600;font-family:var(--font-mono);color:${isPz ? 'var(--crit)' : 'var(--accent)'};">${isPz ? '🎯 ' : ''}${p.label || p.node_id}</span>
            <span style="font-size:10.5px;color:var(--fg-muted);margin-left:6px;">(${p.role})</span>
          </div>
          <span class="kpi-pill ok" style="font-size:9.5px;">PPR: ${Number(p.pagerank_score || 0).toFixed(3)}</span>
        `;
        pivotsBox.appendChild(div);
      });
      if (pivots.length === 0) {
        pivotsBox.innerHTML = '<div style="color:var(--fg-muted);font-size:12px;font-style:italic;">No distinct pivot entities identified.</div>';
      }
    }

    // MITRE ATT&CK Matrix
    const mitreBox = document.getElementById("soc-mitre-container");
    if (mitreBox) {
      mitreBox.innerHTML = "";
      (soc.mitre_attack || []).forEach(m => {
        const div = document.createElement("div");
        div.className = "kpi-pill warn";
        div.style.cssText = "font-size:11px;padding:3px 8px;";
        div.title = `${m.tactic}: ${m.technique_name}`;
        div.innerHTML = `<strong>${m.technique_id}</strong> ${m.technique_name}`;
        mitreBox.appendChild(div);
      });
      if (!soc.mitre_attack || soc.mitre_attack.length === 0) {
        mitreBox.innerHTML = '<div style="color:var(--fg-muted);font-size:12px;font-style:italic;">No MITRE techniques mapped.</div>';
      }
    }

    // Attack Timeline
    const timelineBox = document.getElementById("soc-timeline-container");
    if (timelineBox) {
      timelineBox.innerHTML = "";
      (soc.attack_timeline || []).forEach(step => {
        const div = document.createElement("div");
        div.style.cssText = "display:flex;gap:8px;font-size:11.5px;line-height:1.4;";
        div.innerHTML = `
          <span style="font-weight:bold;color:var(--crit);min-width:18px;">${step.step || '•'}</span>
          <div>
            <strong style="color:var(--fg-primary);">${step.phase}:</strong>
            <span style="color:var(--fg-secondary);">${step.description}</span>
          </div>
        `;
        timelineBox.appendChild(div);
      });
      if (!soc.attack_timeline || soc.attack_timeline.length === 0) {
        timelineBox.innerHTML = '<div style="color:var(--fg-muted);font-size:12px;font-style:italic;">No sequential milestones recorded.</div>';
      }
    }

    // Rule Directive Text
    const directiveText = document.getElementById("soc-rule-directive-text");
    if (directiveText) {
      directiveText.textContent = (soc.recommended_snort_rules || []).join(" · ") || "Autonomous rule generation ready.";
    }
  }

  // -----------------------------------------------------------------
  // Interactive Visual Correlation Graph Renderer
  // -----------------------------------------------------------------
  function renderCorrelationGraph(eventGraph, rep) {
    const svg = document.getElementById("correlation-graph-svg");
    const statsEl = document.getElementById("corr-graph-stats");
    if (!svg) return;

    // Choose graph view: Condensed Supernodes vs Full Telemetry
    let targetGraph = (currentGraphMode === "full" && rep && rep.raw_graph && rep.raw_graph.nodes && rep.raw_graph.nodes.length > 0)
      ? rep.raw_graph
      : (rep && rep.event_graph && rep.event_graph.nodes ? rep.event_graph : (eventGraph || { nodes: [], links: [] }));

    const allNodes = targetGraph.nodes || [];
    const allLinks = targetGraph.links || [];

    // Populate Cluster Filter Tabs
    const clusterTabs = document.getElementById("corr-graph-cluster-tabs");
    if (clusterTabs && rep && rep.graph_summary) {
      clusterTabs.innerHTML = "";
      const clusters = rep.graph_summary.clusters || [];
      if (clusters.length > 1) {
        const allBtn = document.createElement("button");
        allBtn.className = "studio-btn sb-btn " + (currentClusterFilter === "all" ? "active" : "");
        allBtn.style.cssText = "font-size:10px;padding:2px 8px;height:24px;";
        allBtn.textContent = `All (${allNodes.length})`;
        allBtn.onclick = () => {
          currentClusterFilter = "all";
          renderCorrelationGraph(null, rep);
        };
        clusterTabs.appendChild(allBtn);

        clusters.forEach((cl, i) => {
          const btn = document.createElement("button");
          btn.className = "studio-btn sb-btn " + (currentClusterFilter === cl.cluster_id ? "active" : "");
          btn.style.cssText = "font-size:10px;padding:2px 8px;height:24px;";
          btn.textContent = `${cl.title.replace('Threat Cluster ', 'C')} (${cl.nodes_count})`;
          btn.onclick = () => {
            currentClusterFilter = cl.cluster_id;
            renderCorrelationGraph(null, rep);
          };
          clusterTabs.appendChild(btn);
        });
      }
    }

    // Apply Cluster Filter
    let activeNodes = allNodes;
    let activeLinks = allLinks;
    if (currentClusterFilter !== "all") {
      activeNodes = activeNodes.filter(n => n.cluster_id === currentClusterFilter);
      const activeIds = new Set(activeNodes.map(n => n.id));
      activeLinks = activeLinks.filter(l => activeIds.has(l.source) && activeIds.has(l.target));
    }

    if (statsEl) {
      const modeLabel = currentGraphMode === "condensed" ? "Condensed" : "Full Telemetry";
      statsEl.textContent = `${activeNodes.length} Nodes · ${activeLinks.length} Relations (${modeLabel})`;
    }

    if (activeNodes.length === 0) {
      svg.innerHTML = `
        <text x="50%" y="50%" text-anchor="middle" dominant-baseline="middle" fill="var(--fg-muted)" font-size="13" font-style="italic">
          No correlation graph nodes available in this view.
        </text>
      `;
      return;
    }

    // If in full mode with extreme density (>40 nodes), apply smart alert-centered connected filter
    if (currentGraphMode === "full" && activeNodes.length > 35) {
      const alertIds = new Set(activeNodes.filter(n => n.type === "alert").map(n => n.id));
      const connected = new Set(alertIds);
      activeLinks.forEach(l => {
        if (alertIds.has(l.source)) connected.add(l.target);
        if (alertIds.has(l.target)) connected.add(l.source);
      });
      activeLinks.forEach(l => {
        if (connected.has(l.source)) connected.add(l.target);
        if (connected.has(l.target)) connected.add(l.source);
      });
      activeNodes = activeNodes.filter(n => connected.has(n.id)).slice(0, 32);
      const activeIds = new Set(activeNodes.map(n => n.id));
      activeLinks = activeLinks.filter(l => activeIds.has(l.source) && activeIds.has(l.target));
    }

    // Layer assignments across wide horizontal canvas
    const nodeMap = new Map();
    activeNodes.forEach(n => {
      let layer = 1;
      const type = n.type || "";
      const id = n.id || "";
      if (type === "alert" || type.includes("alert")) {
        layer = 2;
      } else if (type === "flow" || type.includes("http") || type.includes("dns")) {
        layer = 1;
      } else if (type.includes("domain") || (type.includes("ip") && !id.includes("192.168.1.50") && !id.includes("10."))) {
        layer = 0;
      } else {
        layer = 3;
      }
      n.layer = layer;
      nodeMap.set(n.id, n);
    });

    const layers = [[], [], [], []];
    activeNodes.forEach(n => {
      layers[n.layer].push(n);
    });

    const width = 1180;
    const maxLayerCount = Math.max(1, ...layers.map(l => l.length));
    const minCardSpacing = 44; // Minimum 44px vertical space per card (card height 36px) prevents overlap
    const height = Math.max(380, (maxLayerCount + 1) * minCardSpacing);
    const layerX = [140, 440, 740, 1020];

    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

    layers.forEach((layerNodes, lIdx) => {
      const count = layerNodes.length;
      const gap = height / (count + 1);
      layerNodes.forEach((node, idx) => {
        node.x = layerX[lIdx];
        node.y = Math.round((idx + 1) * gap);
      });
    });

    const typeColors = {
      alert: "#ef4444",
      entity_ip: "#3b82f6",
      flow: "#8b5cf6",
      entity_domain: "#14b8a6",
      domain: "#14b8a6",
      dns_event: "#06b6d4",
      http_event: "#f59e0b",
      http: "#f59e0b",
      entity_file: "#ec4899",
      entity_cert: "#10b981"
    };

    const typeIcons = {
      alert: "⚡",
      entity_ip: "🖥️",
      flow: "⇄",
      entity_domain: "🌐",
      domain: "🌐",
      dns_event: "📡",
      http_event: "📄",
      http: "📄",
      entity_file: "📦",
      entity_cert: "🔒"
    };

    let svgHtml = `
      <defs>
        <marker id="arrowhead" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#64748b" />
        </marker>
        <marker id="arrowhead-crit" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#ef4444" />
        </marker>
        <marker id="arrowhead-warn" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#f59e0b" />
        </marker>
        <filter id="glow-crit" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="3.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <g id="corr-graph-root" transform="translate(${graphPanX}, ${graphPanY}) scale(${graphZoom})">
    `;

    // Render Curved Directed Links
    activeLinks.forEach(l => {
      const src = nodeMap.get(l.source);
      const tgt = nodeMap.get(l.target);
      if (!src || !tgt) return;

      const isAttackPath = !!l.is_attack_path;
      const isAlert = (src.type === "alert" || tgt.type === "alert");
      const strokeColor = isAttackPath ? "#ef4444" : (isAlert ? "rgba(239, 68, 68, 0.75)" : "rgba(100, 116, 139, 0.45)");
      const strokeWidth = isAttackPath ? 2.8 : (isAlert ? 2.0 : 1.4);
      const marker = (isAttackPath || isAlert) ? "url(#arrowhead-crit)" : "url(#arrowhead)";
      const filterAttr = isAttackPath ? 'filter="url(#glow-crit)"' : '';

      const midX = (src.x + tgt.x) / 2;
      const pathData = `M ${src.x} ${src.y} C ${midX} ${src.y}, ${midX} ${tgt.y}, ${tgt.x} ${tgt.y}`;

      svgHtml += `
        <path d="${pathData}" fill="none" stroke="${strokeColor}" stroke-width="${strokeWidth}" marker-end="${marker}" class="corr-graph-edge ${isAttackPath ? 'attack-path-edge' : ''}" ${filterAttr} />
      `;

      if (l.relation) {
        const lblX = Math.round(midX);
        const lblY = Math.round((src.y + tgt.y) / 2) - 4;
        const cleanRel = l.relation.replace(/_/g, " ").toLowerCase();
        svgHtml += `
          <rect x="${lblX - 35}" y="${lblY - 9}" width="70" height="13" rx="3" fill="var(--bg-elev-1)" stroke="${isAttackPath ? '#ef4444' : 'var(--border-subtle)'}" stroke-width="${isAttackPath ? 1.0 : 0.8}" opacity="0.9" />
          <text x="${lblX}" y="${lblY}" text-anchor="middle" dominant-baseline="central" fill="${isAttackPath ? '#ef4444' : 'var(--fg-muted)'}" font-size="8.5" font-weight="${isAttackPath ? '700' : 'normal'}" font-family="var(--font-sans)">
            ${cleanRel}
          </text>
        `;
      }
    });

    // Render Node Cards
    activeNodes.forEach(n => {
      const color = typeColors[n.type] || "#94a3b8";
      const icon = typeIcons[n.type] || "•";
      const rawLabel = (n.label || n.id || "").replace(/^(Alert:\s*|HTTP:\s*|Flow:\s*|Flows:\s*|DNS:\s*)/i, "");
      const shortLabel = rawLabel.length > 21 ? rawLabel.slice(0, 20) + "…" : rawLabel;

      const cardW = 142;
      const cardH = 36;
      const cardX = n.x - (cardW / 2);
      const cardY = n.y - (cardH / 2);

      const isAlert = n.type === "alert" || (n.id && n.id.startsWith("alert"));
      const isSuper = !!n.is_supernode;
      const ppr = Number(n.ppr_score || 0);

      // Supernode Badge count
      const foldCount = (n.details && (n.details.total_flows || n.details.query_count || n.details.count || n.count)) || "";

      svgHtml += `
        <g class="corr-graph-node" onclick="window.handleGraphNodeClick('${n.id}')" data-id="${n.id}" style="cursor:pointer;">
          <rect x="${cardX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="6" ry="6" 
                fill="var(--bg-elev-2)" stroke="${color}" stroke-width="${isAlert ? 2.2 : (isSuper ? 1.8 : 1.2)}" 
                ${isAlert ? 'stroke-dasharray="none"' : (isSuper ? 'stroke-dasharray="3,2"' : '')} />
          
          <text x="${cardX + 11}" y="${cardY + 23}" font-size="12">${icon}</text>
          
          <text x="${cardX + 28}" y="${cardY + 16}" fill="var(--fg-primary)" font-size="10.5" font-weight="600" font-family="var(--font-sans)">
            ${shortLabel}
          </text>
          
          <text x="${cardX + 28}" y="${cardY + 29}" fill="var(--fg-muted)" font-size="8.5" font-family="var(--font-mono)">
            ${(n.type || '').replace('_event', '').replace('entity_', '').toUpperCase()}
          </text>
      `;

      // Supernode Pill Badge [Nx]
      if (isSuper && foldCount) {
        svgHtml += `
          <rect x="${cardX + cardW - 32}" y="${cardY - 6}" width="30" height="13" rx="3" fill="#38bdf8" />
          <text x="${cardX + cardW - 17}" y="${cardY + 3.5}" fill="#0f172a" font-size="8.5" font-weight="800" text-anchor="middle" font-family="var(--font-sans)">${foldCount}x</text>
        `;
      }

      // PageRank Pivot Indicator
      if (ppr >= 0.08) {
        svgHtml += `
          <rect x="${cardX + cardW - (isSuper ? 68 : 36)}" y="${cardY - 6}" width="32" height="13" rx="3" fill="var(--bg-elev-1)" stroke="var(--ok)" stroke-width="0.8" />
          <text x="${cardX + cardW - (isSuper ? 52 : 20)}" y="${cardY + 3.5}" fill="var(--ok)" font-size="7.5" font-weight="700" font-family="var(--font-mono)" text-anchor="middle">PPR ${ppr.toFixed(2)}</text>
        `;
      }

      svgHtml += `</g>`;
    });

    svgHtml += `</g>`;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.innerHTML = svgHtml;
  }

  window.handleGraphNodeClick = function(nodeId) {
    if (!currentReport) return;
    const targetGraph = (currentGraphMode === "full" && currentReport.raw_graph && currentReport.raw_graph.nodes) 
      ? currentReport.raw_graph 
      : (currentReport.event_graph || {});
    const node = (targetGraph.nodes || []).find(n => n.id === nodeId);
    if (!node) return;

    if (node.is_supernode) {
      window.showZeekModal("supernode.aggregate", node.details, `Supernode Record: ${node.label}`);
      return;
    }

    if (node.type === "alert") {
      const sid = (node.details && node.details.sid) || parseInt(nodeId.split(":")[2]);
      const alertItem = (currentReport.alert_summary || []).find(a => a.sid === sid) || {
        sid: sid,
        msg: (node.details && node.details.evidence && node.details.evidence.msg) || node.label,
        priority: (node.details && node.details.priority) || 1,
        protocol: (node.details && node.details.evidence && node.details.evidence.proto) || "TCP",
        count: 1,
        triggering_packets: (node.details && node.details.evidence && node.details.evidence.packets) || []
      };
      window.showSidModal(alertItem, currentReport);
    } else if (node.type === "flow") {
      const flow = (currentReport.network_behaviour && currentReport.network_behaviour.tcp_connections || []).find(f => f.flow_id === node.id || node.id.includes(f.flow_id)) || node.details;
      window.showZeekModal("conn.log", flow || node, `Zeek Flow Record: ${node.label}`);
    } else if (node.type.includes("http")) {
      const pkt = parseInt(nodeId.split(":")[1]);
      const httpReq = (currentReport.network_behaviour && currentReport.network_behaviour.http_requests || []).find(h => h.pkt_num === pkt) || node.details;
      window.showZeekModal("http.log", httpReq || node, `Zeek HTTP Record #${pkt}`);
    } else if (node.type.includes("ip")) {
      const ip = (node.details && node.details.ip) || node.label;
      const related = (currentReport.network_behaviour && currentReport.network_behaviour.tcp_connections || []).filter(c => c.src_ip === ip || c.dst_ip === ip);
      window.showZeekModal("conn.log", { ip: ip, active_flows_count: related.length, connections: related }, `Host Telemetry Profile: ${ip}`);
    }
  };

  // 3. Zeek Log Popup Modal Handler (Requirement 1)
  window.showZeekModal = function(logType, logData, customTitle) {
    const modal = document.getElementById("zeek-modal");
    if (!modal) return;
    document.getElementById("zeek-modal-title").textContent = customTitle || `Zeek Telemetry Log Inspection (${logType})`;
    document.getElementById("zeek-modal-type").textContent = logType;

    const summaryEl = document.getElementById("zeek-modal-summary");
    const fieldsEl = document.getElementById("zeek-modal-fields");
    const rawEl = document.getElementById("zeek-modal-raw");

    fieldsEl.innerHTML = "";
    rawEl.textContent = JSON.stringify(logData, null, 2);

    if (logType.includes("conn") || logData.conn_state || logData.flow_id) {
      summaryEl.innerHTML = `TCP/IP Stateful Connection: <span class="badge-sig">${logData.orig_h || logData.src_ip || '—'}:${logData.orig_p || logData.src_port || '—'} &rarr; ${logData.resp_h || logData.dst_ip || '—'}:${logData.resp_p || logData.dst_port || '—'}</span>`;
      const fields = [
        ["Connection State", logData.conn_state || logData.zeek_conn_state || "—"],
        ["Service Protocol", (logData.service || logData.zeek_service || "other").toUpperCase()],
        ["Session UID", logData.uid || "—"],
        ["Duration", (logData.duration || logData.duration_sec || 0) + " sec"],
        ["Origin Bytes", logData.orig_bytes || logData.byte_count || 0],
        ["Response Bytes", logData.resp_bytes || 0],
        ["Origin Packets", logData.orig_pkts || logData.packet_count || 0],
        ["Response Packets", logData.resp_pkts || 0]
      ];
      fields.forEach(([k, v]) => {
        fieldsEl.innerHTML += `<div class="detail-item"><div class="detail-item-label">${k}</div><div class="detail-item-val">${v}</div></div>`;
      });
    } else if (logType.includes("files") || logData.fuid) {
      summaryEl.innerHTML = `Extracted File Artifact: <strong style="color:var(--accent);">${logData.filename || 'Stream ' + (logData.fuid || '')}</strong>`;
      const fields = [
        ["File UID (FUID)", logData.fuid || "—"],
        ["Session UID", logData.uid || "—"],
        ["MIME Type", logData.mime_type || "Unknown"],
        ["Total Size", (logData.total_bytes || 0) + " bytes"],
        ["Source Channel", logData.source || "HTTP/TLS"],
        ["Server Host", logData.resp_h || "—"]
      ];
      fields.forEach(([k, v]) => {
        fieldsEl.innerHTML += `<div class="detail-item"><div class="detail-item-label">${k}</div><div class="detail-item-val">${v}</div></div>`;
      });
    } else if (logType.includes("ssl") || logData.subject || logData.server_name) {
      summaryEl.innerHTML = `TLS / SSL Certificate: <strong style="color:var(--accent);">${logData.subject || logData.server_name || 'TLS Session'}</strong>`;
      const fields = [
        ["Subject", logData.subject || "—"],
        ["Issuer", logData.issuer || "—"],
        ["Self-Signed", logData.is_self_signed ? "YES (Suspicious)" : "No"],
        ["Key Alg", logData.key_alg || "RSA"],
        ["Sig Alg", logData.sig_alg || "SHA256withRSA"],
        ["SNI Server Name", logData.server_name || "—"]
      ];
      fields.forEach(([k, v]) => {
        fieldsEl.innerHTML += `<div class="detail-item"><div class="detail-item-label">${k}</div><div class="detail-item-val">${v}</div></div>`;
      });
    } else {
      summaryEl.textContent = `Zeek ${logType} Protocol Record`;
      Object.entries(logData).slice(0, 8).forEach(([k, v]) => {
        if (typeof v !== "object") {
          fieldsEl.innerHTML += `<div class="detail-item"><div class="detail-item-label">${k}</div><div class="detail-item-val">${v}</div></div>`;
        }
      });
    }

    modal.classList.add("open");
  };

  window.showZeekState = function(state) {
    if (!currentReport) return;
    const conns = (currentReport.network_behaviour && currentReport.network_behaviour.tcp_connections || []).filter(c => (c.zeek_conn_state || c.conn_state) === state);
    if (conns.length > 0) {
      window.showZeekModal("conn.log", conns[0], `Zeek Connection State (${state}) Log`);
    } else {
      window.showZeekModal("conn.log", { state: state, timestamp: Date.now() / 1000, description: `State ${state} recorded in Zeek connection summary.` }, `Zeek State (${state}) Log`);
    }
  };

  window.showZeekService = function(svc) {
    if (!currentReport) return;
    const sLower = svc.toLowerCase();
    if (sLower === "http") {
      const httpReqs = (currentReport.network_behaviour && currentReport.network_behaviour.http_requests || []);
      if (httpReqs.length > 0) {
        window.showZeekModal("http.log", httpReqs[0], `Zeek HTTP Protocol Log`);
        return;
      }
    } else if (sLower === "dns") {
      const dns = (currentReport.network_behaviour && currentReport.network_behaviour.dns_queries || []);
      if (dns.length > 0) {
        window.showZeekModal("dns.log", dns[0], `Zeek DNS Protocol Log`);
        return;
      }
    }
    const matchingConns = (currentReport.network_behaviour && currentReport.network_behaviour.tcp_connections || []).filter(c => (c.zeek_service || c.service || "").toLowerCase() === sLower);
    if (matchingConns.length > 0) {
      window.showZeekModal("conn.log", matchingConns[0], `Zeek ${svc.toUpperCase()} Connection Log`);
    } else {
      window.showZeekModal(`${sLower}.log`, { service: svc, detected_in_capture: currentReport.capture_id }, `Zeek ${svc.toUpperCase()} Protocol Log`);
    }
  };

  // 4. Snort Detection Rule & Associated Packet Evidence Modal (Requirement 2)
  window.showSidModal = async function(a, rep) {
    const modal = document.getElementById("sid-modal");
    if (!modal) return;

    document.getElementById("sid-modal-sid").textContent = `SID ${a.sid}`;
    document.getElementById("sid-modal-msg").textContent = a.msg;
    const prioEl = document.getElementById("sid-modal-priority");
    prioEl.textContent = `Priority ${a.priority}`;
    prioEl.className = `badge-priority p${a.priority}`;
    document.getElementById("sid-modal-proto").textContent = a.protocol || "TCP";
    document.getElementById("sid-modal-gidrev").textContent = `${a.gid || 1}:${a.rev || 1}`;
    document.getElementById("sid-modal-count").textContent = a.count || 1;
    document.getElementById("sid-modal-pkts-summary").textContent = JSON.stringify(a.triggering_packets || []);

    const ruleCodeEl = document.getElementById("sid-modal-rule-code");
    ruleCodeEl.textContent = "Loading official Snort 3 signature syntax...";

    // Fetch actual rule definition by SID from backend
    try {
      const res = await fetch(`/api/pipeline/rule_definition/${a.sid}?msg=${encodeURIComponent(a.msg)}&proto=${a.protocol}&priority=${a.priority}`);
      const data = await res.json();
      ruleCodeEl.textContent = data.rule_text || `# Snort 3 Rule SID ${a.sid}`;
    } catch (e) {
      ruleCodeEl.textContent = `alert ${a.protocol.toLowerCase()} $EXTERNAL_NET any -> $HOME_NET any (msg:"${a.msg}"; priority:${a.priority}; sid:${a.sid}; rev:${a.rev || 1};)`;
    }

    // Set up copy rule button
    const copyBtn = document.getElementById("sid-modal-copy-rule");
    if (copyBtn) {
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(ruleCodeEl.textContent).then(() => {
          copyBtn.textContent = "Copied!";
          setTimeout(() => { copyBtn.textContent = "Copy Rule"; }, 2000);
        });
      };
    }

    // Associated Triggering Packets Evidence
    const pktsList = document.getElementById("sid-modal-packets-list");
    pktsList.innerHTML = "";
    const trigPkts = a.triggering_packets || [];

    if (trigPkts.length === 0) {
      pktsList.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;">No triggering packets recorded for this detection.</div>';
    } else {
      trigPkts.forEach(pNum => {
        const ev = (rep.packet_evidence || []).find(e => e.pkt_num === pNum);
        const httpReq = (rep.network_behaviour && rep.network_behaviour.http_requests || []).find(h => h.pkt_num === pNum);

        const div = document.createElement("div");
        div.className = "corr-event-item";
        div.style.borderLeft = "3px solid var(--crit)";

        let packetDetailsHtml = "";
        if (httpReq) {
          packetDetailsHtml = `
            <div style="font-size:12px;margin:4px 0;"><strong>HTTP Request:</strong> <code>${httpReq.method} ${httpReq.uri}</code> (Host: <code>${httpReq.host || '—'}</code>)</div>
            ${httpReq.user_agent ? `<div style="font-size:11.5px;color:var(--fg-muted);word-break:break-all;"><strong>User-Agent:</strong> <code>${httpReq.user_agent}</code></div>` : ''}
            <div style="font-size:11px;color:var(--fg-secondary);margin-top:3px;">5-Tuple: ${httpReq.src_ip} &rarr; ${httpReq.dst_ip}:${httpReq.dst_port}</div>
          `;
        } else if (ev) {
          packetDetailsHtml = `
            <div style="font-size:12px;margin:4px 0;"><strong>Protocol:</strong> <span class="kpi-pill dim">${ev.proto}</span></div>
            <div style="font-size:12px;color:var(--fg-secondary);">${ev.summary}</div>
            ${ev.payload_sample ? `<pre style="font-size:11px;background:var(--bg-base);padding:6px;margin-top:4px;border-radius:4px;overflow-x:auto;">${ev.payload_sample}</pre>` : ''}
          `;
        } else {
          packetDetailsHtml = `
            <div style="font-size:12px;color:var(--fg-muted);">Frame #${pNum} in capture ${rep.filename || rep.capture_id}. Triggered rule signature pattern matching condition.</div>
          `;
        }

        div.innerHTML = `
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="font-family:var(--font-mono);font-weight:700;color:var(--crit);">Triggering Packet Frame #${pNum}</span>
            <span class="kpi-pill crit">Signature Match</span>
          </div>
          ${packetDetailsHtml}
        `;
        pktsList.appendChild(div);
      });
    }

    modal.classList.add("open");
  };

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function showStudioNotification(msg) {
    const toastContainer = document.getElementById("toast-container");
    if (!toastContainer) return;
    const t = document.createElement("div");
    t.className = "toast";
    t.style.cssText = "background:var(--bg-elev-2);color:var(--fg-primary);padding:10px 16px;border-radius:6px;border:1px solid var(--accent);box-shadow:0 4px 12px rgba(0,0,0,0.4);font-size:12.5px;margin-top:8px;animation:fadeIn 0.2s ease;";
    t.textContent = msg;
    toastContainer.appendChild(t);
    setTimeout(() => {
      t.remove();
    }, 3500);
  }

  // 5. LLM Intelligence Studio Tasks (Modal Presentation)
  async function runTaskA(refresh = false) {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const modal = document.getElementById("modal-task-a");
    if (!modal) return;

    modal.classList.add("open");
    const cidEl = document.getElementById("task-a-modal-cid");
    if (cidEl) cidEl.textContent = currentReport.capture_id;
    const famEl = document.getElementById("task-a-modal-family");
    if (famEl) famEl.textContent = currentReport.malware_family || "Unknown Threat Family";
    const sumEl = document.getElementById("task-a-modal-summary-line");
    if (sumEl) sumEl.textContent = `Evaluated against ${currentReport.filename || currentReport.capture_id}`;

    const loadingEl = document.getElementById("task-a-modal-loading");
    const contentEl = document.getElementById("task-a-modal-content");
    const cachedPill = document.getElementById("task-a-modal-cached-pill");

    if (loadingEl && contentEl) {
      loadingEl.style.display = "block";
      contentEl.style.display = "none";
    }

    try {
      const url = `/api/pipeline/tasks/a/${currentReport.capture_id}${refresh ? "?refresh=true" : ""}`;
      const res = await fetch(url, { method: "POST" });
      const data = await res.json();

      if (data.status === "success" && data.result) {
        if (cachedPill) cachedPill.style.display = data.cached ? "inline-block" : "none";
        renderTaskAModalResult(data.result);
      } else {
        alert("Task A Error: " + (data.message || "Failed to analyze signatures"));
      }
    } catch (err) {
      alert("Task A Error: " + err);
    } finally {
      if (loadingEl && contentEl) {
        loadingEl.style.display = "none";
        contentEl.style.display = "flex";
      }
    }
  }

  function renderTaskAModalResult(res) {
    // Overall detection gaps
    const gapsContainer = document.getElementById("task-a-modal-gaps-container");
    const gapsText = document.getElementById("task-a-modal-gaps-text");
    if (gapsText) {
      if (res.overall_detection_gaps) {
        gapsText.textContent = res.overall_detection_gaps;
        if (gapsContainer) gapsContainer.style.display = "block";
      } else {
        if (gapsContainer) gapsContainer.style.display = "none";
      }
    }

    // Signature evaluations
    const listEl = document.getElementById("task-a-modal-evals-list");
    const countEl = document.getElementById("task-a-modal-eval-count");
    if (listEl) {
      listEl.innerHTML = "";
      const evals = res.signature_evaluations || [];
      if (countEl) countEl.textContent = `${evals.length} Signature${evals.length !== 1 ? 's' : ''}`;

      if (evals.length === 0) {
        listEl.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;padding:12px;">No signature evaluations returned. Ready for new candidate rule engineering.</div>';
      } else {
        evals.forEach(ev => {
          const card = document.createElement("div");
          card.className = "corr-event-item";
          card.style.cssText = "border-left:3px solid var(--accent);background:var(--bg-base);padding:12px;border-radius:6px;border:1px solid var(--border-subtle);display:flex;flex-direction:column;gap:6px;";

          const pkts = (ev.triggering_packets || []).join(", ") || "—";
          card.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
              <div>
                <span class="badge-sig" style="font-weight:700;">SID ${ev.sid || "—"}</span>
                <strong style="color:var(--fg-bright);margin-left:6px;font-size:13px;">${escapeHtml(ev.msg || "Snort Signature")}</strong>
              </div>
              <span class="kpi-pill crit" style="font-size:10.5px;">Priority ${ev.priority || 1}</span>
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--fg-bright);">Matching Conditions:</strong> ${escapeHtml(ev.matching_conditions || "—")}
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--fg-bright);">Triggering Packets:</strong> <span class="badge-sig" style="font-family:var(--font-mono);font-size:11px;">[${pkts}]</span>
              · <strong style="color:var(--fg-bright);">Activity Context:</strong> ${escapeHtml(ev.activity_relationship || "Malicious session activity")}
            </div>
            ${ev.coverage_limitations ? `
              <div style="background:rgba(245,158,11,0.06);border-left:2px solid var(--warn);padding:6px 10px;border-radius:4px;font-size:11.5px;color:var(--fg-secondary);margin-top:2px;">
                <strong style="color:var(--warn);">Coverage Limitations:</strong> ${escapeHtml(ev.coverage_limitations)}
              </div>
            ` : ""}
            ${ev.uncovered_related_events ? `
              <div style="background:rgba(239,68,68,0.06);border-left:2px solid var(--crit);padding:6px 10px;border-radius:4px;font-size:11.5px;color:var(--fg-secondary);margin-top:2px;">
                <strong style="color:var(--crit);">Uncovered Events:</strong> ${escapeHtml(ev.uncovered_related_events)}
              </div>
            ` : ""}
          `;
          listEl.appendChild(card);
        });
      }
    }

    // Raw JSON
    const rawEl = document.getElementById("task-a-modal-raw-json");
    if (rawEl) {
      rawEl.textContent = JSON.stringify(res, null, 2);
    }
  }

  async function runTaskB(refresh = false) {
    const modal = document.getElementById("modal-task-b");
    if (!modal) return;

    modal.classList.add("open");
    const loadingEl = document.getElementById("task-b-modal-loading");
    const contentEl = document.getElementById("task-b-modal-content");
    const cachedPill = document.getElementById("task-b-modal-cached-pill");

    if (loadingEl && contentEl) {
      loadingEl.style.display = "block";
      contentEl.style.display = "none";
    }

    try {
      const url = `/api/pipeline/tasks/b${refresh ? "?refresh=true" : ""}`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ capture_ids: currentReport ? [currentReport.capture_id] : [] })
      });
      const data = await res.json();

      if (data.status === "success" && data.result) {
        if (cachedPill) cachedPill.style.display = data.cached ? "inline-block" : "none";
        renderTaskBModalResult(data.result);
      } else {
        alert("Task B Error: " + (data.message || "Failed to discover patterns"));
      }
    } catch (err) {
      alert("Task B Error: " + err);
    } finally {
      if (loadingEl && contentEl) {
        loadingEl.style.display = "none";
        contentEl.style.display = "flex";
      }
    }
  }

  function renderTaskBModalResult(res) {
    function renderPills(containerId, items, badgeClass = "badge-sig") {
      const el = document.getElementById(containerId);
      if (!el) return;
      el.innerHTML = "";
      if (!items || items.length === 0) {
        el.innerHTML = '<span style="color:var(--fg-muted);font-style:italic;font-size:11px;">None identified</span>';
        return;
      }
      items.forEach(it => {
        const span = document.createElement("span");
        span.className = badgeClass;
        span.style.fontSize = "11px";
        span.style.padding = "2px 6px";
        span.textContent = typeof it === "string" ? it : JSON.stringify(it);
        el.appendChild(span);
      });
    }

    renderPills("task-b-modal-static-list", res.static_indicators || []);
    renderPills("task-b-modal-protocol-list", res.protocol_indicators || []);
    renderPills("task-b-modal-behavioural-list", res.behavioural_indicators || []);
    renderPills("task-b-modal-campaign-list", res.campaign_specific_indicators || []);

    const patternsList = document.getElementById("task-b-modal-patterns-list");
    const countEl = document.getElementById("task-b-modal-pattern-count");
    if (patternsList) {
      patternsList.innerHTML = "";
      const patterns = res.reusable_patterns || [];
      if (countEl) countEl.textContent = `${patterns.length} Pattern${patterns.length !== 1 ? 's' : ''}`;

      if (patterns.length === 0) {
        patternsList.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;padding:12px;">No reusable patterns discovered yet.</div>';
      } else {
        patterns.forEach(p => {
          const card = document.createElement("div");
          card.className = "corr-event-item";
          card.style.cssText = "border-left:3px solid var(--ok);background:var(--bg-base);padding:12px;border-radius:6px;border:1px solid var(--border-subtle);display:flex;flex-direction:column;gap:6px;";
          card.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong style="color:var(--ok);font-size:13.5px;">${escapeHtml(p.pattern_name || "Discovered Pattern")}</strong>
              <span class="badge-sig" style="font-size:11px;">Protocol: ${escapeHtml(p.protocol || "TCP/HTTP")}</span>
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--fg-bright);">Stable Characteristics:</strong> ${escapeHtml(p.stable_characteristics || "—")}
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--accent);">Generalization Rationale:</strong> ${escapeHtml(p.generalization_rationale || "—")}
            </div>
          `;
          patternsList.appendChild(card);
        });
      }
    }

    const rawEl = document.getElementById("task-b-modal-raw-json");
    if (rawEl) {
      rawEl.textContent = JSON.stringify(res, null, 2);
    }
  }

  // ── Task C: HDIRC Stage 1 (Hypothesis & Validation Gate) Logic ──
  async function runHdircStage1() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const modal = document.getElementById("modal-hdirc-stage1");
    if (!modal) return;

    modal.classList.add("open");
    const loadingEl = document.getElementById("hdirc-s1-loading");
    const contentEl = document.getElementById("hdirc-s1-content");

    if (loadingEl && contentEl) {
      loadingEl.style.display = "block";
      contentEl.style.display = "none";
    }

    try {
      const res = await fetch(`/api/pipeline/hdirc/stage1/${currentReport.capture_id}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.status === "success" && data.rule_state) {
        renderHdircStage1Result(data);
      } else {
        alert("HDIRC Stage 1 Error: " + (data.message || "Failed to formulate hypothesis"));
      }
    } catch (err) {
      alert("HDIRC Stage 1 Request Failed: " + err);
    } finally {
      if (loadingEl && contentEl) {
        loadingEl.style.display = "none";
        contentEl.style.display = "flex";
      }
    }
  }

  function renderHdircStage1Result(data) {
    const state = data.rule_state || {};
    const hyp = data.hypothesis || state.hypothesis || {};
    const val = data.validation || (state.component_validation ? state.component_validation.stage1_hypothesis : {}) || {};

    const pcapBadge = document.getElementById("hdirc-s1-pcap-id");
    if (pcapBadge) pcapBadge.textContent = data.capture_id || (currentReport ? currentReport.capture_id : "—");

    const statusPill = document.getElementById("hdirc-s1-status-pill");
    if (statusPill) {
      const st = (state.status || "").toLowerCase();
      statusPill.className = "kpi-pill " + (st.includes("approved") ? "ok" : (st.includes("insufficient") ? "warn" : (st.includes("correlation") ? "info" : "crit")));
      statusPill.textContent = (state.status || "UNKNOWN").toUpperCase();
    }

    const dispPill = document.getElementById("hdirc-s1-disposition-pill");
    if (dispPill) {
      const disp = (val.details ? val.details.verdict : null) || hyp.disposition || "PROCEED_TO_RULE";
      dispPill.className = "kpi-pill " + (disp === "PROCEED_TO_RULE" ? "ok" : (disp === "CORRELATION_ONLY" ? "info" : "warn"));
      dispPill.textContent = disp;
    }

    const hypIdEl = document.getElementById("hdirc-s1-hyp-id");
    if (hypIdEl) hypIdEl.textContent = hyp.hypothesis_id || state.hypothesis_id || "HYP_001";

    const sidEl = document.getElementById("hdirc-s1-sid-text");
    if (sidEl) sidEl.textContent = (state.components && state.components.sid) ? state.components.sid : (state.candidate_id || "9001001");

    const rationaleEl = document.getElementById("hdirc-s1-rationale");
    if (rationaleEl) {
      rationaleEl.textContent = hyp.rationale || val.reason || "Stage 1 Hypothesis formulated and validated against invariant protocol indicators.";
    }

    const behEl = document.getElementById("hdirc-s1-behaviour");
    if (behEl) behEl.textContent = hyp.target_behaviour || "Malicious traffic pattern";

    const objEl = document.getElementById("hdirc-s1-objective");
    if (objEl) objEl.textContent = "Objective: " + (hyp.detection_objective || "Synthesize Snort 3 rule to match malicious attack vector.");

    const protoEl = document.getElementById("hdirc-s1-protocol");
    if (protoEl) protoEl.textContent = (hyp.protocol || "TCP").toUpperCase();

    const servEl = document.getElementById("hdirc-s1-service");
    if (servEl) servEl.textContent = hyp.service || "any";

    const dirEl = document.getElementById("hdirc-s1-direction");
    if (dirEl) dirEl.textContent = hyp.communication_direction || "client_to_server";

    const flowEl = document.getElementById("hdirc-s1-flow-intent");
    if (flowEl) flowEl.textContent = hyp.flow_intent || "to_server";

    // Invariant Indicators list
    const indContainer = document.getElementById("hdirc-s1-indicators-list");
    if (indContainer) {
      indContainer.innerHTML = "";
      const indicators = hyp.invariant_indicators || [];
      if (indicators.length === 0) {
        indContainer.innerHTML = '<span style="color:var(--fg-muted);font-style:italic;font-size:11px;">No invariant indicators identified</span>';
      } else {
        indicators.forEach(ind => {
          const chip = document.createElement("span");
          chip.className = "kpi-pill ok";
          chip.style.cssText = "font-size:11px;font-family:var(--font-mono);background:rgba(34,197,94,0.12);border:1px solid rgba(34,197,94,0.3);";
          chip.textContent = ind;
          indContainer.appendChild(chip);
        });
      }
    }

    // Evidence Packets
    const evContainer = document.getElementById("hdirc-s1-evidence-pkts");
    if (evContainer) {
      evContainer.innerHTML = "";
      const pkts = hyp.evidence_packets || (state.evidence_mapping ? state.evidence_mapping.packet_numbers : []) || [];
      if (pkts.length === 0) {
        evContainer.innerHTML = '<span style="color:var(--fg-muted);font-style:italic;font-size:11px;">No specific packet numbers bound</span>';
      } else {
        pkts.forEach(p => {
          const badge = document.createElement("span");
          badge.className = "badge-sig";
          badge.style.fontSize = "11px";
          badge.textContent = `Pkt #${p}`;
          evContainer.appendChild(badge);
        });
      }
    }

    // Raw JSON
    const rawEl = document.getElementById("hdirc-s1-raw-json");
    if (rawEl) {
      rawEl.textContent = JSON.stringify(state, null, 2);
    }

    // Stage 2 Header UI
    const s2Body = document.getElementById("hdirc-s2-header-body");
    const s2Pill = document.getElementById("hdirc-s2-gate-pill");
    const s2Btn = document.getElementById("btn-advance-hdirc-stage2");
    const s2Tracker = document.querySelector("#hdirc-s1-ast-stages > div:nth-child(2)");

    const hdr = (state.ast && state.ast.header) || (state.components ? state.components.header : null);
    const s2Val = state.component_validation ? state.component_validation.stage2_header : null;

    if (hdr && hdr.action) {
      if (s2Body) s2Body.style.display = "flex";
      if (s2Pill) {
        s2Pill.style.display = "inline-block";
        const passed = s2Val ? s2Val.passed : true;
        s2Pill.className = "kpi-pill " + (passed ? "ok" : "crit");
        s2Pill.textContent = passed ? "HEADER_APPROVED" : "VALIDATION_FAILED";
      }
      if (s2Btn) {
        s2Btn.innerHTML = "✓ Stage 2 Header Generated";
        s2Btn.disabled = false;
      }
      if (s2Tracker) {
        s2Tracker.style.borderTop = "3px solid var(--ok)";
        s2Tracker.style.opacity = "1";
        const statEl = s2Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--ok)";
          statEl.textContent = "✓ Approved";
        }
      }

      // Populate values
      const renderedTextEl = document.getElementById("hdirc-s2-rendered-text");
      const typeBadgeEl = document.getElementById("hdirc-s2-type-badge");
      const actValEl = document.getElementById("hdirc-s2-action-val");
      const protoValEl = document.getElementById("hdirc-s2-proto-val");
      const srcValEl = document.getElementById("hdirc-s2-src-val");
      const dirValEl = document.getElementById("hdirc-s2-dir-val");
      const dstValEl = document.getElementById("hdirc-s2-dst-val");

      const hType = hdr.header_type || "traditional";
      if (typeBadgeEl) typeBadgeEl.textContent = hType;
      if (actValEl) actValEl.textContent = hdr.action || "alert";
      if (protoValEl) protoValEl.textContent = hdr.service || hdr.protocol || "tcp";

      let srcStr = "—";
      let dstStr = "—";
      let dirStr = hdr.direction || "->";

      if (hType === "traditional") {
        const srcAddr = (hdr.source ? hdr.source.address : hdr.source_addr) || "$HOME_NET";
        const srcPort = (hdr.source ? hdr.source.port : hdr.source_port) || "any";
        const dstAddr = (hdr.destination ? hdr.destination.address : hdr.dest_addr) || "$EXTERNAL_NET";
        const dstPort = (hdr.destination ? hdr.destination.port : hdr.dest_port) || "$HTTP_PORTS";
        srcStr = `${srcAddr}:${srcPort}`;
        dstStr = `${dstAddr}:${dstPort}`;
        if (renderedTextEl) renderedTextEl.textContent = `${hdr.action} ${hdr.protocol || 'tcp'} ${srcStr} ${dirStr} ${dstStr}`;
      } else if (hType === "service") {
        if (renderedTextEl) renderedTextEl.textContent = `${hdr.action} ${hdr.service || 'http'}`;
      } else if (hType === "file") {
        if (renderedTextEl) renderedTextEl.textContent = `${hdr.action} file`;
      } else if (hType === "file_id") {
        if (renderedTextEl) renderedTextEl.textContent = "file_id";
      }

      if (srcValEl) srcValEl.textContent = srcStr;
      if (dirValEl) dirValEl.textContent = dirStr;
      if (dstValEl) dstValEl.textContent = dstStr;
    } else {
      if (s2Body) s2Body.style.display = "none";
      if (s2Pill) s2Pill.style.display = "none";
      if (s2Btn) {
        s2Btn.innerHTML = "⚡ Execute Stage 2: Header Generation";
        s2Btn.disabled = false;
      }
      if (s2Tracker) {
        s2Tracker.style.borderTop = "3px solid var(--border-subtle)";
        s2Tracker.style.opacity = "0.65";
        const statEl = s2Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--fg-muted)";
          statEl.textContent = "Placeholder";
        }
      }
    }

    // Stage 3 Message UI
    const s3Body = document.getElementById("hdirc-s3-msg-body");
    const s3Pill = document.getElementById("hdirc-s3-gate-pill");
    const s3Btn = document.getElementById("btn-advance-hdirc-stage3");
    const s3Tracker = document.querySelector("#hdirc-s1-ast-stages > div:nth-child(3)");

    const msgVal = (state.components ? state.components.msg : null);
    const s3Val = state.component_validation ? state.component_validation.stage3_message : null;

    if (msgVal) {
      if (s3Body) s3Body.style.display = "flex";
      if (s3Pill) {
        s3Pill.style.display = "inline-block";
        const passed = s3Val ? s3Val.passed : true;
        s3Pill.className = "kpi-pill " + (passed ? "ok" : "crit");
        s3Pill.textContent = passed ? "MESSAGE_APPROVED" : "VALIDATION_FAILED";
      }
      if (s3Btn) {
        s3Btn.innerHTML = "✓ Stage 3 Message Generated";
        s3Btn.disabled = false;
      }
      if (s3Tracker) {
        s3Tracker.style.borderTop = "3px solid var(--ok)";
        s3Tracker.style.opacity = "1";
        const statEl = s3Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--ok)";
          statEl.textContent = "✓ Approved";
        }
      }

      // Populate message values
      const msgTextEl = document.getElementById("hdirc-s3-rendered-text");
      const prefixBadgeEl = document.getElementById("hdirc-s3-prefix-badge");
      const lenValEl = document.getElementById("hdirc-s3-len-val");

      if (msgTextEl) msgTextEl.textContent = `msg:"${msgVal}";`;
      const prefix = msgVal.split(" ")[0] || "MALWARE";
      if (prefixBadgeEl) prefixBadgeEl.textContent = prefix;
      if (lenValEl) lenValEl.textContent = `${msgVal.length} chars`;
    } else {
      if (s3Body) s3Body.style.display = "none";
      if (s3Pill) s3Pill.style.display = "none";
      if (s3Btn) {
        s3Btn.innerHTML = "⚡ Execute Stage 3: Message Generation";
        s3Btn.disabled = false;
      }
      if (s3Tracker) {
        s3Tracker.style.borderTop = "3px solid var(--border-subtle)";
        s3Tracker.style.opacity = "0.65";
        const statEl = s3Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--fg-muted)";
          statEl.textContent = "Placeholder";
        }
      }
    }

    // Stage 4 Flow UI
    const s4Body = document.getElementById("hdirc-s4-flow-body");
    const s4Pill = document.getElementById("hdirc-s4-gate-pill");
    const s4Btn = document.getElementById("btn-advance-hdirc-stage4");
    const s4Tracker = document.querySelector("#hdirc-s1-ast-stages > div:nth-child(4)");

    const flowVal = (state.components ? state.components.flow : null);
    const s4Val = state.component_validation ? state.component_validation.stage4_flow : null;

    if (flowVal !== undefined && (flowVal !== null || (s4Val && s4Val.passed))) {
      if (s4Body) s4Body.style.display = "flex";
      if (s4Pill) {
        s4Pill.style.display = "inline-block";
        const passed = s4Val ? s4Val.passed : true;
        s4Pill.className = "kpi-pill " + (passed ? "ok" : "crit");
        s4Pill.textContent = passed ? "FLOW_APPROVED" : "VALIDATION_FAILED";
      }
      if (s4Btn) {
        s4Btn.innerHTML = "✓ Stage 4 Flow Generated";
        s4Btn.disabled = false;
      }
      if (s4Tracker) {
        s4Tracker.style.borderTop = "3px solid var(--ok)";
        s4Tracker.style.opacity = "1";
        const statEl = s4Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--ok)";
          statEl.textContent = "✓ Approved";
        }
      }

      // Populate flow values
      const flowTextEl = document.getElementById("hdirc-s4-rendered-text");
      const flowBadgeEl = document.getElementById("hdirc-s4-type-badge");
      const dirValEl = document.getElementById("hdirc-s4-dir-val");
      const connValEl = document.getElementById("hdirc-s4-conn-val");
      const streamValEl = document.getElementById("hdirc-s4-stream-val");
      const fragValEl = document.getElementById("hdirc-s4-frag-val");

      const flowList = Array.isArray(flowVal) ? flowVal : (flowVal ? [flowVal] : []);
      const flowStr = flowList.length > 0 ? `flow:${flowList.join(",")};` : "omitted (file/stateless)";

      if (flowTextEl) flowTextEl.textContent = flowStr;
      if (flowBadgeEl) flowBadgeEl.textContent = flowList.length > 0 ? flowList.join(",") : "not_required";

      const dirItem = flowList.find(x => ["to_server", "to_client", "from_client", "from_server"].includes(x.toLowerCase()));
      const connItem = flowList.find(x => ["established", "not_established", "stateless"].includes(x.toLowerCase()));
      const streamItem = flowList.find(x => ["only_stream", "no_stream"].includes(x.toLowerCase()));
      const fragItem = flowList.find(x => ["only_frag", "no_frag"].includes(x.toLowerCase()));

      if (dirValEl) dirValEl.textContent = dirItem || "none";
      if (connValEl) connValEl.textContent = connItem || "none";
      if (streamValEl) streamValEl.textContent = streamItem || "default";
      if (fragValEl) fragValEl.textContent = fragItem || "default";
    } else {
      if (s4Body) s4Body.style.display = "none";
      if (s4Pill) s4Pill.style.display = "none";
      if (s4Btn) {
        s4Btn.innerHTML = "⚡ Execute Stage 4: Flow Generation";
        s4Btn.disabled = false;
      }
      if (s4Tracker) {
        s4Tracker.style.borderTop = "3px solid var(--border-subtle)";
        s4Tracker.style.opacity = "0.65";
        const statEl = s4Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--fg-muted)";
          statEl.textContent = "Placeholder";
        }
      }
    }

    // Stage 5 Detection UI
    const s5Body = document.getElementById("hdirc-s5-detection-body");
    const s5Pill = document.getElementById("hdirc-s5-gate-pill");
    const s5Btn = document.getElementById("btn-advance-hdirc-stage5");
    const s5Tracker = document.querySelector("#hdirc-s1-ast-stages > div:nth-child(5)");

    const detVal = (state.components ? state.components.detection : null);
    const s5Val = state.component_validation ? state.component_validation.stage5_detection : null;

    if (detVal && detVal.length > 0) {
      if (s5Body) s5Body.style.display = "flex";
      if (s5Pill) {
        s5Pill.style.display = "inline-block";
        const passed = s5Val ? s5Val.passed : true;
        s5Pill.className = "kpi-pill " + (passed ? "ok" : "crit");
        s5Pill.textContent = passed ? "DETECTION_APPROVED" : "VALIDATION_FAILED";
      }
      if (s5Btn) {
        s5Btn.innerHTML = "✓ Stage 5 Detection Generated";
        s5Btn.disabled = false;
      }
      if (s5Tracker) {
        s5Tracker.style.borderTop = "3px solid var(--ok)";
        s5Tracker.style.opacity = "1";
        const statEl = s5Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--ok)";
          statEl.textContent = "✓ Approved";
        }
      }

      // Populate list of detection conditions
      const optListEl = document.getElementById("hdirc-s5-options-list");
      if (optListEl) {
        optListEl.innerHTML = "";
        detVal.forEach((node, idx) => {
          const itemDiv = document.createElement("div");
          itemDiv.style.cssText = "background:var(--bg-elev-1);border:1px solid var(--border-subtle);border-radius:5px;padding:6px 10px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;";

          let repr = "";
          if (node.value === null) {
            repr = `<span style="color:var(--accent);font-weight:700;">${node.name};</span> <span class="badge-sig" style="font-size:10px;">sticky buffer</span>`;
          } else if (node.name === "content") {
            const mods = node.modifiers || {};
            const modKeys = Object.keys(mods).map(k => mods[k] === true ? k : `${k} ${mods[k]}`);
            const modStr = modKeys.length > 0 ? `,${modKeys.join(",")}` : "";
            repr = `<span style="color:var(--fg-bright);font-weight:700;">content:"${node.value}"${modStr};</span>`;
          } else {
            repr = `<span style="color:var(--fg-bright);">${node.name}:${node.value};</span>`;
          }
          itemDiv.innerHTML = `<div><span style="color:var(--fg-muted);margin-right:6px;">#${idx+1}</span>${repr}</div>`;
          optListEl.appendChild(itemDiv);
        });
      }

      // Metadata summary row
      const bufEl = document.getElementById("hdirc-s5-buffer-val");
      const fpEl = document.getElementById("hdirc-s5-fp-val");
      const countEl = document.getElementById("hdirc-s5-count-val");
      const s5SourceVal = document.getElementById("hdirc-s5-source-val");
      const s5FallbackPill = document.getElementById("hdirc-s5-fallback-pill");
      const s5FallbackBanner = document.getElementById("hdirc-s5-fallback-banner");

      const isFallback = Boolean(
        (state.components && (state.components.fallback_used || state.components.synthesis_source === "deterministic_fallback")) ||
        (s5Val && s5Val.details && (s5Val.details.fallback_used || s5Val.details.synthesis_source === "deterministic_fallback")) ||
        (state.stage_results && state.stage_results.stage5_detection && state.stage_results.stage5_detection.reasoning_summary && state.stage_results.stage5_detection.reasoning_summary.includes("fallback"))
      );

      if (s5FallbackPill) s5FallbackPill.style.display = isFallback ? "inline-block" : "none";
      if (s5FallbackBanner) s5FallbackBanner.style.display = isFallback ? "flex" : "none";
      if (s5SourceVal) {
        s5SourceVal.textContent = isFallback ? "⚡ Telemetry Fallback" : "Autonomous LLM";
        s5SourceVal.style.color = isFallback ? "var(--warn)" : "var(--ok)";
      }

      const buffers = (s5Val && s5Val.details && s5Val.details.buffers_selected) || [];
      if (bufEl) bufEl.textContent = buffers.length > 0 ? buffers.join(", ") : "pkt_data";
      if (fpEl) {
        const hasFp = s5Val && s5Val.details && s5Val.details.fast_pattern_found;
        fpEl.textContent = hasFp ? "✓ Designated" : "Default anchor";
      }
      if (countEl) countEl.textContent = `${detVal.length} nodes`;
    } else {
      if (s5Body) s5Body.style.display = "none";
      if (s5Pill) s5Pill.style.display = "none";
      const s5FallbackPill = document.getElementById("hdirc-s5-fallback-pill");
      const s5FallbackBanner = document.getElementById("hdirc-s5-fallback-banner");
      if (s5FallbackPill) s5FallbackPill.style.display = "none";
      if (s5FallbackBanner) s5FallbackBanner.style.display = "none";
      if (s5Btn) {
        s5Btn.innerHTML = "⚡ Execute Stage 5: Detection Generation";
        s5Btn.disabled = false;
      }
      if (s5Tracker) {
        s5Tracker.style.borderTop = "3px solid var(--border-subtle)";
        s5Tracker.style.opacity = "0.65";
        const statEl = s5Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--fg-muted)";
          statEl.textContent = "Placeholder";
        }
      }
    }

    // Stage 6 Supporting Options UI Update
    const s6Body = document.getElementById("hdirc-s6-supporting-body");
    const s6Pill = document.getElementById("hdirc-s6-gate-pill");
    const s6Btn = document.getElementById("btn-advance-hdirc-stage6");
    const s6Tracker = document.querySelector("#hdirc-s1-ast-stages > div:nth-child(6)");

    const s6Val = state.component_validation ? state.component_validation.stage6_supporting : null;
    const sidVal = (state.components ? state.components.sid : null);

    if (sidVal) {
      if (s6Body) s6Body.style.display = "flex";
      if (s6Pill) {
        s6Pill.style.display = "inline-block";
        const passed = s6Val ? s6Val.passed : true;
        s6Pill.className = "kpi-pill " + (passed ? "ok" : "crit");
        s6Pill.textContent = passed ? "OPTIONS_COMMITTED" : "VALIDATION_FAILED";
      }
      if (s6Btn) {
        s6Btn.innerHTML = "✓ Stage 6 Supporting Committed";
        s6Btn.disabled = false;
      }
      if (s6Tracker) {
        s6Tracker.style.borderTop = "3px solid var(--ok)";
        s6Tracker.style.opacity = "1";
        const statEl = s6Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--ok)";
          statEl.textContent = "✓ Committed";
        }
      }

      // Populate list of supporting options
      const optListEl = document.getElementById("hdirc-s6-options-list");
      if (optListEl && state.ast && state.ast.options) {
        optListEl.innerHTML = "";
        const suppNames = ["classtype", "sid", "rev", "priority", "reference", "metadata", "service", "rem", "detection_filter", "tag", "flags", "ttl"];
        const suppNodes = state.ast.options.filter(o => suppNames.includes(o.name));
        suppNodes.forEach(node => {
          const badge = document.createElement("span");
          badge.style.cssText = "background:var(--bg-elev-1);border:1px solid var(--border-subtle);border-radius:4px;padding:3px 8px;font-size:11.5px;";
          badge.innerHTML = `<span style="color:var(--accent);font-weight:700;">${node.name}:</span><span style="color:var(--fg-bright);">${node.value};</span>`;
          optListEl.appendChild(badge);
        });
      }

      const ctEl = document.getElementById("hdirc-s6-classtype-val");
      const sidEl = document.getElementById("hdirc-s6-sid-val");
      const revEl = document.getElementById("hdirc-s6-rev-val");
      const refEl = document.getElementById("hdirc-s6-ref-val");

      if (ctEl) ctEl.textContent = state.components.classification || "trojan-activity";
      if (sidEl) sidEl.textContent = String(sidVal);
      if (revEl) revEl.textContent = `rev:${state.components.rev || 1}`;
      const refs = state.components.references || [];
      if (refEl) refEl.textContent = `${refs.length} cited`;
    } else {
      if (s6Body) s6Body.style.display = "none";
      if (s6Pill) s6Pill.style.display = "none";
      if (s6Btn) {
        s6Btn.innerHTML = "⚡ Execute Stage 6: Supporting Options";
        s6Btn.disabled = false;
      }
      if (s6Tracker) {
        s6Tracker.style.borderTop = "3px solid var(--border-subtle)";
        s6Tracker.style.opacity = "0.65";
        const statEl = s6Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--fg-muted)";
          statEl.textContent = "Placeholder";
        }
      }
    }

    // Stage 7 Assembly & Verification UI Update
    const s7Body = document.getElementById("hdirc-s7-assembly-body");
    const s7Pill = document.getElementById("hdirc-s7-gate-pill");
    const s7Btn = document.getElementById("btn-advance-hdirc-stage7");
    const s7Tracker = document.querySelector("#hdirc-s1-ast-stages > div:nth-child(7)");

    const s7Val = state.component_validation ? state.component_validation.stage7_assembly : null;
    const isAssembled = state.status === "approved" || state.status === "rule_assembled" || (state.stage_results && state.stage_results.stage7_assembly);

    if (isAssembled || s7Val) {
      if (s7Body) s7Body.style.display = "flex";
      if (s7Pill) {
        s7Pill.style.display = "inline-block";
        const passed = s7Val ? s7Val.passed : (state.status === "approved");
        s7Pill.className = "kpi-pill " + (passed ? "ok" : "crit");
        s7Pill.textContent = passed ? "RULE_APPROVED" : "ASSEMBLY_FAILED";
      }
      if (s7Btn) {
        s7Btn.innerHTML = "✓ Stage 7 Assembled &amp; Verified";
        s7Btn.disabled = false;
      }
      if (s7Tracker) {
        s7Tracker.style.borderTop = "3px solid var(--ok)";
        s7Tracker.style.opacity = "1";
        const statEl = s7Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--ok)";
          statEl.textContent = "✓ Approved";
        }
      }

      // Rendered Multi-line Rule
      const rulePre = document.getElementById("hdirc-s7-rendered-rule");
      if (rulePre) {
        rulePre.textContent = data.rendered_multiline || state.rendered_rule_text || "";
      }

      // Structured JSON
      const structPre = document.getElementById("hdirc-s7-structured-json");
      if (structPre) {
        const sData = data.structured_representation || (state.stage_results && state.stage_results.stage7_assembly ? state.stage_results.stage7_assembly.generated_value.structured_representation : null);
        structPre.textContent = sData ? JSON.stringify(sData, null, 2) : "{}";
      }

      // Metrics
      const det = (s7Val && s7Val.details) || (state.stage_results && state.stage_results.stage7_assembly ? state.stage_results.stage7_assembly.generated_value : {});
      const synEl = document.getElementById("hdirc-s7-syntax-val");
      const confEl = document.getElementById("hdirc-s7-conflict-val");
      const tpEl = document.getElementById("hdirc-s7-tp-val");
      const fpEl = document.getElementById("hdirc-s7-fp-val");

      if (synEl) {
        const syn = det.syntax_validation || {};
        synEl.textContent = syn.passed ? "✓ Passed (Exit 0)" : "✗ Syntax Error";
        synEl.style.color = syn.passed ? "var(--ok)" : "var(--crit)";
      }
      if (confEl) {
        const conf = det.conflict_detection || {};
        confEl.textContent = !conf.has_conflict ? "✓ Clean (Unique SID)" : "✗ Conflict Detected";
        confEl.style.color = !conf.has_conflict ? "var(--ok)" : "var(--crit)";
      }
      if (tpEl) {
        const tp = det.true_positive || {};
        if (tp.tested) {
          tpEl.textContent = tp.passed ? `✓ ${tp.alerts_count} Alert(s) Triggered` : "✗ No Alerts Triggered";
          tpEl.style.color = tp.passed ? "var(--accent)" : "var(--crit)";
        } else {
          tpEl.textContent = "Untested";
        }
      }
      if (fpEl) {
        const fp = det.false_positive || {};
        if (fp.tested) {
          fpEl.textContent = fp.passed ? `✓ Clean (${fp.alerts_count} FP)` : `✗ ${fp.alerts_count} FP Alerts!`;
          fpEl.style.color = fp.passed ? "var(--ok)" : "var(--crit)";
        } else {
          fpEl.textContent = "Clean";
        }
      }

      // Candidate Registration Confirmation Banner
      const candBadge = document.getElementById("hdirc-s7-candidate-registered-badge");
      const candSid = document.getElementById("hdirc-s7-registered-sid");
      const candBtn = document.getElementById("btn-hdirc-view-candidate");
      const sid = (data.candidate && data.candidate.rule_id) || (state.components ? state.components.sid : null) || (state.ast && state.ast.options ? (state.ast.options.find(o => o.name === 'sid') || {}).value : null);
      if (candBadge && sid) {
        candBadge.style.display = "flex";
        if (candSid) candSid.textContent = `SID ${sid}`;
        if (candBtn) {
          candBtn.onclick = () => {
            const s1Modal = document.getElementById("modal-hdirc-stage1");
            if (s1Modal) s1Modal.classList.remove("open");
            if (window.selectCandidate) window.selectCandidate(sid);
          };
        }
      }
    } else {
      if (s7Body) s7Body.style.display = "none";
      if (s7Pill) s7Pill.style.display = "none";
      const candBadge = document.getElementById("hdirc-s7-candidate-registered-badge");
      if (candBadge) candBadge.style.display = "none";
      if (s7Btn) {
        s7Btn.innerHTML = "⚡ Execute Stage 7: Assemble &amp; Verify";
        s7Btn.disabled = false;
      }
      if (s7Tracker) {
        s7Tracker.style.borderTop = "3px solid var(--border-subtle)";
        s7Tracker.style.opacity = "0.65";
        const statEl = s7Tracker.querySelector("div:last-child");
        if (statEl) {
          statEl.style.color = "var(--fg-muted)";
          statEl.textContent = "Placeholder";
        }
      }
    }
  }

  async function runHdircStage2() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const s2Btn = document.getElementById("btn-advance-hdirc-stage2");
    if (s2Btn) {
      s2Btn.disabled = true;
      s2Btn.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Generating Header...';
    }

    try {
      const res = await fetch(`/api/pipeline/hdirc/stage2/${currentReport.capture_id}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.status === "success" && data.rule_state) {
        renderHdircStage1Result(data);
      } else {
        alert("HDIRC Stage 2 Error: " + (data.message || "Failed to generate rule header"));
        if (s2Btn) {
          s2Btn.disabled = false;
          s2Btn.innerHTML = "⚡ Execute Stage 2: Header Generation";
        }
      }
    } catch (err) {
      alert("HDIRC Stage 2 Request Failed: " + err);
      if (s2Btn) {
        s2Btn.disabled = false;
        s2Btn.innerHTML = "⚡ Execute Stage 2: Header Generation";
      }
    }
  }

  async function runHdircStage3() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const s3Btn = document.getElementById("btn-advance-hdirc-stage3");
    if (s3Btn) {
      s3Btn.disabled = true;
      s3Btn.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Generating Message...';
    }

    try {
      const res = await fetch(`/api/pipeline/hdirc/stage3/${currentReport.capture_id}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.status === "success" && data.rule_state) {
        renderHdircStage1Result(data);
      } else {
        alert("HDIRC Stage 3 Error: " + (data.message || "Failed to generate rule message"));
        if (s3Btn) {
          s3Btn.disabled = false;
          s3Btn.innerHTML = "⚡ Execute Stage 3: Message Generation";
        }
      }
    } catch (err) {
      alert("HDIRC Stage 3 Request Failed: " + err);
      if (s3Btn) {
        s3Btn.disabled = false;
        s3Btn.innerHTML = "⚡ Execute Stage 3: Message Generation";
      }
    }
  }

  async function runHdircStage4() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const s4Btn = document.getElementById("btn-advance-hdirc-stage4");
    if (s4Btn) {
      s4Btn.disabled = true;
      s4Btn.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Generating Flow...';
    }

    try {
      const res = await fetch(`/api/pipeline/hdirc/stage4/${currentReport.capture_id}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.status === "success" && data.rule_state) {
        renderHdircStage1Result(data);
      } else {
        alert("HDIRC Stage 4 Error: " + (data.message || "Failed to generate flow options"));
        if (s4Btn) {
          s4Btn.disabled = false;
          s4Btn.innerHTML = "⚡ Execute Stage 4: Flow Generation";
        }
      }
    } catch (err) {
      alert("HDIRC Stage 4 Request Failed: " + err);
      if (s4Btn) {
        s4Btn.disabled = false;
        s4Btn.innerHTML = "⚡ Execute Stage 4: Flow Generation";
      }
    }
  }

  async function runHdircStage5() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const s5Btn = document.getElementById("btn-advance-hdirc-stage5");
    if (s5Btn) {
      s5Btn.disabled = true;
      s5Btn.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Generating Detection...';
    }

    try {
      const res = await fetch(`/api/pipeline/hdirc/stage5/${currentReport.capture_id}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.status === "success" && data.rule_state) {
        renderHdircStage1Result(data);
      } else {
        alert("HDIRC Stage 5 Error: " + (data.message || "Failed to generate detection conditions"));
        if (s5Btn) {
          s5Btn.disabled = false;
          s5Btn.innerHTML = "⚡ Execute Stage 5: Detection Generation";
        }
      }
    } catch (err) {
      alert("HDIRC Stage 5 Request Failed: " + err);
      if (s5Btn) {
        s5Btn.disabled = false;
        s5Btn.innerHTML = "⚡ Execute Stage 5: Detection Generation";
      }
    }
  }

  async function runHdircStage6() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const s6Btn = document.getElementById("btn-advance-hdirc-stage6");
    if (s6Btn) {
      s6Btn.disabled = true;
      s6Btn.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Generating Supporting Options...';
    }

    try {
      const res = await fetch(`/api/pipeline/hdirc/stage6/${currentReport.capture_id}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.status === "success" && data.rule_state) {
        renderHdircStage1Result(data);
      } else {
        alert("HDIRC Stage 6 Error: " + (data.message || "Failed to generate supporting options"));
        if (s6Btn) {
          s6Btn.disabled = false;
          s6Btn.innerHTML = "⚡ Execute Stage 6: Supporting Options";
        }
      }
    } catch (err) {
      alert("HDIRC Stage 6 Request Failed: " + err);
      if (s6Btn) {
        s6Btn.disabled = false;
        s6Btn.innerHTML = "⚡ Execute Stage 6: Supporting Options";
      }
    }
  }

  async function runHdircStage7() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    const s7Btn = document.getElementById("btn-advance-hdirc-stage7");
    if (s7Btn) {
      s7Btn.disabled = true;
      s7Btn.innerHTML = '<span class="spinner" style="width:11px;height:11px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:4px;"></span> Assembling &amp; Verifying Rule...';
    }

    try {
      const res = await fetch(`/api/pipeline/hdirc/stage7/${currentReport.capture_id}`, {
        method: "POST"
      });
      const data = await res.json();
      if (data.status === "success" && data.rule_state) {
        renderHdircStage1Result(data);
        // Automatically reload candidates into the Candidate Rules & Version Audit Log section
        await loadCandidates();
        if (data.candidate && data.candidate.rule_id) {
          const sid = data.candidate.rule_id;
          if (window.showToast) {
            window.showToast(`Candidate Rule SID ${sid} automatically added to Candidate Rules & Version Audit Log!`, "success");
          }
        }
      } else {
        alert("HDIRC Stage 7 Error: " + (data.message || "Failed to assemble and verify rule"));
        if (s7Btn) {
          s7Btn.disabled = false;
          s7Btn.innerHTML = "⚡ Execute Stage 7: Assemble &amp; Verify";
        }
      }
    } catch (err) {
      alert("HDIRC Stage 7 Request Failed: " + err);
      if (s7Btn) {
        s7Btn.disabled = false;
        s7Btn.innerHTML = "⚡ Execute Stage 7: Assemble &amp; Verify";
      }
    }
  }

  // ── Generated Reports Archive & Viewer Logic ─────────────────────
  let generatedReportsList = [];
  let currentReportIndex = -1;
  let currentModalReportData = null;
  let currentModalTaskTab = "a";
  const taskReportsCache = {};

  async function openGeneratedReportsModal() {
    const modal = document.getElementById("modal-generated-reports");
    if (!modal) return;
    modal.classList.add("open");

    try {
      const res = await fetch("/api/pipeline/reports");
      const data = await res.json();
      generatedReportsList = data.reports || [];
    } catch (e) {
      console.error("Failed to load generated reports list:", e);
      generatedReportsList = [];
    }

    const badgeEl = document.getElementById("rep-modal-total-badge");
    if (badgeEl) badgeEl.textContent = `${generatedReportsList.length} Reports`;

    // Populate dropdown options
    populateReportsModalDropdown(generatedReportsList);

    // Determine initial selected report index
    if (generatedReportsList.length > 0) {
      if (currentReport && currentReport.capture_id) {
        const foundIdx = generatedReportsList.findIndex(r => r.capture_id === currentReport.capture_id);
        currentReportIndex = foundIdx >= 0 ? foundIdx : (generatedReportsList.length - 1);
      } else {
        currentReportIndex = generatedReportsList.length - 1;
      }
      const initialCid = generatedReportsList[currentReportIndex].capture_id;
      const selectEl = document.getElementById("rep-modal-select");
      if (selectEl) selectEl.value = initialCid;
      await loadAndRenderTaskReportsForCapture(initialCid);
    } else {
      currentReportIndex = -1;
      updateReportNavButtons();
    }
  }

  function populateReportsModalDropdown(reports) {
    const selectEl = document.getElementById("rep-modal-select");
    if (!selectEl) return;
    selectEl.innerHTML = "";
    if (reports.length === 0) {
      selectEl.innerHTML = '<option value="">No generated reports available</option>';
      return;
    }
    reports.forEach((rep, idx) => {
      const opt = document.createElement("option");
      opt.value = rep.capture_id;
      opt.dataset.index = idx;
      opt.textContent = `[${rep.capture_id}] ${rep.malware_family} (${rep.total_alerts} alerts, ${rep.zeek_connections} zeek) — ${rep.generated_at}`;
      selectEl.appendChild(opt);
    });
  }

  function updateReportNavButtons() {
    const prevBtn = document.getElementById("rep-modal-btn-prev");
    const nextBtn = document.getElementById("rep-modal-btn-next");
    const orderInd = document.getElementById("rep-modal-order-indicator");

    if (prevBtn) prevBtn.disabled = (currentReportIndex <= 0);
    if (nextBtn) nextBtn.disabled = (currentReportIndex < 0 || currentReportIndex >= generatedReportsList.length - 1);

    if (orderInd) {
      if (currentReportIndex >= 0 && currentReportIndex < generatedReportsList.length) {
        orderInd.textContent = `Report ${currentReportIndex + 1} of ${generatedReportsList.length} (Chronological)`;
      } else {
        orderInd.textContent = "0 Reports";
      }
    }
  }

  function filterReportsModalOptions(e) {
    const q = (e.target.value || "").toLowerCase().trim();
    const selectEl = document.getElementById("rep-modal-select");
    if (!selectEl) return;

    let firstMatch = null;
    let matchCount = 0;

    Array.from(selectEl.options).forEach(opt => {
      const txt = opt.textContent.toLowerCase();
      const val = opt.value.toLowerCase();
      const match = !q || txt.includes(q) || val.includes(q);
      opt.hidden = !match;
      opt.style.display = match ? "" : "none";
      if (match) {
        matchCount++;
        if (!firstMatch) firstMatch = opt;
      }
    });

    if (firstMatch && (!selectEl.value || selectEl.selectedOptions[0]?.hidden)) {
      selectEl.value = firstMatch.value;
      const idx = generatedReportsList.findIndex(r => r.capture_id === firstMatch.value);
      if (idx >= 0) {
        currentReportIndex = idx;
        loadAndRenderTaskReportsForCapture(firstMatch.value);
      }
    }
  }

  async function loadAndRenderTaskReportsForCapture(captureId, forceRefreshTask = null) {
    updateReportNavButtons();

    // Context info
    const meta = generatedReportsList[currentReportIndex] || {};
    const cidEl = document.getElementById("rep-modal-detail-cid");
    if (cidEl) cidEl.textContent = captureId;
    const famEl = document.getElementById("rep-modal-detail-family");
    const displayFamily = meta.malware_family || (currentReport?.capture_id === captureId ? currentReport.malware_family : "Malware Activity");
    if (famEl) {
      famEl.textContent = displayFamily;
      famEl.title = displayFamily;
    }

    const loadingEl = document.getElementById("gen-rep-modal-loading");
    const paneA = document.getElementById("gen-rep-pane-a");
    const paneB = document.getElementById("gen-rep-pane-b");

    // Check if both cached and not refreshing
    const cachedEntry = taskReportsCache[captureId];
    const needFetchA = !cachedEntry?.a || forceRefreshTask === "a";
    const needFetchB = !cachedEntry?.b || forceRefreshTask === "b";

    if (needFetchA || needFetchB) {
      if (loadingEl) loadingEl.style.display = "block";
      if (paneA) paneA.style.display = "none";
      if (paneB) paneB.style.display = "none";

      try {
        const fetchPromises = [];
        if (needFetchA) {
          fetchPromises.push(
            fetch(`/api/pipeline/tasks/a/${captureId}${forceRefreshTask === "a" ? "?refresh=true" : ""}`, { method: "POST" })
              .then(r => r.json())
              .catch(e => ({ status: "error", message: String(e) }))
          );
        } else {
          fetchPromises.push(Promise.resolve({ status: "success", result: cachedEntry.a, cached: true }));
        }

        if (needFetchB) {
          fetchPromises.push(
            fetch(`/api/pipeline/tasks/b/${captureId}${forceRefreshTask === "b" ? "?refresh=true" : ""}`, { method: "POST" })
              .then(r => r.json())
              .catch(e => ({ status: "error", message: String(e) }))
          );
        } else {
          fetchPromises.push(Promise.resolve({ status: "success", result: cachedEntry.b, cached: true }));
        }

        const [resA, resB] = await Promise.all(fetchPromises);

        taskReportsCache[captureId] = {
          a: (resA && resA.result) ? resA.result : (cachedEntry?.a || null),
          b: (resB && resB.result) ? resB.result : (cachedEntry?.b || null),
          cachedA: resA?.cached !== undefined ? resA.cached : (forceRefreshTask !== "a"),
          cachedB: resB?.cached !== undefined ? resB.cached : (forceRefreshTask !== "b")
        };
      } catch (err) {
        console.error("Error fetching Task A/B reports:", err);
      } finally {
        if (loadingEl) loadingEl.style.display = "none";
      }
    }

    const currentCached = taskReportsCache[captureId] || {};
    renderGenRepTaskA(currentCached.a, captureId, currentCached.cachedA, meta);
    renderGenRepTaskB(currentCached.b, captureId, currentCached.cachedB, meta);

    // Show appropriate pane based on active option tab
    if (paneA && paneB) {
      paneA.style.display = currentModalTaskTab === "a" ? "flex" : "none";
      paneB.style.display = currentModalTaskTab === "b" ? "flex" : "none";
    }
  }

  function renderGenRepTaskA(res, captureId, isCached, meta) {
    const metaEl = document.getElementById("gen-rep-a-header-meta");
    const fn = meta?.filename || (currentReport?.capture_id === captureId ? currentReport.filename : "");
    const fam = meta?.malware_family || (currentReport?.capture_id === captureId ? currentReport.malware_family : "Malware Traffic");
    if (metaEl) metaEl.textContent = `Capture: ${captureId} ${fn ? `(${fn})` : ''} · ${fam}`;
    const badgeEl = document.getElementById("gen-rep-a-cached-badge");
    if (badgeEl) badgeEl.style.display = isCached ? "inline-block" : "none";

    const gapsContainer = document.getElementById("gen-rep-a-gaps-container");
    const gapsText = document.getElementById("gen-rep-a-gaps-text");
    if (gapsText) {
      if (res?.overall_detection_gaps) {
        gapsText.textContent = res.overall_detection_gaps;
        if (gapsContainer) gapsContainer.style.display = "block";
      } else {
        if (gapsContainer) gapsContainer.style.display = "none";
      }
    }

    const listEl = document.getElementById("gen-rep-a-evals-list");
    const countEl = document.getElementById("gen-rep-a-eval-count");
    if (listEl) {
      listEl.innerHTML = "";
      const evals = res?.signature_evaluations || [];
      if (countEl) countEl.textContent = `${evals.length} Signature${evals.length !== 1 ? 's' : ''}`;

      if (evals.length === 0) {
        listEl.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;padding:12px;background:rgba(255,255,255,0.02);border-radius:4px;border:1px dashed var(--border);">No baseline Snort community signatures triggered for this capture. Complete coverage gap (0% baseline detection) — ready for candidate rule engineering.</div>';
      } else {
        evals.forEach(ev => {
          const card = document.createElement("div");
          card.className = "corr-event-item";
          card.style.cssText = "border-left:3px solid var(--accent);background:var(--bg-base);padding:12px;border-radius:6px;border:1px solid var(--border-subtle);display:flex;flex-direction:column;gap:6px;";
          const pkts = (ev.triggering_packets || []).join(", ") || "—";
          card.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
              <div>
                <span class="badge-sig" style="font-weight:700;">SID ${ev.sid || "—"}</span>
                <strong style="color:var(--fg-bright);margin-left:6px;font-size:13px;">${escapeHtml(ev.msg || "Snort Signature")}</strong>
              </div>
              <span class="kpi-pill crit" style="font-size:10.5px;">Priority ${ev.priority || 1}</span>
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--fg-bright);">Matching Conditions:</strong> ${escapeHtml(ev.matching_conditions || "—")}
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--fg-bright);">Triggering Packets:</strong> <span class="badge-sig" style="font-family:var(--font-mono);font-size:11px;">[${pkts}]</span>
              · <strong style="color:var(--fg-bright);">Activity Context:</strong> ${escapeHtml(ev.activity_relationship || "Malicious session activity")}
            </div>
            ${ev.coverage_limitations ? `
              <div style="background:rgba(245,158,11,0.06);border-left:2px solid var(--warn);padding:6px 10px;border-radius:4px;font-size:11.5px;color:var(--fg-secondary);margin-top:2px;">
                <strong style="color:var(--warn);">Coverage Limitations:</strong> ${escapeHtml(ev.coverage_limitations)}
              </div>
            ` : ""}
            ${ev.uncovered_related_events ? `
              <div style="background:rgba(239,68,68,0.06);border-left:2px solid var(--crit);padding:6px 10px;border-radius:4px;font-size:11.5px;color:var(--fg-secondary);margin-top:2px;">
                <strong style="color:var(--crit);">Uncovered Events:</strong> ${escapeHtml(ev.uncovered_related_events)}
              </div>
            ` : ""}
          `;
          listEl.appendChild(card);
        });
      }
    }

    const rawEl = document.getElementById("gen-rep-a-raw-json");
    if (rawEl) {
      rawEl.textContent = JSON.stringify(res || {}, null, 2);
    }
  }

  function renderGenRepTaskB(res, captureId, isCached, meta) {
    const metaEl = document.getElementById("gen-rep-b-header-meta");
    const fn = meta?.filename || (currentReport?.capture_id === captureId ? currentReport.filename : "");
    const fam = meta?.malware_family || (currentReport?.capture_id === captureId ? currentReport.malware_family : "Malware Traffic");
    if (metaEl) metaEl.textContent = `Capture: ${captureId} ${fn ? `(${fn})` : ''} · ${fam}`;
    const badgeEl = document.getElementById("gen-rep-b-cached-badge");
    if (badgeEl) badgeEl.style.display = isCached ? "inline-block" : "none";

    function renderPills(containerId, items, badgeClass = "badge-sig") {
      const el = document.getElementById(containerId);
      if (!el) return;
      el.innerHTML = "";
      if (!items || items.length === 0) {
        el.innerHTML = '<span style="color:var(--fg-muted);font-style:italic;font-size:11px;">None identified</span>';
        return;
      }
      items.forEach(it => {
        const span = document.createElement("span");
        span.className = badgeClass;
        span.style.fontSize = "11px";
        span.style.padding = "2px 6px";
        span.textContent = typeof it === "string" ? it : JSON.stringify(it);
        el.appendChild(span);
      });
    }

    renderPills("gen-rep-b-static-list", res?.static_indicators || []);
    renderPills("gen-rep-b-protocol-list", res?.protocol_indicators || []);
    renderPills("gen-rep-b-behavioural-list", res?.behavioural_indicators || []);
    renderPills("gen-rep-b-campaign-list", res?.campaign_specific_indicators || []);

    const patternsList = document.getElementById("gen-rep-b-patterns-list");
    const countEl = document.getElementById("gen-rep-b-pattern-count");
    if (patternsList) {
      patternsList.innerHTML = "";
      const patterns = res?.reusable_patterns || [];
      if (countEl) countEl.textContent = `${patterns.length} Pattern${patterns.length !== 1 ? 's' : ''}`;

      if (patterns.length === 0) {
        patternsList.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;padding:12px;">No reusable patterns discovered for this capture.</div>';
      } else {
        patterns.forEach(p => {
          const card = document.createElement("div");
          card.className = "corr-event-item";
          card.style.cssText = "border-left:3px solid var(--ok);background:var(--bg-base);padding:12px;border-radius:6px;border:1px solid var(--border-subtle);display:flex;flex-direction:column;gap:6px;";
          card.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong style="color:var(--ok);font-size:13.5px;">${escapeHtml(p.pattern_name || "Discovered Pattern")}</strong>
              <span class="badge-sig" style="font-size:11px;">Protocol: ${escapeHtml(p.protocol || "TCP/HTTP")}</span>
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--fg-bright);">Stable Characteristics:</strong> ${escapeHtml(p.stable_characteristics || "—")}
            </div>
            <div style="font-size:12px;color:var(--fg-secondary);line-height:1.5;">
              <strong style="color:var(--accent);">Generalization Rationale:</strong> ${escapeHtml(p.generalization_rationale || "—")}
            </div>
          `;
          patternsList.appendChild(card);
        });
      }
    }

    const rawEl = document.getElementById("gen-rep-b-raw-json");
    if (rawEl) {
      rawEl.textContent = JSON.stringify(res || {}, null, 2);
    }
  }

  // 6. Rule Synthesis & Modal Inspection (Requirement 6)
  async function generateRule() {
    if (!currentReport) return alert("Please select or analyze a PCAP first.");
    setLoading(true, "LLM Task C: Engineering Candidate Snort 3 Rule...");
    try {
      const res = await fetch(`/api/pipeline/generate/${currentReport.capture_id}`, { method: "POST" });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data || data.status !== "success" || !data.candidate) {
        const msg = (data && data.message) ? data.message : `HTTP ${res.status}: Candidate rule generation failed. Check terminal logs for detailed error.`;
        alert("Rule Generation Failed:\n" + msg);
        return;
      }
      currentCandidate = data.candidate;
      await loadCandidates();
      window.selectCandidate(currentCandidate.rule_id);
    } catch (err) {
      alert("Rule Generation Error: " + (err.message || err));
    } finally {
      setLoading(false);
    }
  }

  // Populates Candidate Rule & 4-Stage Validation Modal
  function renderCandidateRule(cand) {
    const modal = document.getElementById("candidate-rule-modal");
    if (!modal) return;

    document.getElementById("candidate-modal-sid").textContent = `SID ${cand.rule_id}`;
    document.getElementById("candidate-modal-status").textContent = cand.status;
    document.getElementById("candidate-modal-status").className = cand.status === "APPROVED_DEPLOYED"
      ? "kpi-pill ok"
      : cand.status === "PENDING_REVIEW"
        ? "kpi-pill warn"
        : cand.status.startsWith("FAILED")
          ? "kpi-pill crit"
          : "kpi-pill dim";

    document.getElementById("candidate-modal-text").textContent = cand.rule_text;
    document.getElementById("candidate-modal-objective").textContent = cand.rule_objective || "Candidate Snort 3 Detection Rule";
    document.getElementById("candidate-modal-source").textContent = cand.source_pcap || "—";
    document.getElementById("candidate-modal-logic").textContent = typeof cand.matching_logic === "object"
      ? JSON.stringify(cand.matching_logic, null, 2)
      : cand.matching_logic;
    document.getElementById("candidate-modal-generalization").textContent = cand.generalization || "—";
    document.getElementById("candidate-modal-limitations").textContent = cand.limitations || "—";
    document.getElementById("candidate-modal-fp").textContent = cand.false_positive_risks || "—";
    document.getElementById("candidate-modal-confidence").textContent = cand.confidence || "High";

    const copyBtn = document.getElementById("candidate-modal-copy-rule");
    if (copyBtn) {
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(cand.rule_text).then(() => {
          copyBtn.textContent = "Copied!";
          setTimeout(() => { copyBtn.textContent = "Copy Rule"; }, 2000);
        });
      };
    }

    if (cand.validation_results) {
      renderValidationMatrix(cand.validation_results);
    } else {
      ["1", "2", "3", "4"].forEach(st => {
        const el = document.getElementById(`modal-val-stage${st}-status`);
        if (el) { el.textContent = "—"; el.className = "kpi-pill dim"; }
      });
      const appBtn = document.getElementById("modal-btn-approve-rule");
      const rejBtn = document.getElementById("modal-btn-reject-rule");
      if (appBtn) appBtn.disabled = true;
      if (rejBtn) rejBtn.disabled = true;
    }

    modal.classList.add("open");
  }

  // 7. Rule Validation (Updates Validation Matrix Inside Modal)
  async function validateRule() {
    if (!currentCandidate) return alert("No candidate rule selected for validation.");
    setLoading(true, `Running 4-Stage Snort Validation Pipeline for SID ${currentCandidate.rule_id}...`);
    try {
      const res = await fetch(`/api/pipeline/validate/${currentCandidate.rule_id}`, { method: "POST" });
      const data = await res.json().catch(() => null);
      if (!res.ok || !data) {
        throw new Error(data && data.message ? data.message : `HTTP ${res.status}: Validation request failed`);
      }
      if (data.status === "success" && data.validation) {
        currentValidation = data.validation;
        renderValidationMatrix(currentValidation);
        await loadCandidates();
      } else {
        alert("Validation error: " + (data.message || "Unknown error"));
      }
    } catch (err) {
      alert("Validation Error: " + (err.message || err));
    } finally {
      setLoading(false);
    }
  }

  function renderValidationMatrix(val) {
    const s1 = val.stage1_syntax || {};
    const s1El = document.getElementById("modal-val-stage1-status");
    if (s1El) {
      s1El.textContent = s1.passed ? "PASSED" : "FAILED";
      s1El.className = s1.passed ? "kpi-pill ok" : "kpi-pill crit";
    }
    const s1D = document.getElementById("modal-val-stage1-details");
    if (s1D) {
      s1D.textContent = s1.passed
        ? "Snort configuration test (-T) compiled rule cleanly."
        : "Error: " + (s1.error_output || "Syntax check failed");
    }

    const s2 = val.stage2_positive || {};
    const s2El = document.getElementById("modal-val-stage2-status");
    const s2Passed = (s2.detected_pcaps_count || 0) > 0;
    if (s2El) {
      s2El.textContent = s2Passed ? "PASSED" : "FAILED / NO TRIGGER";
      s2El.className = s2Passed ? "kpi-pill ok" : "kpi-pill crit";
    }
    const s2D = document.getElementById("modal-val-stage2-details");
    if (s2D) {
      s2D.textContent = `Detected ${s2.detected_pcaps_count || 0}/${s2.tested_pcaps_count || 0} motivating PCAPs (${s2.total_alerts || 0} alerts).`;
    }

    const s3 = val.stage3_negative || {};
    const s3El = document.getElementById("modal-val-stage3-status");
    const s3Passed = (s3.false_positive_pcaps_count || 0) === 0;
    if (s3El) {
      s3El.textContent = s3Passed ? "PASSED (0 FP)" : "FAILED (FP DETECTED)";
      s3El.className = s3Passed ? "kpi-pill ok" : "kpi-pill crit";
    }
    const s3D = document.getElementById("modal-val-stage3-details");
    if (s3D) {
      s3D.textContent = `${s3.false_positive_pcaps_count || 0} false positive alerts on benign captures.`;
    }

    const s4 = val.stage4_generalization || {};
    const s4El = document.getElementById("modal-val-stage4-status");
    const s4D = document.getElementById("modal-val-stage4-details");
    if (s4El) {
      if (s4.status === "SKIPPED") {
        s4El.textContent = "SKIPPED (NO FAMILY HOLDOUT)";
        s4El.className = "kpi-pill muted";
        if (s4D) s4D.textContent = s4.reason || "No matching malware family in holdout split. Clean skip applied without penalty.";
      } else {
        const detected = s4.detected_pcaps_count || 0;
        const tested = s4.tested_holdout_count || 0;
        const crossClean = s4.cross_family_clean_count || 0;
        s4El.textContent = `${detected}/${tested} DETECTED` + (crossClean > 0 ? ` (+${crossClean} TN)` : "");
        s4El.className = (detected > 0 || crossClean > 0) ? "kpi-pill ok" : "kpi-pill warn";
        if (s4D) {
          let desc = `${detected} variants detected out of ${tested} holdouts.`;
          if (crossClean > 0) desc += ` ${crossClean} cross-family PCAPs verified clean (True Negatives).`;
          s4D.textContent = desc;
        }
      }
    }

    const m = val.metrics || {};
    const tpEl = document.getElementById("modal-metric-tp");
    if (tpEl) tpEl.textContent = m.true_positives || 0;
    const fpEl = document.getElementById("modal-metric-fp");
    if (fpEl) fpEl.textContent = m.false_positives || 0;
    const fnEl = document.getElementById("modal-metric-fn");
    if (fnEl) fnEl.textContent = m.false_negatives || 0;
    const precEl = document.getElementById("modal-metric-precision");
    if (precEl) precEl.textContent = (m.precision || 0).toFixed(3);
    const recEl = document.getElementById("modal-metric-recall");
    if (recEl) recEl.textContent = (m.recall || 0).toFixed(3);
    const f1El = document.getElementById("modal-metric-f1");
    if (f1El) f1El.textContent = (m.f1_score || 0).toFixed(3);

    const appBtn = document.getElementById("modal-btn-approve-rule");
    const rejBtn = document.getElementById("modal-btn-reject-rule");
    if (appBtn) appBtn.disabled = false;
    if (rejBtn) rejBtn.disabled = false;
  }

  // 8. Lifecycle Management & Analyst Reviews
  async function reviewRule(action) {
    if (!currentCandidate) return alert("No candidate rule to review.");
    const notes = prompt(`Enter analyst review notes for ${action.toUpperCase()}:`, `Analyst ${action} after inspecting evidence & validation matrix`);
    if (notes === null) return;

    setLoading(true, `Recording analyst review (${action})...`);
    try {
      const res = await fetch(`/api/pipeline/review/${currentCandidate.rule_id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: action, analyst: "SOC-Analyst-Lead", notes: notes })
      });
      const data = await res.json();
      if (data.status === "success") {
        currentCandidate = data.candidate;
        renderCandidateRule(currentCandidate);
        await loadCandidates();
        alert(`Rule SID ${currentCandidate.rule_id} status updated to: ${data.candidate.status}`);
      }
    } catch (err) {
      alert("Review Error: " + err);
    } finally {
      setLoading(false);
    }
  }

  async function promptRollback() {
    const vStr = prompt("Enter ruleset version number to rollback to (e.g., 1):", "1");
    if (!vStr) return;
    const reason = prompt("Enter rollback justification:", "False positive mitigation");
    if (!reason) return;

    setLoading(true, `Rolling back local.rules to version v${vStr}...`);
    try {
      const res = await fetch("/api/pipeline/rollback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: parseInt(vStr), analyst: "SOC-Lead", reason: reason })
      });
      const data = await res.json();
      alert("Rollback Successful: " + JSON.stringify(data.result));
      await loadCandidates();
    } catch (err) {
      alert("Rollback Error: " + err);
    } finally {
      setLoading(false);
    }
  }

  // 9. Candidate Table & Audit Log (Requirements 2, 4, 5, 6)
  async function loadCandidates() {
    try {
      const res = await fetch("/api/pipeline/rules");
      const data = await res.json();
      if (data.status === "success") {
        renderCandidatesTable(data.candidates || []);
        renderAuditLog(data.audit_log || []);
        const cCount = (data.candidates || []).length;
        const navCount = document.getElementById("nav-count-candidates");
        if (navCount) navCount.textContent = cCount;
        const headerCount = document.getElementById("studio-header-candidates-count");
        if (headerCount) headerCount.textContent = `${cCount} Candidates`;
      }
    } catch (err) {
      console.error("Failed to load candidates:", err);
    }
  }

  function renderCandidatesTable(cands) {
    const tbody = document.getElementById("pipeline-candidates-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    // Requirement 2: Horizontal scrolling enabled, never leak out of card
    const container = document.getElementById("pipeline-candidates-table-container");
    if (container) {
      container.style.overflowX = "auto";
      container.style.maxWidth = "100%";
      container.style.width = "100%";
      if (cands.length > 20) {
        container.style.maxHeight = "420px";
        container.style.overflowY = "auto";
      } else {
        container.style.maxHeight = "none";
        container.style.overflowY = "visible";
      }
    }

    if (cands.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No candidates registered yet.</td></tr>';
      return;
    }

    cands.forEach(c => {
      const tr = document.createElement("tr");
      tr.className = "clickable-row";
      tr.title = "Click to inspect candidate rule and 4-stage validation matrix";
      tr.onclick = () => window.selectCandidate(c.rule_id);

      const statusBadge = c.status === "APPROVED_DEPLOYED"
        ? '<span class="kpi-pill ok">DEPLOYED</span>'
        : c.status === "PENDING_REVIEW"
          ? '<span class="kpi-pill warn">PENDING REVIEW</span>'
          : c.status.startsWith("FAILED")
            ? `<span class="kpi-pill crit">${c.status}</span>`
            : `<span class="kpi-pill dim">${c.status}</span>`;

      const fbBadge = (c.fallback_used || c.synthesis_source === "deterministic_fallback")
        ? '<span class="badge-sig" style="color:var(--warn);border-color:rgba(234,179,8,0.4);font-size:10px;margin-left:4px;" title="Synthesized via deterministic PCAP telemetry fallback">⚡ Fallback</span>'
        : '';

      tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-weight:600;">SID ${c.rule_id}${fbBadge}</td>
        <td>${statusBadge}</td>
        <td class="col-objective"><strong>${c.rule_objective || '—'}</strong></td>
        <td><span class="badge-sig">${c.source_pcap || '—'}</span></td>
        <td style="font-size:12px;color:var(--fg-muted);">${c.created_at ? c.created_at.split('T')[0] : '—'}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  window.selectCandidate = async function(sid) {
    try {
      const res = await fetch("/api/pipeline/rules");
      const data = await res.json();
      const cand = (data.candidates || []).find(c => c.rule_id === sid);
      if (cand) {
        currentCandidate = cand;
        renderCandidateRule(cand);
      }
    } catch (e) {
      console.error("Error inspecting candidate:", e);
    }
  };

  function renderAuditLog(logEntries) {
    const box = document.getElementById("pipeline-audit-log");
    if (!box) return;
    box.innerHTML = "";

    if (logEntries.length > 20) {
      box.style.maxHeight = "380px";
      box.style.overflowY = "auto";
    } else {
      box.style.maxHeight = "none";
      box.style.overflowY = "visible";
    }

    if (logEntries.length === 0) {
      box.innerHTML = '<div style="color:var(--fg-muted);font-style:italic;">No ruleset modifications yet.</div>';
      return;
    }

    logEntries.slice().reverse().forEach(e => {
      const div = document.createElement("div");
      div.className = "corr-event-item";
      div.innerHTML = `
        <div style="display:flex;justify-content:space-between;">
          <strong>[${e.action}] Version ${e.version || e.target_version}</strong>
          <span style="font-size:11px;color:var(--fg-muted);">${e.timestamp}</span>
        </div>
        <div style="font-size:12px;margin-top:3px;color:var(--fg-secondary);">
          Analyst: <strong>${e.analyst}</strong> | Notes: ${e.notes || e.reason || '—'}
        </div>
      `;
      box.appendChild(div);
    });
  }

  // 10. Autonomous Pipeline Coordinator
  async function runFullPipeline() {
    if (!currentReport) return alert("Please select a PCAP capture first.");
    const cid = currentReport.capture_id;
    setLoading(true, `Running Autonomous End-to-End Pipeline on ${cid}...`);
    try {
      await loadReport(cid, true);
      const genRes = await fetch(`/api/pipeline/generate/${cid}`, { method: "POST" });
      const genData = await genRes.json().catch(() => null);
      if (!genRes.ok || !genData || genData.status !== "success" || !genData.candidate) {
        const msg = (genData && genData.message) ? genData.message : `HTTP ${genRes.status}: Failed to generate candidate rule. Check terminal logs.`;
        throw new Error(msg);
      }
      currentCandidate = genData.candidate;

      const valRes = await fetch(`/api/pipeline/validate/${currentCandidate.rule_id}`, { method: "POST" });
      const valData = await valRes.json().catch(() => null);
      if (!valRes.ok || !valData) {
        throw new Error(valData && valData.message ? valData.message : `HTTP ${valRes.status}: Validation failed`);
      }
      currentValidation = valData.validation;

      await loadCandidates();
      window.selectCandidate(currentCandidate.rule_id);
    } catch (err) {
      alert("Pipeline Execution Error: " + (err.message || err));
    } finally {
      setLoading(false);
    }
  }

  function setLoading(isLoading, text = "") {
    const banner = document.getElementById("pipeline-loading-banner");
    if (!banner) return;
    if (isLoading) {
      banner.style.display = "flex";
      document.getElementById("pipeline-loading-text").textContent = text;
    } else {
      banner.style.display = "none";
    }
  }

})();
