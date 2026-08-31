'use client';

import React, { useState, useEffect, useMemo } from 'react';
import {
  getSystemHealth,
  getOperationalMetrics,
  getThreatAlerts,
  getDetectorInsights
} from '@/services/api';
import { createPassiveShieldSocket } from '@/services/socket';
import { adaptThreatAlertToIncident, adaptMetrics } from '@/services/dataAdapter';
import {
  mockInitialIncidents,
  mockThreatIntelligence,
  mockDetectorEngineSpecs
} from '@/data/mockData';

const navItems = [
  ['01', 'COMMAND CENTER', '◈'],
  ['02', 'LIVE MONITORING', '◌'],
  ['03', 'THREAT INCIDENTS', '△'],
  ['04', 'ATTACK STORY', '↗'],
  ['05', 'THREAT INTELLIGENCE', '⊙'],
  ['06', 'DETECTION ENGINE', '⌁'],
  ['07', 'EVIDENCE ANALYSIS', '▤'],
  ['08', 'SYSTEM ARCHITECTURE', '⌘'],
  ['09', 'TESTING & VALIDATION', '✓'],
  ['10', 'ABOUT PASSIVESHIELD', 'i'],
];

function Badge({ children, tone = 'neutral' }) {
  const toneLower = String(tone).toLowerCase();
  return <span className={`badge badge-${toneLower}`}>{children}</span>;
}

function Sparkline() {
  return (
    <svg className="sparkline" viewBox="0 0 420 90" role="img" aria-label="Risk score trend">
      <polyline
        points="0,70 35,64 70,69 105,51 140,57 175,44 210,50 245,27 280,36 315,23 350,34 385,12 420,20"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
      />
      <line x1="0" y1="78" x2="420" y2="78" />
    </svg>
  );
}

function SystemHeader({ isConnected, utcTime, newAlertCount }) {
  return (
    <header className="topbar">
      <div className="brand-lockup">
        <div className="brand-mark">PS</div>
        <div>
          <h1>PASSIVESHIELD <span>AI</span></h1>
          <p>AI-BASED PASSIVE CYBER THREAT DETECTION · SIH 26145</p>
        </div>
      </div>
      <div className="header-status">
        <div>
          <small>SYSTEM STATUS</small>
          <strong>
            <i className={`status-dot ${isConnected ? 'pulse' : ''}`} />
            {isConnected ? 'LIVE (PORT 3001)' : 'STANDALONE / READY'}
          </strong>
        </div>
        <div>
          <small>MONITORING MODE</small>
          <strong className="blue-text">PASSIVE / UNIDIRECTIONAL</strong>
        </div>
        <div className="header-time">
          <small>UTC CLOCK</small>
          <strong>{utcTime}</strong>
        </div>
        <button className="icon-button" aria-label="View alert queue" title="Live Threat Queue">
          ◇{newAlertCount > 0 && <sup>{newAlertCount}</sup>}
        </button>
      </div>
    </header>
  );
}

function Sidebar({ active, setActive, isConnected, lastSyncTime }) {
  return (
    <aside className="sidebar">
      <div className="side-kicker">
        OPERATIONS PORTAL <span>v2.6.1</span>
      </div>
      <nav aria-label="Primary navigation">
        {navItems.map(([num, label, icon]) => (
          <button
            key={label}
            className={active === label ? 'nav-item active' : 'nav-item'}
            onClick={() => setActive(label)}
          >
            <span className="nav-number">{num}</span>
            <span className="nav-icon">{icon}</span>
            <span>{label}</span>
            {active === label && <b>›</b>}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <div className="connection-line">
          <i className={`status-dot ${isConnected ? 'pulse' : ''}`} />
          {isConnected ? 'SOCKET.IO STREAM LIVE' : 'REST API READY'}
        </div>
        <p>
          Last Telemetry Sync<br />
          <strong>{lastSyncTime || 'Just now'}</strong>
        </p>
        <div className="classification">INTERNAL // SIH26145 DEFENSE</div>
      </div>
    </aside>
  );
}

function Panel({ title, eyebrow, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h3>{title}</h3>
      </div>
      {children}
    </section>
  );
}

function CommandCenterView({ incidents, metrics, openIncident, refreshData, isLive }) {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">01 / COMMAND CENTER</span>
          <h2>Operational Overview</h2>
          <p>Real-time passive traffic intelligence across protected unidirectional optical networks.</p>
        </div>
        <div className="heading-actions">
          <button className="secondary-button" onClick={() => window.print()}>Export Brief</button>
          <button className="primary-button" onClick={refreshData}>Refresh Pipeline</button>
        </div>
      </div>

      <div className="identity-strip">
        <div className="identity-main">
          <span className="shield">⬡</span>
          <div>
            <span className="eyebrow">SYSTEM IDENTITY</span>
            <h3>PassiveShield AI</h3>
            <p>Unidirectional Cyber Threat Sensor & Threat Fusion Engine</p>
          </div>
        </div>
        <div className="identity-rule" />
        <div>
          <span className="eyebrow">CORE CONSTRAINT</span>
          <strong>OBSERVE ONLY</strong>
          <p>0 packets sent · 0 active probes</p>
        </div>
        <div>
          <span className="eyebrow">PHYSICAL TAP</span>
          <strong>OPTICAL DIODE</strong>
          <p>Rx-Only Fiber · Segment A / Gateway 03</p>
        </div>
      </div>

      <div className="metric-grid">
        {metrics.map(([label, value, note]) => (
          <div className="metric-card" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
            <small>{note}</small>
          </div>
        ))}
      </div>

      <div className="dashboard-grid">
        <Panel title="Active Correlated Threats" eyebrow="THREAT OVERVIEW" className="incidents-panel">
          <div className="panel-meta">
            <span>Recent Observations</span>
            <Badge tone={isLive ? 'low' : 'medium'}>{isLive ? 'LIVE FEED CONNECTED' : 'DEMO & LAB FEED'}</Badge>
          </div>
          <div className="incident-list">
            {incidents.slice(0, 8).map(item => (
              <button className="incident-row" key={item.id} onClick={() => openIncident(item)}>
                <div className={`severity-bar severity-${item.severity.toLowerCase()}`} />
                <div className="incident-copy">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <strong>{item.title}</strong>
                    {item.isStop ? (
                      <Badge tone="low">STOPPED / BENIGN</Badge>
                    ) : (
                      <Badge tone={item.severity}>{item.severity}</Badge>
                    )}
                    {item.direction && (
                      <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', color: '#8db7d6' }}>
                        {item.direction}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '11px', color: '#8ea5b8', display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                    <span><b style={{ color: '#ff8a80' }}>SRC:</b> {item.srcIp} <small style={{ opacity: 0.75 }}>({item.originTag})</small></span>
                    <span>➔</span>
                    <span><b style={{ color: '#80d8ff' }}>DST:</b> {item.dstIp} <small style={{ opacity: 0.75 }}>({item.targetTag})</small></span>
                    <span style={{ marginLeft: 'auto', fontWeight: 600, color: item.isStop ? '#69f0ae' : '#ffb74d' }}>
                      {item.isStop ? '✓ ' : '● '}{item.status}
                    </span>
                  </div>
                </div>
                <span className="row-score">{item.score}</span>
                <span className="row-arrow">›</span>
              </button>
            ))}
          </div>
          <button className="text-button" onClick={() => {}}>
            Viewing {incidents.length} correlated alerts <span>→</span>
          </button>
        </Panel>

        <Panel title="Risk Evolution (Noisy-OR)" eyebrow="PROBABILISTIC FUSION" className="risk-panel">
          <div className="risk-value">
            <strong>88</strong>
            <span>/ 100 <em>+15% Multi-Vector Boost</em></span>
          </div>
          <p>Composite passive risk score derived from multi-detector evidence</p>
          <Sparkline />
          <div className="chart-labels">
            <span>T - 30m</span>
            <span>T - 15m</span>
            <span>NOW (T-0)</span>
          </div>
          <div className="demo-note">FUSED EVIDENCE · Noisy-OR Independence Model with 1.15x Boost</div>
        </Panel>
      </div>

      <div className="bottom-grid">
        <Panel title="Detector Coverage & Health" eyebrow="DETECTION ENGINE">
          <div className="coverage-row">
            <div className="coverage-ring">
              <strong>6</strong>
              <span>ONLINE</span>
            </div>
            <div className="coverage-items">
              <span><i className="status-dot" /> DDoS & Volumetric Flood <b>100%</b></span>
              <span><i className="status-dot" /> Port Scan & Subnet Sweep <b>100%</b></span>
              <span><i className="status-dot" /> C2 Beaconing (FFT Peak) <b>100%</b></span>
              <span><i className="status-dot" /> DNS Tunneling & DGA <b>100%</b></span>
              <span><i className="status-dot" /> Data Exfiltration (MAD Z-Score) <b>100%</b></span>
              <span><i className="status-dot" /> TLS JA3/JA4 Cryptographic Signatures <b>100%</b></span>
            </div>
          </div>
        </Panel>

        <Panel title="Passive Evidence Assurance" eyebrow="DATA DIODE VERIFICATION">
          <div className="evidence-row">
            <div>
              <span>FLOWS OBSERVED</span>
              <strong>1,471 Pkts</strong>
            </div>
            <div>
              <span>FEATURES EXTRACTED</span>
              <strong>28+ Metrics</strong>
            </div>
            <div>
              <span>MEDIAN LATENCY</span>
              <strong className="blue-text">0.210 ms</strong>
            </div>
          </div>
          <div className="evidence-note">Strictly Unidirectional · Rx-Only Fiber · Payload Decryption NOT Required</div>
        </Panel>
      </div>
    </div>
  );
}

function LiveMonitoringView({ incidents, isConnected, openIncident }) {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">02 / LIVE MONITORING</span>
          <h2>Real-Time Socket.IO Telemetry Feed</h2>
          <p>Streaming alerts pushed over the approved &apos;cyber_alerts&apos; Redis Pub/Sub bus to Socket.IO &apos;alert:new&apos;.</p>
        </div>
        <div className="connection-line" style={{ fontSize: '12px' }}>
          <i className={`status-dot ${isConnected ? 'pulse' : ''}`} />
          {isConnected ? 'LIVE WEBSOCKET LISTENER CONNECTED (PORT 3001)' : 'CONNECTING TO WEBSOCKET STREAM...'}
        </div>
      </div>

      <Panel title="Real-Time Event Stream" eyebrow="EVENT CHANNEL: alert:new">
        <div className="incident-list">
          {incidents.map((item) => (
            <button className="incident-row" key={item.id} onClick={() => openIncident(item)}>
              <div className={`severity-bar severity-${item.severity.toLowerCase()}`} />
              <div className="incident-copy">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <strong>{item.title}</strong>
                  {item.isStop ? (
                    <Badge tone="low">STOPPED / BENIGN</Badge>
                  ) : (
                    <Badge tone={item.severity}>{item.severity}</Badge>
                  )}
                  {item.direction && (
                    <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', color: '#8db7d6' }}>
                      {item.direction}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '11px', color: '#8ea5b8', display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                  <span><b style={{ color: '#ff8a80' }}>SRC:</b> {item.srcIp} <small style={{ opacity: 0.75 }}>({item.originTag})</small></span>
                  <span>➔</span>
                  <span><b style={{ color: '#80d8ff' }}>DST:</b> {item.dstIp} <small style={{ opacity: 0.75 }}>({item.targetTag})</small></span>
                  <span style={{ marginLeft: 'auto', fontWeight: 600, color: item.isStop ? '#69f0ae' : '#ffb74d' }}>
                    {item.isStop ? '✓ ' : '● '}{item.status}
                  </span>
                </div>
              </div>
              <span className="row-score">{item.score}</span>
              <span className="row-arrow">›</span>
            </button>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function ThreatIncidentsView({ incidents, openIncident }) {
  const [filter, setFilter] = useState('ALL');
  const filtered = useMemo(() => {
    if (filter === 'ALL') return incidents;
    if (filter === 'STOPPED') return incidents.filter(i => i.isStop);
    return incidents.filter(i => i.severity === filter && !i.isStop);
  }, [incidents, filter]);

  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">03 / THREAT INCIDENTS</span>
          <h2>Correlated Threat Incidents</h2>
          <p>Multi-detector threat alerts generated by the ThreatFusionEngine with preserved evidence cards.</p>
        </div>
        <div className="heading-actions" style={{ display: 'flex', gap: '8px' }}>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'STOPPED'].map(lvl => (
            <button
              key={lvl}
              className={filter === lvl ? 'primary-button' : 'secondary-button'}
              onClick={() => setFilter(lvl)}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      <Panel title={`Threat Incident Queue (${filtered.length})`} eyebrow="INCIDENT REPOSITORY">
        <div className="incident-list">
          {filtered.map(item => (
            <button className="incident-row" key={item.id} onClick={() => openIncident(item)}>
              <div className={`severity-bar severity-${item.severity.toLowerCase()}`} />
              <div className="incident-copy">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  <strong>{item.title}</strong>
                  {item.isStop ? (
                    <Badge tone="low">STOPPED / BENIGN</Badge>
                  ) : (
                    <Badge tone={item.severity}>{item.severity}</Badge>
                  )}
                  {item.direction && (
                    <span style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', color: '#8db7d6' }}>
                      {item.direction}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: '11px', color: '#8ea5b8', display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
                  <span><b style={{ color: '#ff8a80' }}>SRC:</b> {item.srcIp} <small style={{ opacity: 0.75 }}>({item.originTag})</small></span>
                  <span>➔</span>
                  <span><b style={{ color: '#80d8ff' }}>DST:</b> {item.dstIp} <small style={{ opacity: 0.75 }}>({item.targetTag})</small></span>
                  <span style={{ marginLeft: 'auto', fontWeight: 600, color: item.isStop ? '#69f0ae' : '#ffb74d' }}>
                    {item.isStop ? '✓ ' : '● '}{item.status}
                  </span>
                </div>
              </div>
              <span className="row-score">{item.score}</span>
              <span className="row-arrow">›</span>
            </button>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function AttackStoryView() {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">04 / ATTACK STORY</span>
          <h2>Multi-Vector Incident Journey</h2>
          <p>Chronological correlation of disparate signals reconstructed by the Threat Fusion Engine.</p>
        </div>
      </div>

      <div className="feature-grid">
        <Panel title="Reconstructed Cyber Kill-Chain" eyebrow="CORRELATION JOURNEY">
          <div className="note-list">
            <div>
              <strong>1. Reconnaissance & Subnet Sweep (T - 45m)</strong>
              <span>Host 10.10.1.55 initiated horizontal SYN probes across 28 distinct subnet IPs. Caught by PortScanDetector (unique_ips &gt; 10).</span>
            </div>
            <div>
              <strong>2. DGA Query & DNS Tunnel Staging (T - 25m)</strong>
              <span>Host queried high-entropy algorithmic domain names (Shannon entropy 4.12 bits). DNSAnomalyDetector flagged DGA_HIGH_ENTROPY.</span>
            </div>
            <div>
              <strong>3. Command & Control Heartbeat Established (T - 12m)</strong>
              <span>Periodic TLS handshakes with exact 15.0-second intervals observed. C2BeaconDetector flagged SciPy FFT spectral peak (E_peak = 0.84).</span>
            </div>
            <div>
              <strong>4. Asymmetric High-Volume Exfiltration Burst (T - 2m)</strong>
              <span>Outbound directional ratio reached 98.4% with volume burst of 12.4 MB. ExfiltrationDetector computed MAD Robust Z-score of 4.8.</span>
            </div>
          </div>
        </Panel>

        <Panel title="Fusion Correlation Impact" eyebrow="NOISY-OR MATHEMATICS">
          <div className="drawer-score" style={{ marginBottom: '16px' }}>
            <span>CORRELATED MULTI-VECTOR SCORE</span>
            <strong>1.00</strong>
            <small>/ 1.00 (CRITICAL)</small>
          </div>
          <p style={{ color: '#8ea5b8', fontSize: '11px', lineHeight: '1.7' }}>
            When 2 or more distinct threat detectors report threats on the same host, the ThreatFusionEngine applies a 1.15x correlation multiplier on top of the probabilistic noisy-OR independence combination.
          </p>
          <div className="demo-note">EVIDENCE PRESERVED · 4 Independent Detector Signatures Correlated</div>
        </Panel>
      </div>
    </div>
  );
}

function ThreatIntelligenceView() {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">05 / THREAT INTELLIGENCE</span>
          <h2>JA3 / JA4 Cryptographic Malware Signatures</h2>
          <p>Passive ClientHello cryptographic hashes matched without performing SSL/TLS decryption.</p>
        </div>
      </div>

      <Panel title="Known Threat Profiles Database" eyebrow="PASSIVE TLS PROFILES">
        <table className="evidence-table">
          <thead>
            <tr>
              <th>TYPE</th>
              <th>FINGERPRINT / HASH</th>
              <th>MALWARE FAMILY</th>
              <th>SEVERITY</th>
              <th>SENSOR STATUS</th>
            </tr>
          </thead>
          <tbody>
            {mockThreatIntelligence.signatures.map(sig => (
              <tr key={sig.hash}>
                <td><Badge tone="neutral">{sig.type}</Badge></td>
                <td style={{ fontFamily: 'monospace', color: '#7eb8e6' }}>{sig.hash}</td>
                <td><strong>{sig.family}</strong></td>
                <td><Badge tone={sig.severity}>{sig.severity}</Badge></td>
                <td><span className="connection-line"><i className="status-dot" /> {sig.status}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}

function DetectionEngineView() {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">06 / DETECTION ENGINE</span>
          <h2>Active Detector Subsystems</h2>
          <p>Decoupled, high-throughput micro-engines evaluating streaming FeatureSnapshot event contracts.</p>
        </div>
      </div>

      <div className="dashboard-grid">
        {mockDetectorEngineSpecs.map(det => (
          <Panel key={det.name} title={det.name} eyebrow={det.category}>
            <div style={{ marginTop: '8px', fontSize: '11px', color: '#a8bed0' }}>
              <strong>Mathematical Formulation:</strong>
              <p style={{ color: '#7993a8', marginTop: '4px', fontFamily: 'monospace' }}>{det.math}</p>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px' }}>
              <span className="connection-line"><i className="status-dot" /> {det.status}</span>
              <Badge tone="low">PASS RATE {det.rate}</Badge>
            </div>
          </Panel>
        ))}
      </div>
    </div>
  );
}

function EvidenceAnalysisView() {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">07 / EVIDENCE ANALYSIS</span>
          <h2>Explainable Threat Evidence Formulation</h2>
          <p>Deterministic mathematical metrics replacing opaque black-box deep neural networks.</p>
        </div>
      </div>

      <div className="feature-grid">
        <Panel title="Mathematical Formulations in Code" eyebrow="ALGORITHMIC SPECIFICATION">
          <div className="note-list">
            <div>
              <strong>Shannon Information Entropy (DNS &amp; Port Scan)</strong>
              <code>H(X) = -∑ P(x_i) log2 P(x_i) · Trigger: H &gt;= 3.8 bits</code>
            </div>
            <div>
              <strong>SciPy Fast Fourier Transform Spectral Peak (C2 Beacon)</strong>
              <code>E_peak = max(|RFFT(x - x_bar)|^2) / ∑ |RFFT|^2 · Trigger: E_peak &gt;= 0.50</code>
            </div>
            <div>
              <strong>Median Absolute Deviation (MAD) Robust Z-Score (Exfiltration)</strong>
              <code>Z = 0.6745 * (value - median) / (MAD + 1e-5) · Trigger: Z &gt; 3.5</code>
            </div>
            <div>
              <strong>Handshake Asymmetry Ratio (SYN Flood)</strong>
              <code>S_handshake = 0.70 * syn_ratio + 0.30 * ack_missing_ratio</code>
            </div>
          </div>
        </Panel>

        <Panel title="Why Explainability Matters" eyebrow="DEFENSE &amp; SOC COMPLIANCE">
          <p style={{ color: '#8ea5b8', fontSize: '12px', lineHeight: '1.8' }}>
            In high-assurance defense and government environments, security operators cannot act on an opaque 0.89 probability score from a black-box neural net.  
            PassiveShield AI attaches verifiable evidence cards showing exact character lengths, observed packet rates, raw hashes, and mathematical thresholds.
          </p>
        </Panel>
      </div>
    </div>
  );
}

function SystemArchitectureView() {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">08 / SYSTEM ARCHITECTURE</span>
          <h2>Unidirectional Hardware TAP &amp; Pipeline Dataflow</h2>
          <p>Physical isolation guaranteeing 0% packet transmission and 0% active network probing.</p>
        </div>
      </div>

      <Panel title="Physical TAP to SOC Alert Bus Dataflow" eyebrow="HARDWARE &amp; SOFTWARE TOPOLOGY">
        <div style={{ padding: '16px 0', fontFamily: 'monospace', fontSize: '11px', color: '#7eb8e6', lineHeight: '1.9' }}>
          [ Protected Network ] ──( Optical Fiber TAP / Data Diode )──► [ Rx-Only Photodiode ]<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br />
          [ Zeek Log Adapter / PassivePCAPParser ] ──► [ Kafka Topic &apos;raw-flow-events&apos; ]<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br />
          [ Redis Sliding-Window State (ZSETs &amp; TTLs) ] ──► [ FeatureEngine (28+ Metrics) ]<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br />
          [ Decoupled Detectors ] ──► [ ThreatFusionEngine (Noisy-OR) ] ──► [ Redis &apos;cyber_alerts&apos; ]<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│<br />
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;▼<br />
          [ Express REST Gateway (Port 3001) ] ◄──► [ Socket.IO &apos;alert:new&apos; ] ──► [ SOC React UI ]
        </div>
      </Panel>
    </div>
  );
}

function TestingValidationView() {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">09 / TESTING &amp; VALIDATION</span>
          <h2>Verification Test Results &amp; Benchmarks</h2>
          <p>Empirically measured backend throughput, pipeline latency, and test suite pass rates.</p>
        </div>
      </div>

      <div className="metric-grid">
        <div className="metric-card">
          <span>THROUGHPUT</span>
          <strong>4,231</strong>
          <small>events / second</small>
        </div>
        <div className="metric-card">
          <span>MEDIAN LATENCY</span>
          <strong>0.210 ms</strong>
          <small>p95 = 0.400 ms</small>
        </div>
        <div className="metric-card">
          <span>TEST SUITE</span>
          <strong>107 / 107</strong>
          <small>100% Tests Passed</small>
        </div>
        <div className="metric-card">
          <span>ERROR RATE</span>
          <strong>0.00%</strong>
          <small>0 pipeline failures</small>
        </div>
      </div>

      <Panel title="Verification Test Matrix" eyebrow="AUTOMATED REPRODUCIBILITY">
        <table className="evidence-table">
          <thead>
            <tr>
              <th>TEST SUITE</th>
              <th>TEST COMMAND</th>
              <th>TEST COUNT</th>
              <th>RESULT</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Python/JSON Synthetic Attack Test</strong></td>
              <td><code>py -3 scripts/test_attack_dataset.py</code></td>
              <td>8 attacks + 11 edge cases</td>
              <td><Badge tone="low">100% PASS</Badge></td>
            </tr>
            <tr>
              <td><strong>PCAP Real Telemetry E2E Test</strong></td>
              <td><code>py -3 scripts/run_pcap_e2e_validation.py</code></td>
              <td>8 PCAP categories (1,471 pkts)</td>
              <td><Badge tone="low">100% PASS</Badge></td>
            </tr>
            <tr>
              <td><strong>Python Unit &amp; Integration Tests</strong></td>
              <td><code>py -3 -m unittest discover tests</code></td>
              <td>95 unit/contract tests</td>
              <td><Badge tone="low">100% PASS</Badge></td>
            </tr>
            <tr>
              <td><strong>Node.js API &amp; Socket.IO Gateway</strong></td>
              <td><code>npm test --prefix services/api</code></td>
              <td>12 integration tests</td>
              <td><Badge tone="low">100% PASS</Badge></td>
            </tr>
          </tbody>
        </table>
      </Panel>
    </div>
  );
}

function AboutView() {
  return (
    <div className="content-stack">
      <div className="page-heading">
        <div>
          <span className="eyebrow">10 / ABOUT PASSIVESHIELD</span>
          <h2>Built for Networks That Cannot Talk Back</h2>
          <p>Government &amp; Defense grade threat intelligence for strictly unidirectional optical data diodes.</p>
        </div>
      </div>

      <div className="feature-grid">
        <Panel title="Smart India Hackathon 2024 (SIH 26145)" eyebrow="PROBLEM STATEMENT">
          <p style={{ color: '#8ea5b8', fontSize: '12px', lineHeight: '1.8' }}>
            <strong>Title:</strong> AI-Based Detection of Cyber Threats in Unidirectional IP Traffic.<br />
            <strong>Challenge:</strong> Standard IDSs fail in unidirectional environments because they expect bidirectional TCP handshake tracking and packet injection capabilities. PassiveShield AI solves this using strictly forward-directional feature extraction and multi-detector signal fusion.
          </p>
        </Panel>

        <Panel title="Core Architectural Tenets" eyebrow="DESIGN CONSTITUTION">
          <div className="note-list">
            <div>
              <strong>1. Absolute Passivity</strong>
              <span>Never send packets. Never probe hosts. Never inject RSTs.</span>
            </div>
            <div>
              <strong>2. Bounded State</strong>
              <span>Sliding window memory bounds in Redis with strict TTL evictions.</span>
            </div>
            <div>
              <strong>3. Explainable Signals</strong>
              <span>Every threat alert includes verifiable, mathematical evidence tags.</span>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}

export default function PassiveShieldPortal() {
  const [active, setActive] = useState('COMMAND CENTER');
  const [selected, setSelected] = useState(null);
  const [incidents, setIncidents] = useState(mockInitialIncidents);
  const [metrics, setMetrics] = useState([
    ['ACTIVE INCIDENTS', '04', 'Real-time telemetry'],
    ['FLOWS OBSERVED', '1.47K+', 'Unidirectional TAP'],
    ['DETECTION COVERAGE', '100%', '6 detectors active'],
    ['EVIDENCE QUALITY', 'HIGH', 'Passive telemetry']
  ]);
  const [isConnected, setIsConnected] = useState(false);
  const [lastSyncTime, setLastSyncTime] = useState('');
  const [utcTime, setUtcTime] = useState('00:00:00');
  const [newAlertCount, setNewAlertCount] = useState(0);

  // UTC Clock updater
  useEffect(() => {
    const updateTime = () => {
      const d = new Date();
      setUtcTime(d.toTimeString().split(' ')[0]);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Fetch initial REST data from Express backend
  const loadInitialData = async () => {
    try {
      const [health, metricsData, alertsData] = await Promise.all([
        getSystemHealth(),
        getOperationalMetrics(),
        getThreatAlerts({ limit: 10 })
      ]);

      if (health && health.health === 'ok') {
        setIsConnected(true);
      }

      if (alertsData && alertsData.length > 0) {
        const adapted = alertsData.map(adaptThreatAlertToIncident).filter(Boolean);
        setIncidents(adapted);
      }

      if (metricsData) {
        setMetrics(adaptMetrics(metricsData, alertsData ? alertsData.length : 4));
      }

      setLastSyncTime(new Date().toTimeString().split(' ')[0] + ' UTC');
    } catch (e) {
      console.log('[PassiveShield UI] Using offline/demo initial state:', e.message);
      setLastSyncTime(new Date().toTimeString().split(' ')[0] + ' UTC');
    }
  };

  useEffect(() => {
    loadInitialData();

    // Initialize Socket.IO connection
    const socketClient = createPassiveShieldSocket({
      onConnect: () => {
        setIsConnected(true);
      },
      onDisconnect: () => {
        setIsConnected(false);
      },
      onAlert: (alertPayload) => {
        const newIncident = adaptThreatAlertToIncident(alertPayload);
        if (newIncident) {
          setIncidents(prev => [newIncident, ...prev.filter(i => i.id !== newIncident.id)]);
          setNewAlertCount(c => c + 1);
          setLastSyncTime(new Date().toTimeString().split(' ')[0] + ' UTC');
        }
      }
    });

    return () => {
      socketClient.close();
    };
  }, []);

  const renderContent = () => {
    switch (active) {
      case 'COMMAND CENTER':
        return (
          <CommandCenterView
            incidents={incidents}
            metrics={metrics}
            openIncident={setSelected}
            refreshData={loadInitialData}
            isLive={isConnected}
          />
        );
      case 'LIVE MONITORING':
        return (
          <LiveMonitoringView
            incidents={incidents}
            isConnected={isConnected}
            openIncident={setSelected}
          />
        );
      case 'THREAT INCIDENTS':
        return (
          <ThreatIncidentsView
            incidents={incidents}
            openIncident={setSelected}
          />
        );
      case 'ATTACK STORY':
        return <AttackStoryView />;
      case 'THREAT INTELLIGENCE':
        return <ThreatIntelligenceView />;
      case 'DETECTION ENGINE':
        return <DetectionEngineView />;
      case 'EVIDENCE ANALYSIS':
        return <EvidenceAnalysisView />;
      case 'SYSTEM ARCHITECTURE':
        return <SystemArchitectureView />;
      case 'TESTING & VALIDATION':
        return <TestingValidationView />;
      case 'ABOUT PASSIVESHIELD':
        return <AboutView />;
      default:
        return (
          <CommandCenterView
            incidents={incidents}
            metrics={metrics}
            openIncident={setSelected}
            refreshData={loadInitialData}
            isLive={isConnected}
          />
        );
    }
  };

  return (
    <div className="portal">
      <SystemHeader isConnected={isConnected} utcTime={utcTime} newAlertCount={newAlertCount} />
      <div className="shell">
        <Sidebar active={active} setActive={setActive} isConnected={isConnected} lastSyncTime={lastSyncTime} />
        <main className="main-content">{renderContent()}</main>
      </div>

      {selected && (
        <div className="modal-backdrop" onClick={() => setSelected(null)}>
          <aside className="incident-drawer" onClick={e => e.stopPropagation()}>
            <div className="drawer-top">
              <div>
                <span className="eyebrow">INCIDENT DETAIL · {selected.rawClassification}</span>
                <h2>{selected.title}</h2>
              </div>
              <button className="close-button" onClick={() => setSelected(null)} aria-label="Close drawer">
                ×
              </button>
            </div>

            <div className="drawer-id">
              {selected.id} <Badge tone={selected.severity}>{selected.severity}</Badge>
              <span style={{ marginLeft: 'auto', color: '#6f8b9e' }}>Observed: {selected.age}</span>
            </div>

            <div className="drawer-score">
              <span>PROBABILISTIC FUSION SCORE</span>
              <strong>{selected.score}</strong>
              <small>/ 100 ({selected.severity} SEVERITY)</small>
            </div>

            <div className="drawer-facts">
              <div>
                <span>ATTACK ORIGIN (SOURCE)</span>
                <strong style={{ color: '#ff8a80' }}>{selected.srcIp}</strong>
                <small style={{ color: '#8db7d6', display: 'block', marginTop: '2px' }}>{selected.originTag}</small>
              </div>
              <div>
                <span>ATTACK TARGET (DESTINATION)</span>
                <strong style={{ color: '#80d8ff' }}>{selected.dstIp}</strong>
                <small style={{ color: '#8db7d6', display: 'block', marginTop: '2px' }}>{selected.targetTag}</small>
              </div>
              <div>
                <span>DIRECTION &amp; DETECTOR</span>
                <strong>{selected.direction} · {selected.detector}</strong>
              </div>
              <div>
                <span>LIFECYCLE STATE</span>
                <strong style={{ color: selected.isStop ? '#69f0ae' : '#ffb74d' }}>
                  {selected.isStop ? '✓ ' : '● '}{selected.status}
                </strong>
              </div>
            </div>

            <div className="drawer-section">
              <span className="eyebrow">EVIDENCE ANALYSIS &amp; TELEMETRY PROOF</span>
              {selected.evidence && selected.evidence.length > 0 ? (
                <table className="evidence-table">
                  <thead>
                    <tr>
                      <th>CODE</th>
                      <th>DESCRIPTION</th>
                      <th>VALUE</th>
                      <th>THRESHOLD</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.evidence.map((ev, idx) => (
                      <tr key={idx}>
                        <td style={{ fontFamily: 'monospace', color: '#ffb74d' }}>{ev.code}</td>
                        <td>{ev.message}</td>
                        <td style={{ fontWeight: 600, color: '#75b7e5' }}>{String(ev.value)}</td>
                        <td style={{ color: '#8ea5b8' }}>{String(ev.threshold)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <p>Telemetry evidence signals were captured passively from flow inter-arrival times and lexical properties without decrypting packet payloads.</p>
              )}
            </div>

            <button className="primary-button full-button" onClick={() => setSelected(null)}>
              Acknowledge &amp; Return to Feed
            </button>
          </aside>
        </div>
      )}
    </div>
  );
}
