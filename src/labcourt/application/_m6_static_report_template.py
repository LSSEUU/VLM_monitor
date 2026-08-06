"""Inline-only HTML template for the offline M6 regression report."""

# The embedded HTML/CSS keeps complete tags and declarations readable as authored.
# ruff: noqa: E501

M6_STATIC_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>LabCourt M6 regression report</title>
  <style>
    :root {
      color-scheme: light dark;
      --background: #f8fafc;
      --surface: #ffffff;
      --surface-muted: #eef3f9;
      --text: #172033;
      --text-muted: #4b5b73;
      --primary: #1e40af;
      --primary-soft: #dbeafe;
      --border: #cbd5e1;
      --success: #166534;
      --success-soft: #dcfce7;
      --warning: #92400e;
      --warning-soft: #fef3c7;
      --danger: #991b1b;
      --danger-soft: #fee2e2;
      --focus: #1d4ed8;
      --shadow: 0 12px 30px rgba(15, 23, 42, 0.08);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 16px;
      line-height: 1.6;
    }
    * { box-sizing: border-box; }
    html { background: var(--background); scroll-behavior: smooth; }
    body {
      margin: 0;
      min-width: 0;
      background: var(--background);
      color: var(--text);
    }
    a { color: var(--primary); text-underline-offset: 0.18em; }
    a:hover { text-decoration-thickness: 0.14em; }
    :focus-visible { outline: 3px solid var(--focus); outline-offset: 3px; }
    .skip-link {
      position: fixed;
      z-index: 100;
      top: 8px;
      left: 8px;
      padding: 12px 16px;
      border-radius: 8px;
      background: var(--surface);
      color: var(--text);
      transform: translateY(-160%);
      transition: transform 180ms ease-out;
    }
    .skip-link:focus { transform: translateY(0); }
    .shell { width: min(1180px, calc(100% - 32px)); margin: 0 auto; }
    .masthead {
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    .masthead__inner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      min-height: 72px;
      padding: 12px 0;
    }
    .brand { margin: 0; font-weight: 750; letter-spacing: -0.02em; }
    .brand small { display: block; color: var(--text-muted); font-weight: 500; letter-spacing: 0; }
    .classification {
      display: inline-flex;
      align-items: center;
      min-height: 44px;
      padding: 8px 12px;
      border: 1px solid #b45309;
      border-radius: 999px;
      background: var(--warning-soft);
      color: var(--warning);
      font-weight: 750;
      overflow-wrap: anywhere;
    }
    main { padding: 40px 0 64px; }
    h1, h2 { line-height: 1.2; letter-spacing: -0.025em; }
    h1 { max-width: 22ch; margin: 0; font-size: clamp(2rem, 5vw, 3.5rem); }
    h2 { margin: 0 0 16px; font-size: clamp(1.35rem, 3vw, 1.8rem); }
    .lede { max-width: 68ch; margin: 16px 0 0; color: var(--text-muted); }
    .status-line { display: flex; flex-wrap: wrap; gap: 8px; margin: 24px 0 0; }
    .status {
      display: inline-flex;
      align-items: center;
      min-height: 36px;
      padding: 5px 10px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      font-weight: 700;
    }
    .status--pass { border-color: #86efac; background: var(--success-soft); color: var(--success); }
    .status--hold { border-color: #fcd34d; background: var(--warning-soft); color: var(--warning); }
    .panel {
      margin-top: 32px;
      padding: 24px;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: var(--surface);
      box-shadow: var(--shadow);
    }
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin: 0;
    }
    .metric {
      min-width: 0;
      padding: 16px;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: var(--surface-muted);
    }
    .metric dt { color: var(--text-muted); font-size: 0.875rem; font-weight: 650; }
    .metric dd { margin: 4px 0 0; font-size: 1.4rem; font-variant-numeric: tabular-nums; font-weight: 780; overflow-wrap: anywhere; }
    .identity-grid { display: grid; grid-template-columns: minmax(10rem, 1fr) 2fr; gap: 8px 20px; margin: 0; }
    .identity-grid dt { color: var(--text-muted); font-weight: 650; }
    .identity-grid dd { margin: 0; font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 0.875rem; overflow-wrap: anywhere; }
    .artifact-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin: 0; padding: 0; list-style: none; }
    .artifact-list a { display: block; min-height: 44px; padding: 9px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface-muted); overflow-wrap: anywhere; }
    .table-wrap { max-width: 100%; overflow-x: auto; border: 1px solid var(--border); border-radius: 12px; }
    table { width: 100%; border-collapse: collapse; min-width: 900px; font-size: 0.925rem; }
    caption { padding: 12px 14px; text-align: left; color: var(--text-muted); font-weight: 650; }
    th, td { padding: 12px 14px; border-top: 1px solid var(--border); text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    thead th { border-top: 0; background: var(--surface-muted); color: var(--text-muted); font-size: 0.8rem; letter-spacing: 0.04em; text-transform: uppercase; }
    tbody th { max-width: 18rem; font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 0.82rem; }
    tbody tr:hover { background: color-mix(in srgb, var(--primary-soft) 35%, transparent); }
    .evidence-state { display: block; margin-bottom: 6px; font-weight: 750; }
    .evidence-thumb { display: block; width: 176px; max-width: 100%; height: 104px; margin-top: 8px; border: 1px solid var(--border); border-radius: 8px; object-fit: cover; background: var(--surface-muted); }
    .placeholder { max-width: 28rem; padding: 10px; border: 1px dashed var(--border); border-radius: 8px; background: var(--surface-muted); color: var(--text-muted); }
    .mono { font-family: ui-monospace, "SFMono-Regular", Consolas, monospace; font-size: 0.82rem; overflow-wrap: anywhere; }
    .footer-note { margin: 32px 0 0; color: var(--text-muted); font-size: 0.9rem; }
    @media (prefers-color-scheme: dark) {
      :root {
        --background: #0b1220;
        --surface: #111b2e;
        --surface-muted: #17243a;
        --text: #f1f5f9;
        --text-muted: #bdc9da;
        --primary: #93c5fd;
        --primary-soft: #1e3a5f;
        --border: #3a4a62;
        --success: #bbf7d0;
        --success-soft: #143d2a;
        --warning: #fde68a;
        --warning-soft: #4a3214;
        --danger: #fecaca;
        --danger-soft: #4b1d24;
        --focus: #bfdbfe;
        --shadow: none;
      }
      .classification { border-color: #d97706; }
      .status--pass { border-color: #15803d; }
      .status--hold { border-color: #a16207; }
    }
    @media (max-width: 760px) {
      .masthead__inner { align-items: flex-start; flex-direction: column; }
      .metric-grid, .artifact-list { grid-template-columns: 1fr 1fr; }
      .identity-grid { grid-template-columns: 1fr; gap: 2px; }
      .identity-grid dd { margin-bottom: 10px; }
      .panel { padding: 18px; }
    }
    @media (max-width: 375px) {
      .shell { width: min(100% - 24px, 1180px); }
      main { padding-top: 28px; }
      .metric-grid, .artifact-list { grid-template-columns: 1fr; }
      .panel { padding: 14px; border-radius: 12px; }
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      *, *::before, *::after { scroll-behavior: auto !important; transition-duration: 0.01ms !important; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#main-content">Skip to report content</a>
  <header class="masthead">
    <div class="shell masthead__inner">
      <p class="brand">LabCourt <small>M6 offline regression authority</small></p>
      <span class="classification">${classification}</span>
    </div>
  </header>
  <main id="main-content" class="shell">
    <h1>Replay-locked regression report</h1>
    <p class="lede">A deterministic, privacy-safe view of synthetic, precomputed, fake evaluation artifacts. No backend, network resource, raw media, or model hidden reasoning is required.</p>
    <div class="status-line" aria-label="Release status">
      <span class="status ${release_status_class}">Release allowed: ${release_allowed}</span>
      <span class="status">Disposition: ${report_disposition}</span>
      <span class="status">Mode: ${mode}</span>
    </div>

    <section class="panel" aria-labelledby="summary-heading">
      <h2 id="summary-heading">Gate summary</h2>
      <dl class="metric-grid">
${metric_items}
      </dl>
    </section>

    <section class="panel" aria-labelledby="identity-heading">
      <h2 id="identity-heading">Bound authority</h2>
      <dl class="identity-grid">
${identity_items}
      </dl>
    </section>

    <section class="panel" aria-labelledby="artifacts-heading">
      <h2 id="artifacts-heading">Verified JSON artifacts</h2>
      <nav aria-label="Regression artifacts">
        <ul class="artifact-list">
${artifact_items}
        </ul>
      </nav>
    </section>

    <section class="panel" aria-labelledby="cases-heading">
      <h2 id="cases-heading">Case results and evidence state</h2>
      <div class="table-wrap">
        <table>
          <caption>Every report sample and its privacy-safe evidence presentation state.</caption>
          <thead><tr>
            <th scope="col">Sample</th>
            <th scope="col">Dataset</th>
            <th scope="col">Baseline</th>
            <th scope="col">Candidate</th>
            <th scope="col">First divergence</th>
            <th scope="col">Result</th>
            <th scope="col">Evidence</th>
          </tr></thead>
          <tbody>
${case_rows}
          </tbody>
        </table>
      </div>
    </section>
    <p class="footer-note">Privacy posture: persisted privacy-processed media only; retention-purged evidence remains text-only and audit-linked.</p>
  </main>
</body>
</html>
"""

__all__ = ["M6_STATIC_REPORT_TEMPLATE"]
