"""Deterministic, dependency-free HTML template for the offline M6 demo."""

M6_OFFLINE_DEMO_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>LabCourt · M6 Offline Demo</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #071018;
      --surface: #0d1924;
      --surface-raised: #122231;
      --line: #263a4d;
      --text: #f4f8fb;
      --muted: #a9bac8;
      --cyan: #43d9cf;
      --cyan-soft: #123b3d;
      --green: #69e79b;
      --green-soft: #123b28;
      --amber: #ffd166;
      --shadow: 0 18px 55px rgb(0 0 0 / 28%);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
        "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); scroll-behavior: smooth; }
    body {
      margin: 0;
      min-width: 320px;
      color: var(--text);
      background:
        radial-gradient(circle at 85% -10%, rgb(67 217 207 / 14%), transparent 31rem),
        radial-gradient(circle at -10% 35%, rgb(105 231 155 / 8%), transparent 26rem),
        var(--bg);
      line-height: 1.55;
    }
    a { color: inherit; }
    a:focus-visible {
      outline: 3px solid var(--amber);
      outline-offset: 4px;
      border-radius: 6px;
    }
    code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      overflow-wrap: anywhere;
    }
    .shell { width: min(1180px, calc(100% - 40px)); margin: 0 auto; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      min-height: 72px;
      border-bottom: 1px solid var(--line);
    }
    .brand { display: flex; align-items: center; gap: 11px; font-weight: 760; }
    .brand-mark {
      display: grid;
      width: 32px;
      height: 32px;
      place-items: center;
      border: 1px solid rgb(67 217 207 / 65%);
      border-radius: 9px;
      color: var(--cyan);
      background: var(--cyan-soft);
      font-size: 13px;
      letter-spacing: .04em;
    }
    .top-status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--green);
      font-size: 13px;
      font-weight: 760;
      letter-spacing: .05em;
      text-transform: uppercase;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 0 5px rgb(105 231 155 / 12%);
    }
    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1.55fr) minmax(280px, .75fr);
      gap: 42px;
      padding: 72px 0 52px;
      align-items: end;
    }
    .eyebrow {
      margin: 0 0 14px;
      color: var(--cyan);
      font-size: 12px;
      font-weight: 780;
      letter-spacing: .13em;
      text-transform: uppercase;
    }
    h1 {
      max-width: 760px;
      margin: 0;
      font-size: clamp(38px, 6.2vw, 74px);
      line-height: .99;
      letter-spacing: -.055em;
    }
    .hero-copy {
      max-width: 710px;
      margin: 24px 0 0;
      color: var(--muted);
      font-size: clamp(16px, 2vw, 19px);
    }
    .hero-stat {
      padding: 24px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: linear-gradient(145deg, rgb(18 34 49 / 94%), rgb(13 25 36 / 92%));
      box-shadow: var(--shadow);
    }
    .hero-stat strong {
      display: block;
      color: var(--green);
      font-size: clamp(54px, 8vw, 82px);
      line-height: .9;
      letter-spacing: -.06em;
    }
    .hero-stat span { display: block; margin-top: 12px; color: var(--muted); }
    .trust-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin-bottom: 58px;
    }
    .trust-item {
      min-height: 88px;
      padding: 16px 18px;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgb(13 25 36 / 78%);
    }
    .trust-item strong { display: block; color: var(--cyan); font-size: 14px; }
    .trust-item span { display: block; margin-top: 4px; color: var(--muted); font-size: 13px; }
    .section-head {
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 24px;
      margin: 0 0 20px;
    }
    h2 { margin: 0; font-size: clamp(26px, 3.2vw, 38px); letter-spacing: -.035em; }
    .section-head p { max-width: 540px; margin: 0; color: var(--muted); }
    .scenario-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 64px;
    }
    .scenario-card {
      position: relative;
      display: flex;
      min-height: 218px;
      flex-direction: column;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--surface);
      transition: transform 160ms ease, border-color 160ms ease, background 160ms ease;
    }
    .scenario-card:hover {
      transform: translateY(-3px);
      border-color: rgb(67 217 207 / 55%);
      background: var(--surface-raised);
    }
    .scenario-index { color: var(--muted); font: 12px/1 "SFMono-Regular", Consolas, monospace; }
    .pass {
      align-self: flex-start;
      margin: 15px 0 10px;
      padding: 5px 9px;
      border: 1px solid rgb(105 231 155 / 36%);
      border-radius: 999px;
      color: var(--green);
      background: var(--green-soft);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .08em;
    }
    .scenario-card h3 { margin: 0; font-size: 16px; line-height: 1.35; }
    .scenario-card p {
      margin: 8px 0 16px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
      overflow-wrap: anywhere;
    }
    .scenario-card a {
      display: inline-flex;
      min-height: 44px;
      align-items: center;
      margin-top: auto;
      color: var(--cyan);
      font-size: 13px;
      font-weight: 720;
      text-decoration: none;
    }
    .scenario-card a:hover { text-decoration: underline; text-underline-offset: 4px; }
    .chain {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin-bottom: 64px;
    }
    .chain a {
      display: flex;
      min-height: 126px;
      flex-direction: column;
      justify-content: space-between;
      padding: 19px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: var(--surface-raised);
      text-decoration: none;
    }
    .chain a:hover { border-color: var(--cyan); }
    .chain small { color: var(--muted); }
    .chain strong { color: var(--cyan); font-size: 17px; }
    .identity {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px 24px;
      padding: 22px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgb(13 25 36 / 72%);
    }
    .identity div { min-width: 0; }
    .identity span { display: block; color: var(--muted); font-size: 12px; }
    .identity code { display: block; margin-top: 5px; color: var(--text); font-size: 12px; }
    footer {
      display: flex;
      justify-content: space-between;
      gap: 20px;
      padding: 34px 0 44px;
      color: var(--muted);
      font-size: 12px;
    }
    @media (max-width: 940px) {
      .hero { grid-template-columns: 1fr; }
      .hero-stat { max-width: 360px; }
      .scenario-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 680px) {
      .shell { width: min(100% - 28px, 1180px); }
      .hero { padding-top: 48px; }
      .trust-row, .chain, .identity { grid-template-columns: 1fr; }
      .section-head { align-items: start; flex-direction: column; }
      footer { flex-direction: column; }
    }
    @media (max-width: 470px) {
      .topbar { align-items: flex-start; flex-direction: column; padding: 16px 0; }
      .scenario-grid { grid-template-columns: 1fr; }
      .scenario-card { min-height: 192px; }
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      *, *::before, *::after { transition-duration: .001ms !important; }
      .scenario-card:hover { transform: none; }
    }
  </style>
</head>
<body>
  <header class="shell topbar">
    <div class="brand"><span class="brand-mark" aria-hidden="true">LC</span>LabCourt</div>
    <div class="top-status">
      <span class="status-dot" aria-hidden="true"></span>Offline gate passed
    </div>
  </header>
  <main class="shell">
    <section class="hero" aria-labelledby="page-title">
      <div>
        <p class="eyebrow">M6 · Replay, regression &amp; publication</p>
        <h1 id="page-title">A complete case pipeline, proven offline.</h1>
        <p class="hero-copy">
          Sixteen named scenarios traverse the deterministic trust kernel—from temporal
          detection and bounded hearing to appeal, causal replay and upgrade gating.
        </p>
      </div>
      <aside class="hero-stat" aria-label="Scenario result summary">
        <strong>${scenario_count}/${scenario_count}</strong>
        <span>named verification paths passed</span>
      </aside>
    </section>

    <section class="trust-row" aria-label="Execution trust profile">
      <div class="trust-item">
        <strong>Network · off</strong><span>No external service or remote model call.</span>
      </div>
      <div class="trust-item">
        <strong>GPU · not used</strong><span>Default CPU-only deterministic path.</span>
      </div>
      <div class="trust-item">
        <strong>Provider · trapped</strong><span>Precomputed fake authority only.</span>
      </div>
    </section>

    <section aria-labelledby="scenario-title">
      <div class="section-head">
        <h2 id="scenario-title">Verified scenarios</h2>
        <p>
          Each pass is backed by one exact pytest function node and one
          content-addressed canonical result.
        </p>
      </div>
      <div class="scenario-grid">
${scenario_cards}
      </div>
    </section>

    <section aria-labelledby="chain-title">
      <div class="section-head">
        <h2 id="chain-title">Publication chain</h2>
        <p>
          The demo stays useful without a server: every link resolves to a local,
          immutable artifact.
        </p>
      </div>
      <div class="chain">
        <a href="../index.html">
          <small>Human-readable evidence</small><strong>Privacy-safe report →</strong>
        </a>
        <a href="../regression.json">
          <small>Machine-readable CLOSED result</small><strong>Regression JSON →</strong>
        </a>
        <a href="${manifest_href}">
          <small>Sixteen exact receipts</small><strong>Demo manifest →</strong>
        </a>
      </div>
    </section>

    <section aria-labelledby="identity-title">
      <div class="section-head"><h2 id="identity-title">Bound identities</h2></div>
      <div class="identity">
        <div><span>Candidate run</span><code>${candidate_run_id}</code></div>
        <div><span>Demo manifest</span><code>${demo_manifest_id}</code></div>
        <div><span>CLOSED regression report</span><code>${report_id}</code></div>
        <div><span>Static report seal</span><code>${static_seal_id}</code></div>
      </div>
    </section>
  </main>
  <footer class="shell">
    <span>${classification}</span>
    <span>No real-person media · no hidden reasoning · no performance claim</span>
  </footer>
</body>
</html>
"""

__all__ = ["M6_OFFLINE_DEMO_TEMPLATE"]
