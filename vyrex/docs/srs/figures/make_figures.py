"""Generate every figure embedded in the VYREX SRS (docs/srs/make_srs.py).

All figures are produced programmatically so the SRS is reproducible: use-case
diagrams (UML-style), the 4+1 architecture views, and UI wireframes drawn in the
console's locked design language (D-049: charcoal #0C0D0F canvas, teal #3FB6A0
accent on interactive chrome only, status hues for severity).

Run:  python make_figures.py     (writes PNGs next to this script)
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyArrowPatch, FancyBboxPatch, Rectangle
from pathlib import Path

OUT = Path(__file__).parent
DPI = 160

# ----- palette -------------------------------------------------------------
INK = "#1a1f26"          # diagram ink on white
ACCENT = "#0e7c6b"       # teal-ish accent for diagram highlights
BOX = "#f4f6f8"
# console design language (D-049)
BG = "#0C0D0F"; PANEL = "#14161A"; EDGE = "#23262C"; TEAL = "#3FB6A0"
TXT = "#D7DBE0"; DIM = "#8B929B"; RED = "#E5484D"; AMBER = "#E5A33D"; GREEN = "#3FB68B"


# ============================================================ UML helpers ==
def actor(ax, x, y, label):
    ax.add_patch(Ellipse((x, y + 0.55), 0.28, 0.28, fill=False, lw=1.6, ec=INK))
    ax.plot([x, x], [y + 0.41, y - 0.05], lw=1.6, c=INK)
    ax.plot([x - 0.22, x + 0.22], [y + 0.22, y + 0.22], lw=1.6, c=INK)
    ax.plot([x, x - 0.18], [y - 0.05, y - 0.38], lw=1.6, c=INK)
    ax.plot([x, x + 0.18], [y - 0.05, y - 0.38], lw=1.6, c=INK)
    ax.text(x, y - 0.62, label, ha="center", va="top", fontsize=10, weight="bold", color=INK)


def usecase(ax, x, y, label, w=2.6, h=0.62):
    ax.add_patch(Ellipse((x, y), w, h, facecolor=BOX, edgecolor=INK, lw=1.3))
    ax.text(x, y, label, ha="center", va="center", fontsize=8.6, color=INK, wrap=True)


def link(ax, x1, y1, x2, y2, style="-", color=INK):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style if style != "-" else "-",
                                 linestyle="-" if style == "-" else ":", lw=1.0, color=color,
                                 shrinkA=4, shrinkB=4))


def usecase_diagram(fname, title, actors, cases, links, extra_links=()):
    """actors: [(x,y,label)]; cases: {id:(x,y,label)}; links: [(actor_idx, case_id)]"""
    fig, ax = plt.subplots(figsize=(9.2, 6.4))
    ax.set_xlim(0, 12); ax.set_ylim(0, 9); ax.axis("off")
    # system boundary
    ax.add_patch(Rectangle((2.6, 0.4), 9.1, 8.2, fill=False, lw=1.4, ec=INK))
    ax.text(7.15, 8.36, "VYREX", ha="center", fontsize=11, weight="bold", color=ACCENT)
    for (x, y, lab) in actors:
        actor(ax, x, y, lab)
    for cid, (x, y, lab) in cases.items():
        usecase(ax, x, y, lab)
    for ai, cid in links:
        x, y, _ = actors[ai]; cx, cy, _ = cases[cid]
        link(ax, x + 0.35, y, cx - 1.25, cy)
    for (c1, c2, kind) in extra_links:  # include/extend
        x1, y1, _ = cases[c1]; x2, y2, _ = cases[c2]
        ax.add_patch(FancyArrowPatch((x1, y1 - 0.3), (x2, y2 + 0.3), arrowstyle="->",
                                     linestyle=":", lw=1.0, color=ACCENT, shrinkA=4, shrinkB=4))
        ax.text((x1 + x2) / 2 + 0.15, (y1 + y2) / 2, f"«{kind}»", fontsize=7.5, color=ACCENT, style="italic")
    ax.set_title(title, fontsize=12, weight="bold", pad=10, color=INK)
    fig.tight_layout(); fig.savefig(OUT / fname, dpi=DPI, facecolor="white"); plt.close(fig)


def fig_usecases_analyst():
    cases = {
        "triage":   (5.0, 7.6, "View risk-ranked\ntriage queue"),
        "detail":   (9.2, 7.6, "Inspect finding detail\n(XAI / SHAP waterfall)"),
        "fusion":   (5.0, 6.3, "Review multi-tool\nconsensus & evidence"),
        "feedback": (9.2, 6.3, "Submit analyst feedback\n(label priority)"),
        "search":   (5.0, 5.0, "Search assets / CVEs /\nIOCs (global search)"),
        "case":     (9.2, 5.0, "Manage incident cases\n(SLA, timeline)"),
        "request":  (5.0, 3.7, "Request containment\naction"),
        "approve":  (9.2, 3.7, "Approve / reject action\n(two-person rule)"),
        "comply":   (5.0, 2.4, "Review CIS compliance\nposture & evidence"),
        "dash":     (9.2, 2.4, "View Grafana\ndashboards"),
        "hunt":     (7.1, 1.1, "Run hunt queries over\ntelemetry stores"),
    }
    links = [(0, "triage"), (0, "detail"), (0, "fusion"), (0, "feedback"), (0, "search"),
             (0, "case"), (0, "request"), (0, "comply"), (0, "dash"), (0, "hunt"),
             (1, "approve"), (1, "case")]
    usecase_diagram("fig1_usecases_analyst.png", "Figure 1 — SOC Analyst use cases",
                    [(1.2, 5.6, "SOC Analyst"), (1.2, 2.6, "Senior Analyst\n(2nd approver)")],
                    cases, links,
                    extra_links=[("request", "approve", "include"), ("detail", "feedback", "extend")])


def fig_usecases_admin():
    cases = {
        "users":   (5.0, 7.4, "Manage users & roles\n(RBAC: viewer/analyst/admin)"),
        "deploy":  (9.2, 7.4, "Deploy / update stack\n(Compose or K3s Helm)"),
        "agents":  (5.0, 6.0, "Roll out signed agents\n(cosign-verified)"),
        "feeds":   (9.2, 6.0, "Run feed mirror sync\n(staging host only)"),
        "bundle":  (5.0, 4.6, "Build / install offline\nbundle (air-gap)"),
        "airgap":  (9.2, 4.6, "Verify air-gap\n(egress sealing)"),
        "train":   (5.0, 3.2, "Retrain risk model\n(sanitised feedback)"),
        "policy":  (9.2, 3.2, "Set autonomy level /\ndefense policy"),
        "backup":  (5.0, 1.8, "Back up / restore\ndata stores"),
        "audit":   (9.2, 1.8, "Verify hash-chained\naudit integrity"),
    }
    links = [(0, "users"), (0, "deploy"), (0, "agents"), (0, "bundle"), (0, "airgap"),
             (0, "train"), (0, "policy"), (0, "backup"), (0, "audit"),
             (1, "feeds"), (1, "bundle")]
    usecase_diagram("fig2_usecases_admin.png", "Figure 2 — Administrator use cases",
                    [(1.2, 5.4, "SOC Administrator"), (1.2, 2.2, "Staging-host\nOperator")],
                    cases, links,
                    extra_links=[("bundle", "airgap", "include")])


def fig_usecases_system():
    cases = {
        "collect": (5.0, 7.4, "Collect telemetry\n(proc / net / FIM / osquery)"),
        "ship":    (9.2, 7.4, "Ship envelopes over\nmTLS + bearer token"),
        "ingest":  (5.0, 6.0, "Validate schema &\nenqueue (JetStream)"),
        "enrich":  (9.2, 6.0, "Match CVEs, attach\nCVSS / EPSS / KEV"),
        "fuse":    (5.0, 4.6, "Fuse findings across\ntools (consensus)"),
        "score":   (9.2, 4.6, "Score risk (composite\n+ XGBoost + SHAP)"),
        "intel":   (5.0, 3.2, "Enrich with MISP IOC /\nATT&CK / Sigma"),
        "exec":    (9.2, 3.2, "Verify & execute signed\ncontainment command"),
        "sensors": (7.1, 1.8, "Normalize tool detections\n(Suricata/Zeek/Wazuh/Falco/…)"),
    }
    links = [(0, "collect"), (0, "ship"), (0, "exec"),
             (1, "ingest"), (1, "enrich"), (1, "fuse"), (1, "score"), (1, "intel"),
             (2, "sensors"), (2, "ingest")]
    usecase_diagram("fig3_usecases_system.png", "Figure 3 — System / machine-actor use cases",
                    [(1.2, 6.6, "Endpoint Agent"), (1.2, 4.4, "Pipeline Services"),
                     (1.2, 2.0, "Integrated Tools")],
                    cases, links,
                    extra_links=[("ship", "ingest", "include"), ("fuse", "score", "include")])


# ================================================== architecture helpers ==
def block(ax, x, y, w, h, title, lines=(), fc=BOX, ec=INK, title_c=None, fs=9):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.06",
                                facecolor=fc, edgecolor=ec, lw=1.3))
    ax.text(x + w / 2, y + h - 0.28, title, ha="center", fontsize=fs, weight="bold",
            color=title_c or INK)
    for i, ln in enumerate(lines):
        ax.text(x + w / 2, y + h - 0.62 - i * 0.3, ln, ha="center", fontsize=fs - 1.4, color=INK)


def arrow(ax, x1, y1, x2, y2, label="", color=INK, lw=1.4):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=13,
                                 lw=lw, color=color, shrinkA=2, shrinkB=2))
    if label:
        ax.text((x1 + x2) / 2 + 0.12, (y1 + y2) / 2, label, fontsize=7.6, color=color)


def fig_logical():
    fig, ax = plt.subplots(figsize=(9.6, 7.0))
    ax.set_xlim(0, 12); ax.set_ylim(0, 10); ax.axis("off")
    block(ax, 0.6, 8.0, 10.8, 1.5, "PRESENTATION LAYER",
          ["Analyst console (SPA · triage / XAI / cases / compliance / fusion)   ·   Grafana dashboards   ·   Swagger API docs"])
    block(ax, 0.6, 5.6, 10.8, 1.7, "DATA LAYER",
          ["PostgreSQL (state: findings, incidents, users, audit)   ·   TimescaleDB (telemetry_raw hypertable)",
           "OpenSearch (search index)   ·   local feed mirror (NVD / EPSS / KEV)"])
    block(ax, 0.6, 2.4, 10.8, 2.5, "INGESTION & ASSESSMENT LAYER",
          ["ingest-edge (Go · mTLS + schema validate + enqueue)  →  NATS JetStream  →  workers (Python)",
           "enrichment (CVE match · compliance)  ·  risk-engine (fusion · composite · XGBoost/SHAP)",
           "feed-sync (the ONLY egress)  ·  sensor/wazuh bridges  ·  intel-enricher (MISP/ATT&CK/Sigma)"])
    block(ax, 0.6, 0.4, 10.8, 1.3, "ENDPOINT AGENT LAYER (Go)",
          ["process/network observation · embedded osquery · FIM · YARA  —  mTLS up, Ed25519-signed commands down"])
    arrow(ax, 6.0, 1.7, 6.0, 2.4, " mTLS 8443 / signed channel", ACCENT)
    arrow(ax, 6.0, 4.9, 6.0, 5.6, " fan-out writes", INK)
    arrow(ax, 6.0, 7.3, 6.0, 8.0, " REST / SSE + dashboards", INK)
    ax.set_title("Figure 4 — Logical view: the four layers", fontsize=12, weight="bold", pad=8)
    fig.tight_layout(); fig.savefig(OUT / "fig4_logical.png", dpi=DPI, facecolor="white"); plt.close(fig)


def fig_development():
    fig, ax = plt.subplots(figsize=(9.6, 6.4))
    ax.set_xlim(0, 12); ax.set_ylim(0, 9); ax.axis("off")
    mods = [
        (0.5, 6.7, 3.4, 1.7, "agent/", ["Go endpoint agent", "collectors · shipper ·", "responder (verify+exec)"]),
        (4.3, 6.7, 3.4, 1.7, "services/", ["api (FastAPI) · ingest-edge (Go)", "workers · enrichment · feed-sync", "sensor/wazuh bridges · intel-enricher"]),
        (8.1, 6.7, 3.4, 1.7, "ml/", ["fusion · scoring · features", "train · evaluate · eval_fusion", "attack_scenario · feedback"]),
        (0.5, 4.4, 3.4, 1.7, "web/console/", ["dependency-free SPA", "views · SHAP waterfall ·", "entity chips · approval gate"]),
        (4.3, 4.4, 3.4, 1.7, "schema/", ["telemetry envelope v1", "(JSON Schema, versioned)"]),
        (8.1, 4.4, 3.4, 1.7, "deploy/", ["Helm chart (K3s) · Vault ·", "Keycloak · Velero · ArgoCD ·", "smoke (k3d + compose e2e)"]),
        (0.5, 2.1, 3.4, 1.7, "tools/", ["fake-producer · load (k6)", "airgap (bundle/install/verify)", "sensors · suricata rules"]),
        (4.3, 2.1, 3.4, 1.7, "grafana/ + observability/", ["provisioned dashboards", "Prometheus · Loki"]),
        (8.1, 2.1, 3.4, 1.7, "docs/", ["ARCHITECTURE · DECISIONS(49)", "METHODOLOGY · THREAT-MODEL", "BENCHMARKS · SRS · phases"]),
    ]
    for m in mods:
        block(ax, *m[:4], m[4], m[5], fs=9.2)
    ax.text(6, 0.9, "One repository · docker-compose.{yml,tools,airgap} + Makefile drive every module · CI: pytest (91) + go vet + Trivy + k3d & compose smokes",
            ha="center", fontsize=8.4, color=ACCENT)
    ax.set_title("Figure 5 — Development view: repository modules", fontsize=12, weight="bold", pad=8)
    fig.tight_layout(); fig.savefig(OUT / "fig5_development.png", dpi=DPI, facecolor="white"); plt.close(fig)


def fig_process():
    fig, ax = plt.subplots(figsize=(10.2, 6.8))
    ax.set_xlim(0, 14); ax.set_ylim(0, 9.5); ax.axis("off")
    # ingest pipeline (top)
    block(ax, 0.4, 7.2, 2.3, 1.4, "Agent /\nTool bridge", ["envelope v1"])
    block(ax, 3.3, 7.2, 2.5, 1.4, "ingest-edge", ["mTLS + token", "schema validate"])
    block(ax, 6.4, 7.2, 2.4, 1.4, "JetStream", ["telemetry.v1.<kind>", "durable, back-pressure"])
    block(ax, 9.4, 7.2, 2.2, 1.4, "workers", ["batch insert"])
    block(ax, 12.0, 7.2, 1.7, 1.4, "Stores", ["TSDB · OS"])
    arrow(ax, 2.7, 7.9, 3.3, 7.9, ""); arrow(ax, 5.8, 7.9, 6.4, 7.9, "")
    arrow(ax, 8.8, 7.9, 9.4, 7.9, ""); arrow(ax, 11.6, 7.9, 12.0, 7.9, "")
    # scoring loop (middle)
    block(ax, 0.4, 4.6, 2.6, 1.5, "enrichment", ["pkg→CVE match", "CVSS/EPSS/KEV", "CIS compliance"])
    block(ax, 3.6, 4.6, 2.6, 1.5, "findings (PG)", ["dedup_key stamped", "per-tool rows"])
    block(ax, 6.8, 4.6, 2.8, 1.5, "risk-engine", ["fusion clusters →", "consensus weight"])
    block(ax, 10.2, 4.6, 3.4, 1.5, "scoring", ["composite (10 factors)", "XGBoost + TreeSHAP", "risk_score + rank"])
    arrow(ax, 3.0, 5.35, 3.6, 5.35, ""); arrow(ax, 6.2, 5.35, 6.8, 5.35, "")
    arrow(ax, 9.6, 5.35, 10.2, 5.35, "")
    arrow(ax, 11.9, 6.1 - 0.0, 11.9, 7.2, " read pkg state", INK, 1.0)
    arrow(ax, 4.9, 6.1, 4.9, 7.2, "", INK, 1.0)
    # response flow (bottom)
    block(ax, 0.4, 1.6, 3.0, 1.6, "Analyst", ["requests containment"])
    block(ax, 4.0, 1.6, 3.2, 1.6, "API response router", ["two-person approval", "hash-chained audit"])
    block(ax, 7.8, 1.6, 3.0, 1.6, "Signer", ["Ed25519 sign", "nonce + expiry"])
    block(ax, 11.3, 1.6, 2.4, 1.6, "Agent responder", ["verify fail-closed", "execute · report"])
    arrow(ax, 3.4, 2.4, 4.0, 2.4, ""); arrow(ax, 7.2, 2.4, 7.8, 2.4, "")
    arrow(ax, 10.8, 2.4, 11.3, 2.4, " signed cmd", ACCENT)
    ax.text(7, 0.7, "Top: telemetry ingestion (stateless edge → durable queue).  Middle: assessment & scoring loop.  Bottom: analyst-controlled signed response.",
            ha="center", fontsize=8.4, color=ACCENT)
    ax.set_title("Figure 6 — Process view: ingestion, scoring and response flows", fontsize=12, weight="bold", pad=8)
    fig.tight_layout(); fig.savefig(OUT / "fig6_process.png", dpi=DPI, facecolor="white"); plt.close(fig)


def fig_physical():
    fig, ax = plt.subplots(figsize=(10.2, 6.8))
    ax.set_xlim(0, 14); ax.set_ylim(0, 9.5); ax.axis("off")
    # air-gapped site boundary
    ax.add_patch(Rectangle((0.4, 0.6), 10.2, 8.2, fill=False, lw=1.8, ec=ACCENT))
    ax.text(5.5, 8.95, "AIR-GAPPED SITE (no internet)", ha="center", fontsize=10.5, weight="bold", color=ACCENT)
    block(ax, 0.8, 6.4, 3.0, 1.9, "Endpoints (fleet)", ["Linux / Windows / macOS", "signed VYREX agent", "mTLS client certs"])
    block(ax, 4.4, 6.4, 3.0, 1.9, "Sensor host", ["Suricata · Zeek", "SPAN / TAP feed", "promiscuous NIC"])
    block(ax, 7.8, 6.4, 2.5, 1.9, "Analyst\nworkstations", ["browser → console", "OIDC / TLS"])
    block(ax, 0.8, 2.6, 6.6, 3.0, "VYREX server cluster",
          ["Pilot: 1 node Docker Compose (8c/32GB/1TB SSD)",
           "Production: 3+ node K3s — Helm chart, CNPG/OpenSearch",
           "operators, Keycloak (SSO), Vault (secrets/PKI), Velero",
           "NetworkPolicy enforces single-egress air gap"])
    block(ax, 7.8, 2.6, 2.5, 3.0, "Data stores", ["PostgreSQL", "TimescaleDB", "OpenSearch", "feed mirror vols"])
    arrow(ax, 2.3, 6.4, 3.4, 5.6, " mTLS 8443", ACCENT)
    arrow(ax, 5.9, 6.4, 5.2, 5.6, " bridge → NATS")
    arrow(ax, 9.0, 6.4, 7.4, 5.3, " HTTPS")
    arrow(ax, 7.4, 4.1, 7.8, 4.1, "")
    # staging host outside
    block(ax, 11.2, 5.6, 2.4, 2.7, "Staging host\n(DMZ, connected)",
          ["feed-sync · mirror-sync", "make bundle →", "SHA256SUMS bundle"])
    ax.add_patch(FancyArrowPatch((11.9, 5.6), (9.0, 4.4), arrowstyle="-|>", mutation_scale=13,
                                 lw=1.6, color=RED, linestyle=":", shrinkA=2, shrinkB=2))
    ax.text(10.6, 4.6, "removable media\n(verified install.sh)", fontsize=7.6, color=RED, ha="center")
    block(ax, 11.2, 1.0, 2.4, 1.6, "Internet feeds", ["NVD · EPSS · KEV", "ET Open · templates"])
    arrow(ax, 12.4, 2.6, 12.4, 5.6, " the ONLY egress", RED)
    ax.text(5.5, 1.4, "Everything inside the boundary runs offline; `make airgap-verify` proves runtime egress is sealed.",
            ha="center", fontsize=8.4, color=INK)
    ax.set_title("Figure 7 — Physical view: air-gapped deployment topology", fontsize=12, weight="bold", pad=8)
    fig.tight_layout(); fig.savefig(OUT / "fig7_physical.png", dpi=DPI, facecolor="white"); plt.close(fig)


# ======================================================== UI wireframes ===
def ui_canvas(title, h=7.2):
    fig, ax = plt.subplots(figsize=(11.4, h))
    ax.set_xlim(0, 16); ax.set_ylim(0, 10); ax.axis("off")
    fig.patch.set_facecolor(BG)
    ax.add_patch(Rectangle((0, 0), 16, 10, facecolor=BG))
    # top bar
    ax.add_patch(Rectangle((0, 9.2), 16, 0.8, facecolor=PANEL, edgecolor=EDGE))
    ax.text(0.4, 9.55, "VYREX", fontsize=12, weight="bold", color=TEAL, family="monospace")
    for i, (lab, on) in enumerate([("Triage", True), ("Compliance", False), ("Cases", False), ("Sensors & Fusion", False)]):
        ax.text(2.6 + i * 2.2, 9.55, lab, fontsize=9, color=TEAL if on else DIM)
    ax.add_patch(FancyBboxPatch((11.6, 9.32), 3.9, 0.55, boxstyle="round,pad=0.03",
                                facecolor=BG, edgecolor=EDGE))
    ax.text(11.85, 9.55, "/  search assets, CVEs, IOCs…", fontsize=8, color=DIM)
    ax.set_title(title, fontsize=11.5, weight="bold", color=INK, pad=10)
    return fig, ax


def sev_chip(ax, x, y, sev):
    col = {"critical": RED, "high": AMBER, "medium": DIM, "low": DIM}[sev]
    mark = {"critical": "s", "high": "^", "medium": "o", "low": "_"}[sev]
    ax.plot([x], [y], marker=mark, ms=6, color=col, mfc=col if sev in ("critical", "high") else "none")
    ax.text(x + 0.25, y, sev.upper(), fontsize=7.4, color=col, va="center", weight="bold")


def fig_ui_triage():
    fig, ax = ui_canvas("Figure 8 — UI design: Triage view (risk-ranked decision queue)")
    # filter row
    for i, f in enumerate(["domain: all", "severity: all", "tool: all", "KEV only ☐"]):
        ax.add_patch(FancyBboxPatch((0.4 + i * 2.5, 8.35), 2.3, 0.5, boxstyle="round,pad=0.03",
                                    facecolor=PANEL, edgecolor=EDGE))
        ax.text(0.55 + i * 2.5, 8.57, f, fontsize=8, color=DIM)
    ax.text(15.6, 8.57, "312 findings · ranked by composite risk", fontsize=8, color=DIM, ha="right")
    rows = [
        ("94", "critical", "CVE-2021-44228 · log4shell RCE", "host-web-01", "nuclei + trivy", "KEV · EPSS 0.97 · exposed", "Contain"),
        ("81", "critical", "CVE-2023-46604 · ActiveMQ RCE", "host-app-03", "nuclei + trivy", "KEV · EPSS 0.91", "Patch now"),
        ("76", "high", "C2 egress beacon :4444", "host-db-02", "suricata + zeek + misp", "consensus 3 tools · T1071 · IOC", "Investigate"),
        ("58", "high", "CVE-2024-3094 · xz backdoor", "host-web-01", "trivy + wazuh + agent", "consensus 3 tools", "Patch"),
        ("44", "medium", "FIM change /etc/passwd", "host-web-01", "wazuh", "single tool", "Review"),
        ("31", "medium", "Weak SSH config (CIS 5.2)", "host-db-02", "agent", "compliance impact", "Harden"),
    ]
    y = 7.6
    for score, sev, title, asset, tools, why, action in rows:
        ax.add_patch(FancyBboxPatch((0.4, y - 0.85), 15.2, 1.0, boxstyle="round,pad=0.04",
                                    facecolor=PANEL, edgecolor=EDGE))
        col = RED if float(score) >= 80 else (AMBER if float(score) >= 60 else DIM)
        ax.text(1.05, y - 0.33, score, fontsize=15, weight="bold", color=col, ha="center")
        ax.text(1.05, y - 0.68, "risk", fontsize=6.5, color=DIM, ha="center")
        sev_chip(ax, 2.0, y - 0.33, sev)
        ax.text(3.6, y - 0.28, title, fontsize=9.4, color=TXT, weight="bold")
        ax.text(3.6, y - 0.62, f"{asset}   ·   {tools}   ·   {why}", fontsize=7.8, color=DIM)
        ax.add_patch(FancyBboxPatch((13.6, y - 0.62), 1.7, 0.5, boxstyle="round,pad=0.03",
                                    facecolor=BG, edgecolor=TEAL))
        ax.text(14.45, y - 0.38, action, fontsize=8, color=TEAL, ha="center")
        y -= 1.18
    ax.text(0.4, 0.35, "keyboard: / search · 1–4 views · j/k move · Enter open · Esc close", fontsize=7.4, color=DIM)
    fig.tight_layout(); fig.savefig(OUT / "fig8_ui_triage.png", dpi=DPI, facecolor=BG); plt.close(fig)


def fig_ui_detail():
    fig, ax = ui_canvas("Figure 9 — UI design: Finding detail (XAI drawer with SHAP waterfall)")
    # left: scores + consensus
    ax.add_patch(FancyBboxPatch((0.4, 5.6), 4.6, 3.2, boxstyle="round,pad=0.05", facecolor=PANEL, edgecolor=EDGE))
    ax.text(2.7, 8.4, "CVE-2021-44228 · host-web-01", fontsize=9.5, color=TXT, weight="bold", ha="center")
    ax.text(1.6, 7.4, "94", fontsize=26, weight="bold", color=RED, ha="center")
    ax.text(1.6, 6.8, "composite", fontsize=7.5, color=DIM, ha="center")
    ax.text(3.8, 7.4, "91", fontsize=26, weight="bold", color=AMBER, ha="center")
    ax.text(3.8, 6.8, "ML (XGBoost)", fontsize=7.5, color=DIM, ha="center")
    ax.text(2.7, 6.3, "consensus  ●●○   2 tools agree (nuclei, trivy)", fontsize=8, color=TXT, ha="center")
    ax.text(2.7, 5.9, "ATT&CK T1190 · KEV listed · EPSS 0.97", fontsize=8, color=DIM, ha="center")
    # right: SHAP waterfall
    ax.add_patch(FancyBboxPatch((5.4, 3.4), 10.2, 5.4, boxstyle="round,pad=0.05", facecolor=PANEL, edgecolor=EDGE))
    ax.text(10.5, 8.4, "Why this score — SHAP waterfall (base → factors → final)", fontsize=9, color=TXT, ha="center", weight="bold")
    factors = [("base", 42, None), ("KEV", 14, AMBER), ("EPSS", 12, AMBER), ("exposure", 9, AMBER),
               ("CVSS", 8, AMBER), ("consensus", 6, AMBER), ("attack ctx", 4, AMBER),
               ("age", 2, AMBER), ("compliance", -3, GREEN), ("criticality", -1, GREEN), ("final = 91", 0, None)]
    x0, y0, run = 6.0, 7.7, 42.0
    scale = 9.0 / 100.0
    for i, (name, delta, col) in enumerate(factors):
        yy = y0 - i * 0.38
        if name == "base":
            ax.plot([6.0 + run * scale], [yy], marker="v", color=TEAL, ms=7)
            ax.text(5.9, yy, "base 42", fontsize=7.2, color=TEAL, ha="right", va="center")
            continue
        if name.startswith("final"):
            ax.plot([6.0 + run * scale], [yy], marker="^", color=TEAL, ms=7)
            ax.text(5.9, yy, name, fontsize=7.6, color=TEAL, ha="right", va="center", weight="bold")
            continue
        w = abs(delta) * scale
        xx = 6.0 + (run if delta > 0 else run + delta) * scale
        ax.add_patch(Rectangle((xx, yy - 0.1), w, 0.2, facecolor=col, edgecolor="none"))
        ax.text(5.9, yy, name, fontsize=7.2, color=DIM, ha="right", va="center")
        ax.text(6.0 + (run + max(delta, 0)) * scale + 0.12, yy, f"{'+' if delta>0 else ''}{delta}",
                fontsize=7, color=col, va="center")
        run += delta
    for t in (0, 25, 50, 75, 100):
        ax.plot([6.0 + t * scale] * 2, [3.6, 7.9], lw=0.4, color=EDGE)
        ax.text(6.0 + t * scale, 3.45, str(t), fontsize=6.5, color=DIM, ha="center")
    # bottom: containment gate + feedback
    ax.add_patch(FancyBboxPatch((0.4, 3.4), 4.6, 1.9, boxstyle="round,pad=0.05", facecolor=PANEL, edgecolor=EDGE))
    ax.text(2.7, 4.9, "Containment gate", fontsize=8.6, color=TXT, ha="center", weight="bold")
    ax.text(2.7, 4.5, "proposed → approved (you) →", fontsize=7.4, color=DIM, ha="center")
    ax.text(2.7, 4.2, "awaiting 2nd approver → authorized", fontsize=7.4, color=DIM, ha="center")
    ax.add_patch(FancyBboxPatch((1.3, 3.55), 2.8, 0.45, boxstyle="round,pad=0.03", facecolor=BG, edgecolor=TEAL))
    ax.text(2.7, 3.77, "Request isolation", fontsize=8, color=TEAL, ha="center")
    ax.add_patch(FancyBboxPatch((0.4, 0.6), 15.2, 2.4, boxstyle="round,pad=0.05", facecolor=PANEL, edgecolor=EDGE))
    ax.text(0.8, 2.55, "Evidence & provenance", fontsize=8.6, color=TXT, weight="bold")
    for i, ev in enumerate(["nuclei  ·  http /rce probe 200 OK  ·  2026-07-11T09:14Z",
                            "trivy   ·  log4j-core 2.14.1 in web-app SBOM  ·  2026-07-11T08:02Z",
                            "mirror  ·  KEV due 2021-12-24 · EPSS 0.973 (p99)  ·  feed snapshot 2026-07-09"]):
        ax.text(1.0, 2.15 - i * 0.42, ev, fontsize=7.8, color=DIM, family="monospace")
    ax.text(12.4, 2.55, "Analyst feedback", fontsize=8.6, color=TXT, weight="bold")
    ax.text(12.4, 2.1, "priority (0–100):  [ 95 ]   Submit", fontsize=8, color=TEAL)
    fig.tight_layout(); fig.savefig(OUT / "fig9_ui_detail.png", dpi=DPI, facecolor=BG); plt.close(fig)


def fig_ui_cases():
    fig, ax = ui_canvas("Figure 10 — UI design: Cases view (incidents, SLA, hash-chained audit timeline)")
    heads = ["OPEN (3)", "CONTAINING (1)", "RESOLVED (12)"]
    for i, h in enumerate(heads):
        x = 0.4 + i * 5.2
        ax.add_patch(FancyBboxPatch((x, 0.7), 4.9, 8.0, boxstyle="round,pad=0.05", facecolor=PANEL, edgecolor=EDGE))
        ax.text(x + 2.45, 8.35, h, fontsize=9, color=TXT, ha="center", weight="bold")
    cards = [
        (0, "INC-014 · C2 beacon host-db-02", "critical", "SLA 3h left", ["3 findings fused", "T1071 · live IOC"]),
        (0, "INC-015 · log4shell host-web-01", "critical", "SLA 6h left", ["containment proposed", "awaiting 2nd approver"]),
        (0, "INC-016 · FIM /etc/passwd", "medium", "SLA 22h", ["single tool", "triage pending"]),
        (1, "INC-013 · xz backdoor", "high", "isolating", ["authorized 2-person", "agent executing"]),
        (2, "INC-009 · exposed SMB legacy-05", "high", "closed 2d ago", ["patched + verified"]),
    ]
    slots = {0: 0, 1: 0, 2: 0}
    for col, title, sev, sla, lines in cards:
        x = 0.55 + col * 5.2; y = 7.6 - slots[col] * 2.2; slots[col] += 1
        ax.add_patch(FancyBboxPatch((x, y - 1.6), 4.6, 1.9, boxstyle="round,pad=0.04", facecolor=BG, edgecolor=EDGE))
        sev_chip(ax, x + 0.25, y + 0.05, sev)
        ax.text(x + 0.2, y - 0.35, title, fontsize=8.2, color=TXT, weight="bold")
        ax.text(x + 4.4, y + 0.05, sla, fontsize=7.2, color=AMBER, ha="right")
        for j, ln in enumerate(lines):
            ax.text(x + 0.2, y - 0.75 - j * 0.32, "· " + ln, fontsize=7.2, color=DIM)
    ax.text(8.0, 0.35, "audit timeline per case: every action hash-chained — verify badge shows chain integrity (GET /response/audit/verify)",
            fontsize=7.6, color=TEAL, ha="center")
    fig.tight_layout(); fig.savefig(OUT / "fig10_ui_cases.png", dpi=DPI, facecolor=BG); plt.close(fig)


def fig_ui_fusion():
    fig, ax = ui_canvas("Figure 11 — UI design: Sensors & Fusion view (pipeline + integrated-tool grid)")
    # pipeline strip
    stages = ["feed-sync\n(mirror)", "ingest-edge\n(mTLS)", "JetStream\n(queue)", "workers\n(stores)", "enrichment\n(CVE/CIS)", "fusion\n(consensus)", "scoring\n(ML+SHAP)"]
    for i, s in enumerate(stages):
        x = 0.5 + i * 2.2
        ax.add_patch(FancyBboxPatch((x, 7.3), 1.9, 1.2, boxstyle="round,pad=0.04", facecolor=PANEL, edgecolor=TEAL))
        ax.text(x + 0.95, 7.9, s, fontsize=7.4, color=TXT, ha="center")
        ax.plot([x + 0.95], [7.42], marker="o", ms=4, color=GREEN)
        if i < len(stages) - 1:
            ax.annotate("", xy=(x + 2.2, 7.9), xytext=(x + 1.9, 7.9),
                        arrowprops=dict(arrowstyle="-|>", color=DIM, lw=1))
    ax.text(8.0, 6.85, "all stages healthy · last envelope 4 s ago · 312 findings scored · 41 multi-tool clusters", fontsize=7.8, color=DIM, ha="center")
    # tool grid
    tools = [("Suricata", "sensors", 84), ("Zeek", "sensors", 61), ("Wazuh", "hostmon", 47),
             ("Falco", "hostmon", 9), ("Trivy", "scanners", 66), ("Nuclei", "scanners", 24),
             ("MISP", "intel", 12), ("OpenCTI", "intel", 8), ("Sigma", "intel", 15), ("Agent", "core", 128)]
    for i, (name, prof, n) in enumerate(tools):
        x = 0.5 + (i % 5) * 3.1; y = 4.6 - (i // 5) * 2.0
        ax.add_patch(FancyBboxPatch((x, y), 2.8, 1.6, boxstyle="round,pad=0.04", facecolor=PANEL, edgecolor=EDGE))
        ax.plot([x + 0.3], [y + 1.3], marker="o", ms=5, color=GREEN)
        ax.text(x + 0.55, y + 1.3, name, fontsize=8.8, color=TXT, va="center", weight="bold")
        ax.text(x + 0.3, y + 0.85, f"profile: {prof}", fontsize=7, color=DIM)
        ax.text(x + 0.3, y + 0.5, f"{n} findings · envelope ok", fontsize=7, color=DIM)
    ax.text(8.0, 0.5, "the honest agent-roster analog: live status per integrated tool + which envelope kinds it ships", fontsize=7.6, color=TEAL, ha="center")
    fig.tight_layout(); fig.savefig(OUT / "fig11_ui_fusion.png", dpi=DPI, facecolor=BG); plt.close(fig)


if __name__ == "__main__":
    fig_usecases_analyst()
    fig_usecases_admin()
    fig_usecases_system()
    fig_logical()
    fig_development()
    fig_process()
    fig_physical()
    fig_ui_triage()
    fig_ui_detail()
    fig_ui_cases()
    fig_ui_fusion()
    print("figures written to", OUT)
