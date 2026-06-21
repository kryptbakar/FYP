# VYREX — Demo Script & Viva Playbook

> The project is strong. Projects don't lose on substance — they lose because the substance
> never lands in the 5 minutes the evaluators are watching. This is the script that makes it land.
> Rehearse it until you can do it without looking. Total runtime: **~4 minutes + Q&A**.

---

## 0. The one-sentence hook (say this first, before you touch the keyboard)

> "Every cloud SOC — CrowdStrike, Splunk, Sentinel — phones home. Governments, banks, hospitals,
> and defence **legally cannot** use them. VYREX is a full SOC that runs with **zero internet**,
> scores every threat with an **explainable** model, and proves with cryptography that **nothing
> ever leaves the building**. Let me show you in three minutes."

Why it works: it names a real buyer, a real legal constraint, and three concrete differentiators
(air-gap, explainability, proof) — not "a dashboard."

---

## 1. The first 5 seconds (let the screen do the work)

Log in (`admin` / `vyrex`). The login already says *"Air-gapped · explainable · cryptographically
auditable SOC."* You land on **Overview**. Before clicking anything, point at the **trust ribbon**:

> "Top-left tells you the whole thesis: **air-gap sealed, evidence chain intact, multi-tool fusion,
> explainable scoring.** Everything else proves these four claims."

Then point at the **donut** and **7-day posture trend**: "real data, real trend — this isn't a mockup."

---

## 2. Run the guided demo (the spine of the pitch)

Click **▶ Run guided demo** (top-right). It runs a deterministic 7-beat storyline. Narrate over it —
**don't read the captions, talk past them**:

| Beat | What's on screen | Your line |
|---|---|---|
| 1 · Noise → signal | Funnel `~500 → 1` | "Raw tools throw ~500 alerts a day. We fuse and rank them to **the one decision that matters now**." |
| 2 · #1 decision | Top of the queue | "The top finding: a **known-exploited** CVE on an **internet-facing** host. Why does the machine rank it #1?" |
| 3 · Explainability | SHAP waterfall builds | "This is the part commercial tools hide. The score is assembled **factor by factor** — KEV, CVSS, and **three tools agreeing** push it to the top. **Nothing is a black box.**" |
| 4 · Consensus | 3 tools light up → 1.0 | "Agent, Trivy and Suricata **independently** flagged the same issue. Agreement is the most intuitive trust signal. **If only one tool had flagged it, the score drops 21 points** — and we show that counterfactual." |
| 5 · Incident | Kanban board | "Promote to a case; the **attack chain** assembles from the linked findings." |
| 6 · Signed containment | Two-person gate runs | "Containment needs **two people**, then dispatches an **Ed25519-signed** command the agent verifies before executing. A forged command is rejected." |
| 7 · Air-gap proof | Egress matrix | "And the payoff: **every service is egress-denied, the audit chain verifies intact — zero bytes left the building.**" |

End on beat 7. That's your mic-drop. **Pause there.**

---

## 3. The closer (after the storyline)

> "So: ten open-source tools, unified. Every score **explained**. Every action **signed, approved,
> and audited**. And the whole thing runs **disconnected** — which is the one thing no cloud SOC can
> ever offer the buyers who need it most."

---

## 4. The questions that sink teams — and your honest answers

**Q: Is the ML real or did you fake the scores?**
> "Real. The composite score is a transparent weighted formula — every contribution is shown. On top,
> an XGBoost model re-ranks, and SHAP explains it with **native TreeSHAP**. I'll be honest about the
> limit: the model is currently trained largely on **synthetic labels derived from the composite
> formula**, so today it mostly *re-discovers* our weights. The honest framing — which we state openly
> on the **Model card** screen — is that the composite is the primary defensible signal and the ML is a
> **feedback-adaptive re-ranker** that learns real signal as analyst labels accumulate."

*(Stating the limitation before they find it is what flips skepticism into trust. Do not hide it.)*

**Q: Prove the air-gap — "no internet" is easy to claim.**
> "Two layers. In Compose, every service sits on an `internal` Docker network with no host route, and
> we have an **egress-verification script** that proves the API can't even resolve DNS while a control
> bridge can. In production it's a K3s **NetworkPolicy with default-deny egress**. The only thing
> allowed out is an optional feed-sync job for NVD/EPSS/KEV — and in true air-gap that's fed from
> offline files. It's **enforced and tested**, not asserted."

**Q: What's actually yours vs. just integrating open source?**
> "The tools are best-in-class open source — we don't reinvent Suricata. **Our** original value is the
> **intelligence layer**: the composite+ML+SHAP scoring, the **fusion engine** that turns multi-tool
> agreement into a consensus weight, the **signed/two-person/hash-chained** response governance, and
> the air-gap architecture that makes it deployable where cloud SOCs are illegal."

**Q: Does the response actually do anything, or is it a button?**
> "The governance is real: two-person approval state machine, Ed25519 signing, hash-chained audit with
> a `/verify` endpoint that detects tampering. The destructive execution on a live endpoint is the one
> part marked **'needs a Linux endpoint to verify'** — we don't claim what we didn't run. The second
> approver in the demo is simulated so one person can show the two-person flow."

**Q: Why vanilla JS and not React?**
> "Air-gap integrity. No npm, no CDN, no build step means **nothing is fetched at runtime** — the
> console is auditable line-by-line and can't phone home. In a tool whose entire pitch is 'nothing
> egresses,' a single external font or script would be a contradiction. The charts, the SHAP
> waterfall, the command palette — all hand-built inline SVG/CSS."

---

## 5. If something breaks live

- The guided demo forces **deterministic fixtures** — it runs identically every time, even with the
  backend down. **If the live stack is flaky, just run the guided demo.** It always works.
- The top-right badge shows **LIVE /api** vs **DEMO DATA** honestly. If it says DEMO, say so — "the
  backend isn't up right now, this is the bundled offline dataset" — and keep going. Honesty reads as
  competence.

---

## 6. What still separates "great" from "winner" (do these before the day)

1. **Rehearse §2 out loud 5 times.** The demo runs itself; your *narration* is the deliverable.
2. **Have the Model card open in a tab** for the ML question — show the honesty, don't just say it.
3. **Run the egress-verification script once on the day** so you can say "I ran it this morning."
4. Lead with the **buyer and the law** (§0), not the tech. Evaluators reward "who pays for this and why."
