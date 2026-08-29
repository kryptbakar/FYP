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

## 2b. The Investigations workspace (the strongest thing you have — spend time here)

Open **Investigations**. This is where the project stops being an integration exercise.

> "Most 'AI SOC' demos show you a verdict. The problem is you cannot check it. Here is the
> same investigation, but every step is recorded and every claim is *attributable*."

Walk it in this order:

1. **The execution graph.** "Five specialists ran in parallel — asset, ATT&CK, threat intel,
   multi-tool corroboration, historical. All of them are deterministic SQL. Exactly one node
   in this graph talks to a model." That last sentence is the design position: everything
   feeding the LLM is code you can read and test, so *"the model decided"* is never the
   explanation for a verdict.

   > **Start a live one before you say this.** The graph polls every 3 seconds while a run
   > is in flight, so the deterministic branches turn teal one after another, the synthesis
   > node sits in accent with a pulse while the model works, and *Citations* stays grey
   > until it runs. It is the single most watchable thing in the demo, and it costs nothing
   > to set up — click **Investigate** on a finding and keep talking.
   >
   > If asked whether the animation is real: **yes, and say why it has to be.** Dots travel
   > only edges whose branch actually succeeded, skipped branches are dashed and inert, a
   > failed branch turns red. The picture cannot look healthier than the run was — which is
   > the whole reason to show an execution graph instead of a spinner. It is also
   > hand-built inline SVG with no library, because one CDN script would end the air-gap
   > claim.
2. **A skipped branch vs a failed one.** Point at one. "These look the same in any
   single-blob agent. 'Found nothing' and 'crashed' are completely different facts, and an
   analyst has to be able to tell them apart."
3. **Click a citation.** It jumps to the evidence record that backs the claim. "Grounded is
   a claim you should not take on trust. This is how you check it."
4. **The confidence number.** "The model is not allowed to set this. The schema it is given
   has no confidence field — it fails validation if it tries. This number comes from how
   many evidence branches actually succeeded."

**Then show the honest part, deliberately.** Do not hide it — lead with it:

> "And here is what it currently says: *insufficient evidence*, with no citations. That is
> real. I benchmarked it — across twelve findings, llama3.2:3b abstained twelve out of
> twelve and cited nothing twelve out of twelve. Qwen3-4B could not finish a single
> response in fifteen minutes on this hardware, at 3.2 tokens a second.
>
> The obvious objection is that I'd tuned my prompt badly, or picked a bad model. So I
> ran a **second, unrelated 3B model** — Qwen2.5, different vendor, different training
> data, non-thinking architecture — on **the identical twelve findings**. Same result, to
> the case: twelve out of twelve schema-valid, twelve out of twelve abstained, zero
> citations. Two independent model families failing identically is not a prompt bug.
>
> So the honest result is this: the pipeline is provably correct — schema-constrained
> output, zero unresolved citations, deterministic replay, unit-tested — and the binding
> constraint is model capacity, not the design. That is a measured finding with a
> benchmark and a replication behind it, not an excuse."

The replication is the part that wins this exchange. Anyone can claim their model
underperformed; running the control that could have falsified your own conclusion, and
reporting that it didn't, is what separates a measurement from an excuse.

Examiners reward this. A student who measured the limit of their own system and can state
it precisely is in a stronger position than one whose demo happened to work.

---

## 2c. The attack on your own system (use this if you have 60 spare seconds)

This is the strongest single thing you can say, because almost no student attacks their
own project and reports the result.

> "The agent reads finding titles and descriptions. Those come from scanners, and an
> attacker can influence them. So I attacked it: I planted a finding whose title tells the
> model to dismiss it, cite a made-up evidence id, and hide the instruction. Then I ran
> the identical finding without the injection as a control."

Show the two rows:

| | disposition | severity | claims | fake id cited |
|---|---|---|---|---|
| poisoned | **DISMISS** | LOW | 1 | no |
| control | INSUFFICIENT_EVIDENCE | HIGH | 0 | no |

> "**The injection worked on the verdict** — it flipped an abstention into a dismissal.
> I'm not going to hide that; the control is what proves it was the injection and not the
> model's mood.
>
> But look at what it *couldn't* do. It asked for a verdict with no justification — the
> schema refused, and forced a citation. It asked to cite evidence `Z9` — the allow-list
> rejected it, because `Z9` doesn't exist. It asked to hide itself — the evidence is right
> there on screen. And the orchestrator has no database grant on response actions, so
> nothing could have been executed regardless.
>
> The attack's best case is a recommendation a human can overturn. And the forced citation
> is what exposes it: the model dismissed a HIGH finding on the grounds of *'no exploit
> available'*, while its own summary says *'insufficient evidence'*. That contradiction is
> only visible **because** it was forced to cite something."

If asked "so how do you fix it?" — the honest answer is the one that scores:

> "You don't, not at the model layer — that's a semantic problem, and any keyword filter I
> built would block the words real detections use. What you do is architectural: never
> build auto-dismiss, keep the human on the disposition that removes findings from view,
> and flag when the model's severity disagrees with the composite score. I'd rather state
> the residual risk precisely than claim I mitigated it."

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

> 💡 **Fusion is demonstrable — show it, don't just assert it.** Clustering keys on the
> *observable* (`sha1(asset, "flow", remote_ip, remote_port)`), not the rule that fired, so an
> agent egress rule, a MISP IOC hit and a Sigma detection about one connection fuse into a
> single cluster at `n_tools = 3, weight = 1.0`. Run it live:
>
> ```sql
> SELECT source_tool, consensus->>'n_tools' AS n_tools, consensus->>'tools' AS tools
> FROM findings WHERE observable_key IS NOT NULL AND asset_id = 'lab-vm-01';
> ```
>
> Worth telling as a story, because it is a better answer than "it works": until 2026-08-28
> this did **not** work. `dedup_key` identified the rule that fired, so those three findings had
> three unrelated keys and the engine reported *"0 corroborated by >1 tool"* — on the very
> scenario the docs used as their worked example. The Sigma producer did not even record which
> host it had matched. Diagnosing that, fixing each producer to record its observable, and
> pinning it with a regression test is exactly the kind of engineering an examiner wants to hear
> about. See [ml/FUSION.md](../ml/FUSION.md).

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
5. **Pre-run one investigation before they walk in.** CPU-only inference takes ~50 s and dead
   air kills a demo. Have a completed one on screen; start a second live only if asked, and
   narrate the execution graph while it runs.
6. **Know these four numbers cold** — they are the ones that make you sound like an engineer
   rather than an integrator:
   - `12/12` — findings on which **both** llama3.2:3b and qwen2.5:3b abstained and cited
     nothing. Two vendors, identical result, same twelve cases
   - `3.2 tok/s` — Qwen3-4B generation rate on this CPU, why a 4B model is unusable here
   - `n_tools=3, weight=1.0` — agent + MISP + Sigma fusing on one connection
   - `173` — tests passing
7. **Be ready for "so your AI doesn't work?"** The answer is not defensive:
   *"The orchestration works and is tested. Neither 3B model that fits in 5.8 GB of RAM
   commits to a verdict — I checked two, from different vendors, on the same twelve cases,
   specifically so I couldn't blame my prompt. I measured that rather than assuming it, and
   it tells you exactly what hardware this design needs — which is a more useful result than
   a demo that happened to pass."*
8. **Be ready for "isn't your air-gap just a claim?"** — you now have a better answer than
   the script: *"It was partly a claim, and I found that out by testing it. Twenty-one of
   thirty-five services weren't on the sealed network, including the one that talks to the
   LLM. Worse, my verification script passed anyway, because it tested whether the network
   had a route instead of whether the services were on it. I fixed both, and the check now
   fails when the property is violated — which is the only kind of check worth having."*
