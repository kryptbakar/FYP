# Labelling rubric — PRE-REGISTERED

> **Status: FROZEN on 2026-08-28, before any case was labelled and before any
> investigation was run on the evaluation corpus.**
>
> **Rubric version: `rubric-v1`.** Every label records the rubric version it was made
> under. This document is the reason the evaluation means anything: it exists so that
> labels cannot drift toward whatever VYREX happens to output.
>
> Required reading first: [EVALUATION-PROTOCOL.md](EVALUATION-PROTOCOL.md) §2, which
> explains why a solo project needs temporal blinding and what that does and does not buy.

The honest framing: this is one analyst labelling their own system's test set. That is a
real weakness. The mitigations are (a) labelling strictly *before* the system runs, (b) a
decision procedure fixed in advance and followed mechanically, and (c) advisor adjudication
on a subsample. What this rubric buys is **reproducibility** — a second rater given this
document and the same case should reach the same label most of the time, and §11 measures
whether that is actually true rather than assuming it.

---

## 1. What a "case" is

One **finding** (a row in `findings`), together with everything a human could see about it
in the console *without* running an investigation:

- the finding itself: title, description, `severity`, `source_tool`, `dedup_key`
- CVE / KEV / EPSS / CVSS where present
- the asset: hostname, `criticality`, environment, exposure
- the composite `risk_score` and its SHAP factor breakdown
- the fusion cluster: which tools corroborate, `n_tools`, `weight`

**Explicitly NOT visible at labelling time:** any investigation verdict, any LLM output,
any `triage_reports` row. If a case has already been investigated, the labeller must not
open it. In practice: label from a frozen CSV export, not from the live console.

---

## 2. The label

Each case gets exactly one record with these fields:

| Field | Values | Notes |
|---|---|---|
| `case_id` | finding UUID | |
| `disposition` | `ESCALATE` \| `MONITOR` \| `DISMISS` \| `INSUFFICIENT_EVIDENCE` | §4–§7. Matches `Disposition` in `contracts.py` exactly |
| `severity` | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` | §8. The labeller's judgement, **not** the tool's `severity` field |
| `rationale` | free text, ≥ 1 sentence | Why, in the labeller's own words, before seeing any system output |
| `deciding_signals` | ordered list from §9 | Which signals actually drove it |
| `evidence_gaps` | free text or empty | What the labeller wished they had |
| `confidence` | `certain` \| `probable` \| `uncertain` | The labeller's own; used only for stratified analysis, never as a weight |
| `rubric_version` | `rubric-v1` | |
| `labelled_at` | ISO-8601 UTC | |

`rationale` is not decoration. At adjudication it is the only way to tell a genuine
disagreement from two people using a word differently.

---

## 3. The decision procedure — follow it in order

Answer in sequence and **stop at the first rule that fires**. Ordering is what makes this
reproducible; picking whichever rule feels right is how a rubric becomes a vibe.

1. **Is the evidence sufficient to decide at all?** If not → `INSUFFICIENT_EVIDENCE` (§7).
2. **Is this a false positive or an accepted risk?** → `DISMISS` (§6).
3. **Is there active-exploitation or confirmed-malicious evidence on a reachable asset?**
   → `ESCALATE` (§4).
4. **Is it real but not urgent — no exploitation signal, or not reachable, or low-value
   asset?** → `MONITOR` (§5).
5. If none fired, the case is under-specified. → `INSUFFICIENT_EVIDENCE`, and record why in
   `evidence_gaps`. Do not force a decision to avoid an abstention.

---

## 4. ESCALATE

**Definition:** a human should act on this **now** — within the current shift.

Label ESCALATE when **at least one** holds:

- **Known exploited.** CVE is in CISA KEV, on an asset that is running and reachable.
- **Confirmed malicious activity.** An IOC match, C2 indicator, or detection describing
  activity that is malicious by nature rather than merely unusual (e.g. reverse shell,
  credential dumping, ransomware canary).
- **Multi-tool corroboration of a serious event.** `n_tools ≥ 2` independently describing
  the same observable, where at least one is a detection rather than an inventory finding.
- **Critical asset + credible remote exploitation path.** `criticality = critical`,
  internet-exposed, CVSS ≥ 7.0 with a network attack vector.

**Do not** escalate on severity alone. A `CRITICAL` CVE on a decommissioned host in an
isolated segment is not an escalation, and treating it as one is precisely the alert-fatigue
behaviour VYREX exists to reduce.

---

## 5. MONITOR

**Definition:** real, and worth tracking, but does not warrant interrupting anyone today.

Typical shape:

- A genuine vulnerability with no exploitation signal (not in KEV, low EPSS) on a
  non-critical or non-exposed asset.
- Anomalous-but-not-malicious activity: unusual egress to a benign destination, a policy
  deviation, a noisy-but-plausible detection.
- A serious finding whose asset is unreachable, already mitigated, or scheduled for patching.
- Compliance and configuration drift with no immediate attack path.

MONITOR is the correct home for most of a real SOC's queue. A labeller who never uses it is
probably escalating on severity.

---

## 6. DISMISS

**Definition:** no action needed, and the finding should not persist in the queue.

- **False positive.** The detection logic misfired; the described condition is not present.
- **Not applicable.** Package present but the vulnerable code path is not reachable
  (e.g. a library shipped but never loaded); the CVE does not apply to this configuration.
- **Accepted risk / known-good.** Documented exception, an approved administrative tool, an
  expected backup or scanner connection.
- **Duplicate** of another case already labelled in this corpus — record the twin's
  `case_id` in `rationale`.

DISMISS is a claim that the *finding* is wrong or irrelevant, not that it is low priority.
"Low priority but real" is MONITOR. Conflating the two destroys the ESCALATE/MONITOR/DISMISS
distinction the macro-F1 is supposed to measure.

---

## 7. INSUFFICIENT_EVIDENCE — a correct answer, not a cop-out

Use it when a competent analyst genuinely could not decide from what is present:

- The finding names an asset that does not exist in inventory, so exposure and criticality
  are unknowable.
- A detection records only that a rule fired, with no observable — no host, no peer, no port.
- The evidence is internally contradictory (e.g. corroborating tools disagree on the target).
- A **deliberate missing-evidence case** (§10), constructed by removing evidence a decision
  would have required.

**The abuse to guard against** is using it for cases that are merely hard. The test:
*could any additional retrievable evidence change the answer?* If no — the case is decidable
and you are avoiding a call. If yes — name that evidence in `evidence_gaps`. **A label of
INSUFFICIENT_EVIDENCE with an empty `evidence_gaps` is invalid** and must be redone.

This matters more here than in a typical rubric, because abstention is exactly what
llama3.2:3b does on every case (12/12). Without a principled definition of when abstention is
*right*, the evaluation cannot distinguish a well-calibrated abstention from a model that
simply never commits — and that distinction is the difference between a system that is
appropriately cautious and one that is useless.

---

## 8. Severity

The labeller's own judgement of impact if the finding is real and exploited. Deliberately
**independent of the tool's `severity`**, so the evaluation can measure whether tool severity
is a good predictor at all.

| | Meaning |
|---|---|
| `CRITICAL` | Compromise of a critical asset, or a foothold that plausibly leads to one |
| `HIGH` | Serious compromise of a non-critical asset, or significant data/service exposure |
| `MEDIUM` | Limited impact, or requires conditions not currently met |
| `LOW` | Negligible impact even if fully exploited |

Severity and disposition are separate axes: a CRITICAL-severity finding on an unreachable
host is `MONITOR`. Recording both is what makes that visible.

---

## 9. Signal precedence

When signals conflict, weigh them in this order. This is a **pre-registered ordering**, not a
formula, and it is deliberately not the composite score's weighting — otherwise the labels
would inherit the very circularity that [METHODOLOGY.md §4.1](METHODOLOGY.md) documents in the
ML layer, and the evaluation would be measuring VYREX against itself.

1. **Confirmed malicious activity** (IOC hit, C2, attack-technique detection)
2. **Known exploitation in the wild** (KEV; high EPSS)
3. **Reachability** (internet-exposed > internal > isolated > offline)
4. **Asset criticality** (business impact of the host)
5. **Multi-tool corroboration** (independent agreement raises confidence in *the finding*)
6. **Intrinsic severity** (CVSS, tool severity)

Corroboration sits at 5 deliberately: it is evidence that the finding is *true*, not that it
is *urgent*. Three tools agreeing about a trivial issue is still a trivial issue.

---

## 10. Corpus and stratification

Target **60–80 cases**. As of 2026-08-28 the database holds **54 findings**
(29 HIGH, 13 MEDIUM, 6 CRITICAL, 6 LOW), so the corpus needs expansion — see
EVALUATION-PROTOCOL.md §2.5. Sample to cover, not to balance:

| Axis | Requirement |
|---|---|
| Severity | ≥ 5 cases in each of CRITICAL / HIGH / MEDIUM / LOW |
| Domain | vulnerability, network detection, host detection, compliance |
| Source tool | ≥ 3 distinct `source_tool` values |
| KEV | ≥ 8 KEV cases and ≥ 8 non-KEV |
| Corroboration | ≥ 6 with `n_tools ≥ 2`, ≥ 6 singletons |
| IOC | ≥ 5 with an IOC match |
| **Missing evidence** | **≥ 6 constructed cases** where required evidence is absent |

The missing-evidence cases are constructed on purpose and flagged in the label file. They are
the only way to measure abstention quality: without cases where abstaining is *correct*, a
model that always abstains and a model that abstains appropriately score identically.

---

## 11. Adjudication

- The advisor independently labels a **random 20% subsample** using this document alone,
  with no access to VYREX output or to the primary labels.
- Agreement is reported as **Cohen's κ** on disposition, and as weighted agreement on
  severity (adjacent categories are partial credit; opposite ends are not).
- **Disagreements are reported, not resolved.** Silently overwriting the primary label with
  the adjudicated one and then reporting κ would inflate the statistic. If a disagreement
  reveals a genuine rubric ambiguity, that is a finding about the rubric and belongs in the
  limitations section.
- If κ < 0.4, the rubric is not reproducible enough to support accuracy claims, and the
  thesis says so rather than reporting the accuracy anyway.

---

## 12. What invalidates a label

Any of these voids the label; redo it or drop the case, and record which:

- Made after seeing any VYREX investigation output for that case.
- Made under a different `rubric_version` than the one being reported.
- `INSUFFICIENT_EVIDENCE` with empty `evidence_gaps` (§7).
- Revised after the fact. **Labels are append-only.** A mistaken label is corrected by
  adding a superseding row with a reason, never by editing history — the git history is the
  proof that temporal blinding held, so rewriting it destroys the evidence.

---

## 13. Change control

This rubric is frozen. If a genuine defect is found mid-labelling:

1. Stop labelling.
2. Bump to `rubric-v2` and record what changed and why.
3. **Re-label from scratch under v2** — mixing versions in one macro-F1 is not valid.
4. Report both the change and the cost in the thesis.

The bar for a change is a defect that makes cases *impossible to label consistently*, not the
discovery that VYREX disagrees with the rubric. That discovery is the result, not a bug.
