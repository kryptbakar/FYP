# Agent orchestration — the investigation engine

How VYREX turns a finding into a **cited, auditable verdict**, and why it is built the way
it is.

---

## 1. What this replaces, and why

The original AI analyst (`POST /agent/triage`) was a single fire-and-forget LLM call. It
built a prompt, called Ollama once, `json.loads`'d the reply inside a bare `try/except`,
and stored the whole run as **one opaque JSON blob** in `agent_runs.decisions`.

Four things followed, none of them acceptable in a security tool:

| Problem | Consequence |
|---|---|
| No per-step trace | "The historical branch found nothing" and "the historical branch crashed" are indistinguishable |
| No evidence, no citations | A claim cannot be checked against anything |
| No resumability | A restart loses the run entirely |
| Synchronous, 180–240 s | The console's own nginx caps a proxied response at **30 s**, so the reverse proxy killed the request before the answer existed |

The failure mode was also silent: a malformed reply degraded to *zero decisions* and the
caller saw success. Observed live on 2026-08-22 — a triage run took 194 s and returned an
empty result with no error anywhere.

---

## 2. Shape

```
Console / n8n ──► POST /investigations ──► 202 {investigation_id}
                          │
                          │  investigation row + outbox row, ONE transaction
                          ▼
                 investigation_outbox  ◄── risk engine (automatic, on score crossing)
                          │
                          │  FOR UPDATE SKIP LOCKED
                          ▼
                 investigation-orchestrator
                          │
              load_subject ──► route ──┬──► asset_context      ─┐
                                       ├──► attack_context     ─┤
                                       ├──► intel_context      ─┼──► synthesize ──► validate
                                       ├──► fusion_context     ─┤        (LLM)      (deterministic)
                                       └──► historical_context ─┘
                          │
                          ▼
      investigation_steps · investigation_evidence · triage_reports
                          │
                          ▼
              GET /investigations/{id}/steps | /evidence | /report
```

### Only one node uses a model

The five specialists are plain SQL retrieval; the router and validator are branching logic.
**Only `synthesize` consults an LLM.** This is a deliberate position, not a shortcut:
everything feeding the model is code that can be read, unit-tested and defended line by
line, so *"the model decided"* is never the explanation for a verdict.

Calling this "five AI agents" would not survive examination. What it is — *a six-node
investigation graph with deterministic evidence retrieval and a single citation-bound LLM
synthesis step* — is both accurate and a stronger claim.

---

## 3. The three invariants

These are enforced by types and code, not by convention, because each protects against a
failure that is invisible in a demo.

### 3.1 Every claim must cite

`Claim.citation_ids` has `min_length=1`, so an uncited claim **cannot be constructed**.
After synthesis, `validate` drops any claim citing an id the evidence set does not contain,
records it in `unresolved_citations`, and downgrades the report to `partial`.

A fabricated citation looks *more* rigorous than a missing one. That is precisely why it
has to be caught mechanically — and it has caught real fabrications three times during
development (twice from a bug in the test double, which is exactly the kind of thing that
would otherwise ship).

### 3.2 The model does not set its own confidence

`SynthesisOutput` — the schema handed to Ollama — has **no confidence field** and
`extra="forbid"`. A model that volunteers one fails schema validation.

Confidence is computed by `derive_confidence()` from observed execution:

```
0.6 × branch coverage  +  0.3 × evidence volume (saturating at 5)  +  0.1 × corroboration
abstention caps the result at 0.5
```

Deliberately simple and explainable. A self-reported "0.95" is a fluent sentence, not a
measurement; and a function fitted on 42 findings would be no more defensible.

### 3.3 Missing evidence is represented, not omitted

A branch that finds nothing writes a `skipped` step with a reason. A branch that raises
writes `failed` with the exception, and the investigation **continues degraded** — the
confidence denominator counts the branches the router actually selected, so coverage falls
and confidence falls with it.

Verified: `historical_context` failed on a Postgres `AmbiguousParameter` and the run still
completed, with the reason on the step row.

---

## 4. Durability

**Transactional outbox.** `POST /investigations` writes the investigation row and its
outbox row in one transaction. An event can never announce work that rolled back, and work
can never commit without its event — and a lost automatic trigger is invisible, which makes
it the worse of the two failures.

**Exactly-once triggering.** The risk engine fires on a score *crossing*, not a level.
`do_score_once` re-scores every finding every 180 s, so a level rule would re-request an
investigation forever. `findings.previous_risk_score` plus an atomic
`UPDATE ... RETURNING` gives the edge. Measured: first pass queued 4, the next two queued 0.

**One active run per subject.** A partial unique index on
`(subject_type, subject_id, policy_version) WHERE status IN ('queued','running')`. A
duplicate request returns the run already in flight; two concurrent callers cannot both win.

**Resume after a crash.** LangGraph checkpoints to Postgres between nodes. Because
`claim_next_job` marks the outbox row `sent` before running, a crashed worker would
otherwise strand the run — so `resume_orphans()` re-drives anything still `running` at
startup, keyed on the original `thread_id`.

> Verified by SIGKILL mid-synthesis: crash state was `running` / `sent` / 0 reports /
> 30 checkpoint rows; restart logged *"found 1 investigation abandoned mid-graph"* and
> drove it to completion. Evidence was not duplicated (4 rows / 4 citations).
>
> **Single-instance only.** Any `running` row at startup is stale *because this process is
> the only thing that could have been running it*. Scaling out needs a lease (worker id +
> heartbeat) or a second worker will steal a live run.

### Why the outbox and not NATS

The plan called for a JetStream stream fed by a relay. Once the outbox existed that hop
stopped paying for itself: the table already provides durability, ordering, retry counting
and a dead-letter state, and `FOR UPDATE SKIP LOCKED` gives the same competing-consumer
semantics — with one fewer delivery guarantee to reason about and no possibility of the
table and the stream disagreeing about what has been processed. Volume is a handful per
hour, not thousands per second.

`repository.claim_next_job` is the seam. It is the only function that changes if a broker
is ever wanted.

---

## 5. Citation id scheme

Each branch owns a prefix, so parallel branches never collide on an id without
coordinating — and the prefix tells the analyst where a citation came from before they
click it.

| Prefix | Source |
|---|---|
| `F` | the finding itself |
| `X` | SHAP explanation (reused from the risk engine, not recomputed) |
| `A` | asset + compliance posture |
| `T` | ATT&CK technique prevalence |
| `I` | threat intel (MISP) |
| `C` | fusion cluster — multi-tool corroboration |
| `H` | historical similar findings and how they were triaged |

`historical_context` uses **structured** similarity (same CVE / asset / technique), not
embeddings. On a corpus this size a vector index would be slower, unexplainable and no more
accurate. Embeddings remain a measured stretch goal that has to *beat* this, not replace it
on principle.

---

## 6. Measured behaviour

Everything below is from live runs, not estimates.

| | Phase 1 (1 evidence node) | Phase 2 (5 specialists) |
|---|---|---|
| Evidence records | 4 | 9 |
| Latency (llama3.2:3b, CPU) | 82.8 s | 128.4 s |
| Unresolved citations | 0 | 0 |
| Completeness | complete | complete |
| Verdict | INSUFFICIENT_EVIDENCE | INSUFFICIENT_EVIDENCE |

### The open problem: the model, not the pipeline

On finding 4289 — three-tool corroboration (agent + MISP + Sigma) and a Cobalt Strike C2
indicator, where an analyst would escalate — `llama3.2:3b`:

- produced schema-valid output every time,
- cited nothing at all (**0 claims**, despite the system prompt requiring a citation per
  claim),
- abstained,
- and in an earlier run claimed the SHAP factors were *"not provided"* when it had been
  given five weighted factors and `ml_risk_score 69.24`.

Format discipline is fine. **Comprehension is the ceiling.** Richer evidence bought
better-articulated reasoning, not a better verdict.

This has deliberately **not** been fixed by inflating the prompt. Tuning against a single
case produces something that works on one demo and nothing else. It is the decision the
model benchmark exists to make.

---

## 7. Benchmarking

```
make model-benchmark MODELS=llama3.2:3b,qwen3:4b CASES=5 REPEATS=2
```

Measures **behaviour**, on the real prompt and real evidence, with the model as the only
variable: schema validity, whether a repair attempt was needed, citation validity, uncited
verdicts, abstention rate, p50/p95 latency, and determinism across repeats at temperature 0.

It does **not** measure accuracy. That needs ground-truth labels; `analyst_feedback` is
empty, and scoring a model against another model's opinion would repeat exactly the
circular evaluation [METHODOLOGY.md §4.1](METHODOLOGY.md) already documents in the ML layer.
Accuracy is Phase 4, after blinded labelling.

Everything it does measure is objective and label-free — which is why it is enough to
*choose* a model, the decision currently blocked.

> **RAM.** A 4B model needs ~2.5 GB and Docker has 5.8 GB total on the dev host. With the
> full stack up there was 973 MB free. Stop the heavy tools profile first.

---

## 8. Compatibility

`/agent/triage` and `/agent/investigate` still work, marked `deprecated=True` in OpenAPI
with a `_deprecated` field pointing at the replacement. They are removed once their two
live consumers migrate: the n8n master workflow's *"Run AI analyst (Ollama)"* lane, and the
console at `views.js` 438 / 1700 / 2058. Breaking a working demo path to satisfy a
migration step would be the wrong trade.

---

## 9. What is deliberately not built

- **No autonomous containment.** The graph proposes; execution stays behind VYREX's
  two-person, Ed25519-signed approval gate. The orchestrator's database role has no grant
  on `response_actions`.
- **No hidden chain-of-thought stored.** Steps record retrieved evidence, tool activity and
  analyst-facing rationale — not the model's internal monologue.
- **No cloud LLM.** Ollama, on-prem, air-gapped.
- **No accuracy claims** until Phase 4 produces blinded labels.
