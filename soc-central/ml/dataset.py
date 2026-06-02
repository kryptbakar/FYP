"""Training-data assembly.

We have no historical analyst labels yet, so we bootstrap: generate a broad,
synthetic population of findings and label each with the composite score PLUS
deliberate non-linear interactions + noise that mimic analyst judgement
(KEV×EPSS, exposure×CVSS, attack-phase, weak-compliance×exposure). XGBoost then
learns those interactions — which the linear composite cannot express — and SHAP
surfaces them. As real analyst feedback accrues (analyst_feedback table) it is
folded in with higher weight, and the model is retrained (monthly cadence). This
is the assembly idea adapted from the cve-enriched-dataset reference.
"""
from __future__ import annotations

import numpy as np

from features import FEATURES
from scoring import composite

RNG = np.random.default_rng(42)


def _label(fd: dict[str, float], rng) -> float:
    base, _ = composite(fd)  # linear baseline 0..100
    boost = 0.0
    boost += 25.0 * fd["kev"] * fd["epss"]                     # known-exploited AND likely
    boost += 12.0 * fd["exposure"] * fd["cvss"]                # exploitable AND reachable
    boost += 10.0 * fd["attack_phase"] * (0.5 + fd["cvss"])    # late kill-chain stages matter more
    boost += 6.0 * fd["compliance_impact"] * fd["exposure"]    # weak host + exposed
    # Phase-F fusion interactions:
    boost += 20.0 * fd["threat_intel"] * (0.5 + fd["epss"])    # live IOC seen AND exploitable
    boost += 15.0 * fd["consensus"] * (0.5 + fd["cvss"])       # several tools agree on a real issue
    boost += 8.0 * fd["attack_ctx"] * fd["consensus"]          # ATT&CK-mapped AND corroborated
    noise = rng.normal(0, 4.0)                                 # analyst subjectivity
    return float(np.clip(base + boost + noise, 0, 100))


def generate_synthetic(n: int = 6000, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    X, y = [], []
    for _ in range(n):
        fd = {
            "cvss": float(rng.beta(2, 2)),
            "epss": float(rng.beta(0.6, 6)),          # most CVEs low EPSS, a few high
            "kev": float(rng.random() < 0.15),
            "exposure": float(rng.beta(1.5, 2)),
            "threat_intel": float(rng.random() < 0.08),          # IOC hits are rare but decisive
            "consensus": float(rng.choice([0.0, 0.0, 0.0, 0.5, 1.0])),  # most findings: one tool
            "attack_ctx": float(rng.choice([0.0, 0.0, 0.5, 0.7, 0.9, 1.0])),
            "compliance_impact": float(rng.random()),
            "age": float(rng.random()),
            "criticality": float(rng.choice([0.25, 0.5, 1.0])),
            "attack_phase": float(rng.choice([1, 2, 3, 4, 5, 6, 7]) / 7),
        }
        X.append([fd[f] for f in FEATURES])
        y.append(_label(fd, rng))
    return np.array(X, dtype=float), np.array(y, dtype=float)
