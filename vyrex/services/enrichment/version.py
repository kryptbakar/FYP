"""Best-effort version comparison for matching package versions to CVE ranges.

Distro versions are messy (epochs `1:`, Debian revisions `-2+deb12u3`, `~rc`),
and NVD CPE ranges use upstream versions. We strip distro decoration down to the
leading dotted-numeric upstream version and compare component-wise. This is
deliberately approximate for the MVP — a production system would use full dpkg
version semantics (libapt) — and it's enough to place e.g. glibc 2.36 inside
[2.34, 2.39). See DECISIONS D-019.
"""
from __future__ import annotations

import re

_LEAD_NUM = re.compile(r"\d+(?:\.\d+)*")


def normalize(v: str | None) -> tuple[int, ...]:
    """Reduce a version string to a tuple of ints from its leading numeric part."""
    if not v:
        return ()
    v = v.strip()
    if ":" in v:                      # drop epoch  (1:2.38.1 -> 2.38.1)
        v = v.split(":", 1)[1]
    v = re.split(r"[-+~]", v, 1)[0]   # drop Debian revision / suffixes
    m = _LEAD_NUM.match(v)
    if not m:
        return ()
    return tuple(int(p) for p in m.group(0).split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(
    version: str,
    start: str | None,
    start_incl: bool,
    end: str | None,
    end_excl: bool,
) -> bool:
    """Is `version` within [start, end) (with the given inclusivity flags)?

    A range with neither bound matches any version (product-level CVE).
    Unparseable versions conservatively do NOT match a bounded range.
    """
    v = normalize(version)
    if not v:
        return start is None and end is None
    if start:
        c = _cmp(v, normalize(start))
        if c < 0 or (c == 0 and not start_incl):
            return False
    if end:
        c = _cmp(v, normalize(end))
        if c > 0 or (c == 0 and end_excl):
            return False
    return True
