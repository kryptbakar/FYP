"""Unit tests for package-version → CVE-range matching.

This is security-critical: a wrong comparison means a missed CVE (false negative)
or a bogus finding (false positive). The distro-decoration stripping and the
inclusive/exclusive bound handling are the subtle parts, so they are pinned here.
"""
import version as ver


# ---------------------------------------------------------------- normalize

def test_normalize_plain():
    assert ver.normalize("2.36") == (2, 36)
    assert ver.normalize("1.2.3") == (1, 2, 3)


def test_normalize_strips_epoch_and_revision():
    assert ver.normalize("1:2.38.1") == (2, 38, 1)           # epoch dropped
    assert ver.normalize("2.36-9+deb12u3") == (2, 36)        # debian revision dropped
    assert ver.normalize("3.0.2~rc1") == (3, 0, 2)           # pre-release suffix dropped
    assert ver.normalize("1:2.36-9+deb12u3") == (2, 36)      # epoch + revision together


def test_normalize_unparseable_is_empty():
    assert ver.normalize("") == ()
    assert ver.normalize(None) == ()
    assert ver.normalize("git-abcdef") == ()


# ---------------------------------------------------------------- in_range

def test_glibc_inside_half_open_range():
    # the docstring's own example: glibc 2.36 ∈ [2.34, 2.39)
    assert ver.in_range("2.36", "2.34", True, "2.39", True)


def test_start_inclusive_vs_exclusive():
    assert ver.in_range("2.34", "2.34", True, "2.39", True)          # [2.34 includes 2.34
    assert not ver.in_range("2.34", "2.34", False, "2.39", True)     # (2.34 excludes 2.34


def test_end_exclusive_vs_inclusive():
    assert not ver.in_range("2.39", "2.34", True, "2.39", True)      # 2.39) excludes 2.39
    assert ver.in_range("2.39", "2.34", True, "2.39", False)         # 2.39] includes 2.39


def test_below_and_above_range():
    assert not ver.in_range("2.33", "2.34", True, "2.39", True)
    assert not ver.in_range("2.40", "2.34", True, "2.39", True)


def test_unbounded_range_matches_any():
    assert ver.in_range("9.9.9", None, False, None, False)           # product-level CVE


def test_only_lower_bound():
    assert ver.in_range("3.0", "2.0", True, None, False)
    assert not ver.in_range("1.0", "2.0", True, None, False)


def test_only_upper_bound():
    assert ver.in_range("1.0", None, False, "2.0", True)
    assert not ver.in_range("3.0", None, False, "2.0", True)


def test_unparseable_version_conservative():
    # unparseable version does NOT match a bounded range (avoid false positives)…
    assert not ver.in_range("weird", "2.0", True, "3.0", True)
    # …but a totally unbounded CVE still applies
    assert ver.in_range("weird", None, False, None, False)


def test_uneven_component_lengths():
    # 2.36 vs 2.36.0 must compare equal (zero-pad)
    assert ver.in_range("2.36", "2.36.0", True, "2.37", True)
    assert ver.in_range("2.36.0", "2.36", True, "2.37", True)
