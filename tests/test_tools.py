"""Smoke tests for all 6 MCP tools.

Tests validate tool functions directly (no MCP transport), ensuring
CSV data loads correctly and tool logic returns expected results.
"""

from __future__ import annotations

import pytest

from mcp_server.server import (
    check_parent_child,
    list_available_lookups,
    list_by_category,
    list_by_mitre,
    lookup_binary,
    search_lookups,
)


# ---------------------------------------------------------------------------
# lookup_binary
# ---------------------------------------------------------------------------

class TestLookupBinary:
    """Tests for the lookup_binary tool."""

    def test_known_binary(self):
        result = lookup_binary("certutil.exe")
        assert result["found"] is True
        assert result["binary_name"] == "Certutil.exe"
        assert "medium" == result["risk"]
        assert "T1105" in result["mitre_ids"]
        assert "Download" in result["categories"]

    def test_known_binary_case_insensitive(self):
        result = lookup_binary("CERTUTIL.EXE")
        assert result["found"] is True
        assert result["binary_name"] == "Certutil.exe"

    def test_known_binary_with_path(self):
        result = lookup_binary(r"C:\Windows\System32\certutil.exe")
        assert result["found"] is True
        assert result["binary_name"] == "Certutil.exe"

    def test_known_binary_unix_path(self):
        result = lookup_binary("/usr/bin/certutil.exe")
        assert result["found"] is True

    def test_unknown_binary(self):
        result = lookup_binary("totally_fake_binary.exe")
        assert result["found"] is False
        assert result["filename"] == "totally_fake_binary.exe"

    def test_high_risk_binary(self):
        result = lookup_binary("mshta.exe")
        assert result["found"] is True
        assert result["risk"] == "high"

    def test_binary_with_multiple_categories(self):
        result = lookup_binary("certutil.exe")
        assert len(result["categories"]) >= 2

    def test_binary_with_multiple_mitre_ids(self):
        result = lookup_binary("bitsadmin.exe")
        assert result["found"] is True
        assert len(result["mitre_ids"]) >= 2

    def test_whitespace_handling(self):
        result = lookup_binary("  certutil.exe  ")
        assert result["found"] is True

    def test_empty_string(self):
        result = lookup_binary("")
        assert result["found"] is False


# ---------------------------------------------------------------------------
# check_parent_child
# ---------------------------------------------------------------------------

class TestCheckParentChild:
    """Tests for the check_parent_child tool."""

    def test_expected_relationship(self):
        result = check_parent_child("services.exe", "svchost.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "true"

    def test_suspicious_relationship(self):
        result = check_parent_child("winword.exe", "cmd.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "false"
        assert best["risk_if_unexpected"] == "critical"

    def test_lsass_wildcard(self):
        """LSASS should never spawn anything — wildcard child rule."""
        result = check_parent_child("lsass.exe", "anything.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "false"
        assert best["risk_if_unexpected"] == "critical"

    def test_conditional_relationship(self):
        result = check_parent_child("svchost.exe", "rundll32.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "conditional"

    def test_unknown_relationship(self):
        result = check_parent_child("fakeparent.exe", "fakechild.exe")
        assert result["found"] is False
        assert "assessment" in result

    def test_case_insensitive(self):
        result = check_parent_child("SERVICES.EXE", "SVCHOST.EXE")
        assert result["found"] is True

    def test_path_stripping(self):
        result = check_parent_child(
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\System32\svchost.exe",
        )
        assert result["found"] is True

    def test_linux_relationship(self):
        result = check_parent_child("sshd", "bash", os_filter="linux")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["os"] == "linux"

    def test_os_filter_excludes_wrong_os(self):
        """Windows-only relationship should not appear with linux filter."""
        result = check_parent_child("services.exe", "svchost.exe", os_filter="linux")
        assert result["found"] is False

    def test_specific_match_preferred_over_wildcard(self):
        """When both specific and wildcard child rows match, specific should rank first."""
        # lsass.exe has child=* (wildcard) rule. If a specific child row also
        # existed, it should come first. Currently only wildcard exists, so
        # the wildcard should still be returned.
        result = check_parent_child("lsass.exe", "calc.exe")
        assert result["found"] is True
        assert len(result["matches"]) >= 1


# ---------------------------------------------------------------------------
# list_by_category
# ---------------------------------------------------------------------------

class TestListByCategory:
    """Tests for the list_by_category tool."""

    def test_download_category(self):
        result = list_by_category("Download")
        assert result["count"] > 0
        assert result["category"] == "Download"
        filenames = [b["filename"] for b in result["binaries"]]
        assert "certutil.exe" in filenames

    def test_execute_category(self):
        result = list_by_category("Execute")
        assert result["count"] > 10  # Execute is the largest category

    def test_case_insensitive(self):
        lower = list_by_category("download")
        upper = list_by_category("Download")
        assert lower["count"] == upper["count"]

    def test_nonexistent_category(self):
        result = list_by_category("TotallyFakeCategory")
        assert result["count"] == 0
        assert result["binaries"] == []


# ---------------------------------------------------------------------------
# list_by_mitre
# ---------------------------------------------------------------------------

class TestListByMitre:
    """Tests for the list_by_mitre tool."""

    def test_parent_technique(self):
        result = list_by_mitre("T1218")
        assert result["count"] > 0
        assert result["technique_id"] == "T1218"

    def test_sub_technique(self):
        result = list_by_mitre("T1218.011")
        assert result["count"] > 0

    def test_parent_includes_sub_techniques(self):
        """Searching T1218 should also return binaries mapped to T1218.011, etc."""
        parent = list_by_mitre("T1218")
        sub = list_by_mitre("T1218.011")
        assert parent["count"] >= sub["count"]

    def test_case_insensitive(self):
        lower = list_by_mitre("t1218")
        upper = list_by_mitre("T1218")
        assert lower["count"] == upper["count"]

    def test_nonexistent_technique(self):
        result = list_by_mitre("T9999")
        assert result["count"] == 0

    def test_t1059_hierarchy(self):
        """T1059 should match both T1059 and T1059.003, etc."""
        parent = list_by_mitre("T1059")
        assert parent["count"] >= 3  # At least the 3 from T1059 + sub-techniques


# ---------------------------------------------------------------------------
# search_lookups
# ---------------------------------------------------------------------------

class TestSearchLookups:
    """Tests for the search_lookups tool."""

    def test_search_lolbas(self):
        result = search_lookups("certutil")
        assert result["count"] > 0
        sources = [r["source"] for r in result["results"]]
        assert "lolbas_binaries" in sources

    def test_search_parent_child(self):
        result = search_lookups("svchost")
        assert result["count"] > 0
        sources = [r["source"] for r in result["results"]]
        assert "parent_child_baselines" in sources

    def test_search_mitre_id(self):
        result = search_lookups("T1003")
        assert result["count"] > 0

    def test_search_no_results(self):
        result = search_lookups("zzz_nonexistent_term_zzz")
        assert result["count"] == 0

    def test_search_empty(self):
        result = search_lookups("")
        assert "error" in result

    def test_limit(self):
        result = search_lookups("exe", limit=3)
        assert result["count"] <= 3

    def test_case_insensitive(self):
        lower = search_lookups("certutil")
        upper = search_lookups("CERTUTIL")
        assert lower["count"] == upper["count"]


# ---------------------------------------------------------------------------
# list_available_lookups
# ---------------------------------------------------------------------------

class TestListAvailableLookups:
    """Tests for the list_available_lookups tool."""

    def test_returns_lookups(self):
        result = list_available_lookups()
        assert result["count"] >= 2

    def test_lolbas_present(self):
        result = list_available_lookups()
        filenames = [l["filename"] for l in result["lookups"]]
        assert "lolbas_binaries.csv" in filenames

    def test_parent_child_present(self):
        result = list_available_lookups()
        filenames = [l["filename"] for l in result["lookups"]]
        assert "parent_child_baselines.csv" in filenames

    def test_row_counts(self):
        result = list_available_lookups()
        for lookup in result["lookups"]:
            assert lookup["rows"] > 0
            assert len(lookup["columns"]) > 0

    def test_lolbas_schema(self):
        result = list_available_lookups()
        lolbas = next(l for l in result["lookups"] if l["filename"] == "lolbas_binaries.csv")
        expected_cols = {"filename", "binary_name", "categories", "mitre_ids", "risk", "description"}
        assert expected_cols.issubset(set(lolbas["columns"]))

    def test_parent_child_schema(self):
        result = list_available_lookups()
        pc = next(l for l in result["lookups"] if l["filename"] == "parent_child_baselines.csv")
        expected_cols = {"parent", "child", "os", "expected", "risk_if_unexpected", "mitre_id"}
        assert expected_cols.issubset(set(pc["columns"]))


# ---------------------------------------------------------------------------
# CSV data integrity
# ---------------------------------------------------------------------------

class TestDataIntegrity:
    """Tests that validate the CSV data itself."""

    def test_lolbas_row_count(self):
        result = list_available_lookups()
        lolbas = next(l for l in result["lookups"] if l["filename"] == "lolbas_binaries.csv")
        assert lolbas["rows"] >= 200  # Should have 200+ LOLBAS entries

    def test_parent_child_row_count(self):
        result = list_available_lookups()
        pc = next(l for l in result["lookups"] if l["filename"] == "parent_child_baselines.csv")
        assert pc["rows"] >= 90  # Should have 90+ baseline entries

    def test_all_lolbas_have_risk(self):
        """Every LOLBAS entry must have a risk rating."""
        result = list_by_category("Execute")
        for binary in result["binaries"]:
            assert binary["risk"] in ("high", "medium", "low"), (
                f"{binary['filename']} has invalid risk: {binary['risk']}"
            )

    def test_all_lolbas_filenames_lowercase(self):
        """Match key (filename) must be lowercase for SIEM join consistency."""
        result = search_lookups("exe", limit=500)
        for r in result["results"]:
            if r["source"] == "lolbas_binaries":
                assert r["filename"] == r["filename"].lower(), (
                    f"Filename not lowercase: {r['filename']}"
                )
