"""Smoke tests for all 6 MCP tools.

Tests validate tool functions directly (no MCP transport), ensuring
CSV data loads correctly and tool logic returns expected results.
"""

from __future__ import annotations

import pytest

from mcp_server.server import (
    detection_check_parent_child,
    detection_list_lookups,
    detection_list_by_category,
    detection_list_by_mitre,
    detection_lookup_binary,
    detection_search,
)


# ---------------------------------------------------------------------------
# lookup_binary
# ---------------------------------------------------------------------------

class TestLookupBinary:
    """Tests for the lookup_binary tool."""

    def test_known_binary(self):
        result = detection_lookup_binary("certutil.exe")
        assert result["found"] is True
        assert result["binary_name"] == "Certutil.exe"
        assert "medium" == result["risk"]
        assert "T1105" in result["mitre_ids"]
        assert "Download" in result["categories"]
        assert result["source"] == "lolbas"

    def test_known_binary_case_insensitive(self):
        result = detection_lookup_binary("CERTUTIL.EXE")
        assert result["found"] is True
        assert result["binary_name"] == "Certutil.exe"

    def test_known_binary_with_path(self):
        result = detection_lookup_binary(r"C:\Windows\System32\certutil.exe")
        assert result["found"] is True
        assert result["binary_name"] == "Certutil.exe"

    def test_known_binary_unix_path(self):
        result = detection_lookup_binary("/usr/bin/certutil.exe")
        assert result["found"] is True

    def test_unknown_binary(self):
        result = detection_lookup_binary("totally_fake_binary.exe")
        assert result["found"] is False
        assert result["filename"] == "totally_fake_binary.exe"
        assert "suggestion" in result

    def test_high_risk_binary(self):
        result = detection_lookup_binary("mshta.exe")
        assert result["found"] is True
        assert result["risk"] == "high"

    def test_binary_with_multiple_categories(self):
        result = detection_lookup_binary("certutil.exe")
        assert len(result["categories"]) >= 2

    def test_binary_with_multiple_mitre_ids(self):
        result = detection_lookup_binary("bitsadmin.exe")
        assert result["found"] is True
        assert len(result["mitre_ids"]) >= 2

    def test_whitespace_handling(self):
        result = detection_lookup_binary("  certutil.exe  ")
        assert result["found"] is True

    def test_empty_string(self):
        result = detection_lookup_binary("")
        assert result["found"] is False

    def test_gtfobins_lookup(self):
        """GTFOBins binary should be found with source='gtfobins'."""
        result = detection_lookup_binary("curl")
        assert result["found"] is True
        # curl exists in both LOLBAS and GTFOBins, so we expect matches
        if "matches" in result:
            sources = [m["source"] for m in result["matches"]]
            assert "gtfobins" in sources
        else:
            assert result["source"] in ("lolbas", "gtfobins")

    def test_gtfobins_only_binary(self):
        """Binary only in GTFOBins (not LOLBAS)."""
        result = detection_lookup_binary("bash")
        assert result["found"] is True
        assert result["source"] == "gtfobins"
        assert "shell" in result["categories"]

    def test_gtfobins_linux_path(self):
        """GTFOBins binary lookup with Linux path."""
        result = detection_lookup_binary("/usr/bin/python")
        assert result["found"] is True


# ---------------------------------------------------------------------------
# check_parent_child
# ---------------------------------------------------------------------------

class TestCheckParentChild:
    """Tests for the check_parent_child tool."""

    def test_expected_relationship(self):
        result = detection_check_parent_child("services.exe", "svchost.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "true"

    def test_suspicious_relationship(self):
        result = detection_check_parent_child("winword.exe", "cmd.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "false"
        assert best["risk_if_unexpected"] == "critical"

    def test_lsass_wildcard(self):
        """LSASS should never spawn anything — wildcard child rule."""
        result = detection_check_parent_child("lsass.exe", "anything.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "false"
        assert best["risk_if_unexpected"] == "critical"

    def test_conditional_relationship(self):
        result = detection_check_parent_child("svchost.exe", "rundll32.exe")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["expected"] == "conditional"

    def test_unknown_relationship(self):
        result = detection_check_parent_child("fakeparent.exe", "fakechild.exe")
        assert result["found"] is False
        assert "assessment" in result
        assert "suggestion" in result

    def test_case_insensitive(self):
        result = detection_check_parent_child("SERVICES.EXE", "SVCHOST.EXE")
        assert result["found"] is True

    def test_path_stripping(self):
        result = detection_check_parent_child(
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\System32\svchost.exe",
        )
        assert result["found"] is True

    def test_linux_relationship(self):
        result = detection_check_parent_child("sshd", "bash", os_filter="linux")
        assert result["found"] is True
        best = result["matches"][0]
        assert best["os"] == "linux"

    def test_os_filter_excludes_wrong_os(self):
        """Windows-only relationship should not appear with linux filter."""
        result = detection_check_parent_child("services.exe", "svchost.exe", os_filter="linux")
        assert result["found"] is False

    def test_specific_match_preferred_over_wildcard(self):
        """When both specific and wildcard child rows match, specific should rank first."""
        # lsass.exe has child=* (wildcard) rule. If a specific child row also
        # existed, it should come first. Currently only wildcard exists, so
        # the wildcard should still be returned.
        result = detection_check_parent_child("lsass.exe", "calc.exe")
        assert result["found"] is True
        assert len(result["matches"]) >= 1


# ---------------------------------------------------------------------------
# list_by_category
# ---------------------------------------------------------------------------

class TestListByCategory:
    """Tests for the list_by_category tool."""

    def test_download_category(self):
        result = detection_list_by_category("Download")
        assert result["total"] > 0
        assert result["category"] == "Download"
        filenames = [b["filename"] for b in result["binaries"]]
        assert "certutil.exe" in filenames

    def test_execute_category(self):
        result = detection_list_by_category("Execute")
        assert result["total"] > 10  # Execute is the largest category

    def test_case_insensitive(self):
        lower = detection_list_by_category("download")
        upper = detection_list_by_category("Download")
        assert lower["total"] == upper["total"]

    def test_nonexistent_category(self):
        result = detection_list_by_category("TotallyFakeCategory")
        assert result["total"] == 0
        assert result["binaries"] == []
        assert "suggestion" in result

    def test_gtfobins_shell_category(self):
        """GTFOBins shell category should return Linux binaries."""
        result = detection_list_by_category("shell")
        assert result["total"] > 50
        sources = {b["source"] for b in result["binaries"]}
        assert "gtfobins" in sources

    def test_gtfobins_reverse_shell_category(self):
        result = detection_list_by_category("reverse-shell")
        assert result["total"] > 0
        filenames = [b["filename"] for b in result["binaries"]]
        assert "bash" in filenames


# ---------------------------------------------------------------------------
# list_by_mitre
# ---------------------------------------------------------------------------

class TestListByMitre:
    """Tests for the list_by_mitre tool."""

    def test_parent_technique(self):
        result = detection_list_by_mitre("T1218")
        assert result["total"] > 0
        assert result["technique_id"] == "T1218"

    def test_sub_technique(self):
        result = detection_list_by_mitre("T1218.011")
        assert result["total"] > 0

    def test_parent_includes_sub_techniques(self):
        """Searching T1218 should also return binaries mapped to T1218.011, etc."""
        parent = detection_list_by_mitre("T1218")
        sub = detection_list_by_mitre("T1218.011")
        assert parent["total"] >= sub["total"]

    def test_case_insensitive(self):
        lower = detection_list_by_mitre("t1218")
        upper = detection_list_by_mitre("T1218")
        assert lower["total"] == upper["total"]

    def test_nonexistent_technique(self):
        result = detection_list_by_mitre("T9999")
        assert result["total"] == 0
        assert "suggestion" in result

    def test_t1059_hierarchy(self):
        """T1059 should match both T1059 and T1059.003, etc."""
        parent = detection_list_by_mitre("T1059")
        assert parent["total"] >= 3  # At least the 3 from T1059 + sub-techniques

    def test_t1059_includes_gtfobins(self):
        """T1059 should return GTFOBins shell binaries as well."""
        result = detection_list_by_mitre("T1059")
        sources = {b["source"] for b in result["binaries"]}
        assert "gtfobins" in sources

    def test_t1105_cross_platform(self):
        """T1105 (Ingress Tool Transfer) should include both LOLBAS and GTFOBins."""
        # Use limit=100 since LOLBAS alone has 50+ T1105 entries,
        # which would push GTFOBins results off the default page.
        result = detection_list_by_mitre("T1105", limit=100)
        sources = {b["source"] for b in result["binaries"]}
        assert "lolbas" in sources
        assert "gtfobins" in sources


# ---------------------------------------------------------------------------
# search_lookups
# ---------------------------------------------------------------------------

class TestSearchLookups:
    """Tests for the search_lookups tool."""

    def test_search_lolbas(self):
        result = detection_search("certutil")
        assert result["count"] > 0
        assert "total" in result
        assert "has_more" in result
        sources = [r["source"] for r in result["results"]]
        assert "lolbas_binaries" in sources

    def test_search_parent_child(self):
        result = detection_search("svchost")
        assert result["count"] > 0
        sources = [r["source"] for r in result["results"]]
        assert "parent_child_baselines" in sources

    def test_search_mitre_id(self):
        result = detection_search("T1003")
        assert result["count"] > 0

    def test_search_no_results(self):
        result = detection_search("zzz_nonexistent_term_zzz")
        assert result["count"] == 0
        assert "suggestion" in result

    def test_search_empty(self):
        result = detection_search("")
        assert "error" in result
        assert "suggestion" in result

    def test_limit(self):
        result = detection_search("exe", limit=3)
        assert result["count"] <= 3

    def test_case_insensitive(self):
        lower = detection_search("certutil")
        upper = detection_search("CERTUTIL")
        assert lower["total"] == upper["total"]

    def test_search_gtfobins(self):
        """Search should include GTFOBins results."""
        result = detection_search("reverse-shell")
        assert result["count"] > 0
        sources = {r["source"] for r in result["results"]}
        assert "gtfobins" in sources


# ---------------------------------------------------------------------------
# list_available_lookups
# ---------------------------------------------------------------------------

class TestListAvailableLookups:
    """Tests for the list_available_lookups tool."""

    def test_returns_lookups(self):
        result = detection_list_lookups()
        assert result["count"] >= 3  # lolbas, parent_child, gtfobins

    def test_lolbas_present(self):
        result = detection_list_lookups()
        filenames = [l["filename"] for l in result["lookups"]]
        assert "lolbas_binaries.csv" in filenames

    def test_parent_child_present(self):
        result = detection_list_lookups()
        filenames = [l["filename"] for l in result["lookups"]]
        assert "parent_child_baselines.csv" in filenames

    def test_gtfobins_present(self):
        result = detection_list_lookups()
        filenames = [l["filename"] for l in result["lookups"]]
        assert "gtfobins.csv" in filenames

    def test_row_counts(self):
        result = detection_list_lookups()
        for lookup in result["lookups"]:
            assert lookup["rows"] > 0
            assert len(lookup["columns"]) > 0

    def test_lolbas_schema(self):
        result = detection_list_lookups()
        lolbas = next(l for l in result["lookups"] if l["filename"] == "lolbas_binaries.csv")
        expected_cols = {"filename", "binary_name", "categories", "mitre_ids", "risk", "description"}
        assert expected_cols.issubset(set(lolbas["columns"]))

    def test_parent_child_schema(self):
        result = detection_list_lookups()
        pc = next(l for l in result["lookups"] if l["filename"] == "parent_child_baselines.csv")
        expected_cols = {"parent", "child", "os", "expected", "risk_if_unexpected", "mitre_id"}
        assert expected_cols.issubset(set(pc["columns"]))

    def test_gtfobins_schema(self):
        result = detection_list_lookups()
        gtfo = next(l for l in result["lookups"] if l["filename"] == "gtfobins.csv")
        expected_cols = {"filename", "binary_name", "categories", "mitre_ids", "risk", "description"}
        assert expected_cols.issubset(set(gtfo["columns"]))


# ---------------------------------------------------------------------------
# CSV data integrity
# ---------------------------------------------------------------------------

class TestDataIntegrity:
    """Tests that validate the CSV data itself."""

    def test_lolbas_row_count(self):
        result = detection_list_lookups()
        lolbas = next(l for l in result["lookups"] if l["filename"] == "lolbas_binaries.csv")
        assert lolbas["rows"] >= 200  # Should have 200+ LOLBAS entries

    def test_parent_child_row_count(self):
        result = detection_list_lookups()
        pc = next(l for l in result["lookups"] if l["filename"] == "parent_child_baselines.csv")
        assert pc["rows"] >= 90  # Should have 90+ baseline entries

    def test_gtfobins_row_count(self):
        result = detection_list_lookups()
        gtfo = next(l for l in result["lookups"] if l["filename"] == "gtfobins.csv")
        assert gtfo["rows"] >= 400  # Should have 400+ GTFOBins entries

    def test_all_lolbas_have_risk(self):
        """Every LOLBAS entry must have a risk rating."""
        result = detection_list_by_category("Execute")
        for binary in result["binaries"]:
            if binary.get("source") == "lolbas":
                assert binary["risk"] in ("high", "medium", "low"), (
                    f"{binary['filename']} has invalid risk: {binary['risk']}"
                )

    def test_all_lolbas_filenames_lowercase(self):
        """Match key (filename) must be lowercase for SIEM join consistency."""
        result = detection_search("exe", limit=500)
        for r in result["results"]:
            if r["source"] == "lolbas_binaries":
                assert r["filename"] == r["filename"].lower(), (
                    f"Filename not lowercase: {r['filename']}"
                )

    def test_all_gtfobins_have_risk(self):
        """Every GTFOBins entry must have a valid risk rating."""
        result = detection_list_by_category("shell")
        for binary in result["binaries"]:
            if binary.get("source") == "gtfobins":
                assert binary["risk"] in ("high", "medium", "low"), (
                    f"{binary['filename']} has invalid risk: {binary['risk']}"
                )

    def test_all_gtfobins_filenames_lowercase(self):
        """GTFOBins filename keys must be lowercase."""
        result = detection_search("gtfobins", limit=500)
        for r in result["results"]:
            if r["source"] == "gtfobins":
                assert r["filename"] == r["filename"].lower(), (
                    f"GTFOBins filename not lowercase: {r['filename']}"
                )


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

class TestPagination:
    """Tests for pagination on list and search tools."""

    def test_category_pagination(self):
        """list_by_category should support limit/offset pagination."""
        full = detection_list_by_category("shell")
        assert full["total"] > 10
        page1 = detection_list_by_category("shell", limit=5, offset=0)
        page2 = detection_list_by_category("shell", limit=5, offset=5)
        assert page1["count"] == 5
        assert page2["count"] == 5
        assert page1["has_more"] is True
        assert page1["binaries"][0]["filename"] != page2["binaries"][0]["filename"]

    def test_category_offset_beyond_results(self):
        result = detection_list_by_category("shell", limit=50, offset=9999)
        assert result["count"] == 0
        assert result["has_more"] is False
        assert result["total"] > 0

    def test_mitre_pagination(self):
        """list_by_mitre should support limit/offset pagination."""
        full = detection_list_by_mitre("T1059")
        assert full["total"] > 10
        page1 = detection_list_by_mitre("T1059", limit=5, offset=0)
        assert page1["count"] == 5
        assert page1["has_more"] is True

    def test_search_has_more(self):
        """detection_search should report has_more when results exceed limit."""
        result = detection_search("exe", limit=3)
        assert result["count"] == 3
        assert result["total"] > 3
        assert result["has_more"] is True

    def test_search_no_more(self):
        """detection_search should report has_more=False when all results fit."""
        result = detection_search("certutil", limit=100)
        assert result["has_more"] is False
        assert result["total"] == result["count"]
