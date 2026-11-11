import json
import time
from types import SimpleNamespace

from cyber_operator.core import (
    IntelligenceQuery,
    Orchestrator,
    SelectionMode,
)
from cyber_operator.database import DatabaseManager


class ControlledConnectors:
    def __init__(self):
        self.calls = []
        self.fail = set()

    def _result(self, connector, method, target):
        self.calls.append((connector, method, target))
        if connector in self.fail:
            raise RuntimeError(f"{connector} controlled failure")
        return {
            "success": True,
            "target": target,
            "records": ["record-a", "record-a", "record-b"],
        }

    def dns_domain(self, domain):
        return self._result("dns_resolver", "resolve_domain", domain)

    def dns_reverse(self, address):
        return self._result("dns_resolver", "reverse_dns", address)

    def rdap_domain(self, domain):
        return self._result("rdap_lookup", "lookup_domain", domain)

    def rdap_ip(self, address):
        return self._result("rdap_lookup", "lookup_ip", address)

    def crtsh(self, domain, include_subdomains=True):
        return self._result("crtsh", "search_domain", domain)


def make_orchestrator(connectors=None, cache_ttl=3600):
    db = DatabaseManager(":memory:")
    orchestrator = Orchestrator(
        database_manager=db,
        max_concurrent=3,
        connectors=connectors,
    )
    orchestrator.engine.cache_ttl = cache_ttl
    return orchestrator, db


def configured_connectors(controlled):
    return {
        "dns_resolver": SimpleNamespace(
            resolve_domain=controlled.dns_domain,
            reverse_dns=controlled.dns_reverse,
        ),
        "rdap_lookup": SimpleNamespace(
            lookup_domain=controlled.rdap_domain,
            lookup_ip=controlled.rdap_ip,
        ),
        "crtsh": SimpleNamespace(search_domain=controlled.crtsh),
    }


def run_manual(orchestrator, target, source_id):
    return orchestrator.execute_query(IntelligenceQuery(
        target=target,
        selection_mode=SelectionMode.MANUAL,
        source_ids=[source_id],
    ))


def test_dns_connector_is_dispatched_through_orchestrator():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = run_manual(orchestrator, "example.com", "dns_resolver")

    assert result["success"]
    assert controlled.calls == [("dns_resolver", "resolve_domain", "example.com")]
    assert result["findings"]["sources"]["dns_resolver"]["data"]["records"]


def test_rdap_connector_is_dispatched_through_orchestrator():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = run_manual(orchestrator, "example.com", "rdap_lookup")

    assert result["success"]
    assert controlled.calls == [("rdap_lookup", "lookup_domain", "example.com")]


def test_crtsh_connector_is_dispatched_through_orchestrator():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = run_manual(orchestrator, "example.com", "crtsh")

    assert result["success"]
    assert controlled.calls == [("crtsh", "search_domain", "example.com")]


def test_all_selects_only_active_compatible_sources():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = orchestrator.execute_query(IntelligenceQuery(
        "example.com", SelectionMode.ALL
    ))

    expected_ids = {
        source.id for source in orchestrator.registry.get_active_sources()
        if "domain" in source.supported_targets
    }
    assert set(result["sources"]["list"]) == expected_ids
    assert {call[0] for call in controlled.calls} == {
        "dns_resolver", "rdap_lookup", "crtsh"
    }
    assert result["findings"]["sources"]["virustotal"]["execution_status"] == "not_implemented"


def test_recommended_selects_implemented_compatible_sources():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = orchestrator.execute_query(IntelligenceQuery(
        "example.com", SelectionMode.RECOMMENDED
    ))

    assert set(result["sources"]["list"]) == {
        "dns_resolver", "rdap_lookup", "crtsh"
    }
    assert {call[0] for call in controlled.calls} == {
        "dns_resolver", "rdap_lookup", "crtsh"
    }


def test_manual_selection_executes_only_selected_source():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = orchestrator.execute_query(IntelligenceQuery(
        "example.com",
        SelectionMode.MANUAL,
        source_ids=["crtsh", "dns_resolver"],
    ))

    assert set(result["sources"]["list"]) == {"crtsh", "dns_resolver"}
    assert {call[0] for call in controlled.calls} == {"crtsh", "dns_resolver"}


def test_manual_incompatible_source_is_not_queried():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = run_manual(orchestrator, "e3b0c44298fc1c149afbf4c8996fb924", "crtsh")

    assert controlled.calls == []
    assert result["sources"]["list"] == []
    assert result["sources"]["skipped"][0]["availability_status"] == "not_compatible"


def test_one_connector_failure_does_not_stop_others():
    controlled = ControlledConnectors()
    controlled.fail.add("dns_resolver")
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = orchestrator.execute_query(IntelligenceQuery(
        "example.com", SelectionMode.RECOMMENDED
    ))

    assert result["status"] == "partial"
    assert result["findings"]["sources"]["dns_resolver"]["execution_status"] == "error"
    assert result["findings"]["sources"]["rdap_lookup"]["success"]
    assert result["findings"]["sources"]["crtsh"]["success"]


def test_source_timeout_is_reported_without_suppressing_other_sources():
    controlled = ControlledConnectors()
    controlled.dns_domain = lambda domain: (
        time.sleep(0.1) or controlled._result("dns_resolver", "resolve_domain", domain)
    )
    connectors = configured_connectors(controlled)
    orchestrator, _ = make_orchestrator(connectors)
    orchestrator.registry.get_source("dns_resolver").timeout = 0.01

    result = orchestrator.execute_query(IntelligenceQuery(
        "example.com", SelectionMode.RECOMMENDED
    ))

    assert result["findings"]["sources"]["dns_resolver"]["execution_status"] == "timeout"
    assert result["findings"]["sources"]["rdap_lookup"]["success"]
    assert result["findings"]["sources"]["crtsh"]["success"]


def test_new_query_does_not_include_prior_findings_and_has_unique_id():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    first = run_manual(orchestrator, "first.example", "dns_resolver")
    second = run_manual(orchestrator, "second.example", "dns_resolver")

    assert first["query_id"] != second["query_id"]
    assert second["findings"]["target"] == "second.example"
    assert second["findings"]["sources"]["dns_resolver"]["data"]["target"] == "second.example"
    assert len(second["findings"]["sources"]) == 1


def test_query_and_source_results_persist_to_sqlite():
    controlled = ControlledConnectors()
    orchestrator, db = make_orchestrator(configured_connectors(controlled))

    result = run_manual(orchestrator, "example.com", "dns_resolver")
    history = db.get_query_history(limit=5)

    assert len(history) == 1
    assert history[0]["query_id"] == result["query_id"]
    assert json.loads(history[0]["selected_sources"]) == ["dns_resolver"]
    assert json.loads(history[0]["result_data"])["query"]["target"] == "example.com"
    row = db.connection.execute(
        "SELECT source_id, success, result_data FROM query_results"
    ).fetchone()
    assert row["source_id"] == "dns_resolver"
    assert row["success"] == 1
    assert json.loads(row["result_data"])["data"]["records"]


def test_cache_is_used_until_ttl_expires():
    controlled = ControlledConnectors()
    orchestrator, db = make_orchestrator(configured_connectors(controlled), cache_ttl=1)

    first = run_manual(orchestrator, "example.com", "dns_resolver")
    second = run_manual(orchestrator, "example.com", "dns_resolver")

    assert first["success"] and second["success"]
    assert len(controlled.calls) == 1
    assert second["findings"]["sources"]["dns_resolver"]["cached"]

    db.connection.execute("UPDATE cache SET expires_at = '2000-01-01 00:00:00'")
    db.connection.commit()
    third = run_manual(orchestrator, "example.com", "dns_resolver")
    assert third["success"]
    assert len(controlled.calls) == 2
    assert not third["findings"]["sources"]["dns_resolver"]["cached"]


def test_private_target_never_reaches_public_connectors():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = orchestrator.execute_query(IntelligenceQuery(
        "192.168.1.10", SelectionMode.ALL
    ))

    assert controlled.calls == []
    assert "dns_resolver" in result["sources"]["list"]
    assert "rdap_lookup" in result["sources"]["list"]
    assert result["findings"]["sources"]["dns_resolver"]["execution_status"] == "blocked_private_target"
    assert result["findings"]["sources"]["rdap_lookup"]["execution_status"] == "blocked_private_target"


def test_crtsh_is_not_selected_for_url_with_ip_host():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = orchestrator.execute_query(IntelligenceQuery(
        "https://8.8.8.8/path", SelectionMode.ALL
    ))

    assert "crtsh" not in result["sources"]["list"]
    assert not any(call[0] == "crtsh" for call in controlled.calls)


def test_normalized_values_dedupe_without_mutating_original_data():
    controlled = ControlledConnectors()
    orchestrator, _ = make_orchestrator(configured_connectors(controlled))

    result = run_manual(orchestrator, "example.com", "dns_resolver")
    source = result["findings"]["sources"]["dns_resolver"]

    assert source["data"]["records"] == ["record-a", "record-a", "record-b"]
    assert source["normalized_data"]["records"] == ["record-a", "record-b"]
