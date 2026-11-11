"""Executes registered intelligence sources with bounded concurrency."""

import asyncio
import hashlib
import ipaddress
import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from cyber_operator.connectors import DNSConnector, RDAPConnector, CrtshConnector
from .source_registry import Source

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    """Outcome of one source query."""

    source_id: str
    source_name: str
    target: str
    success: bool = False
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: Optional[datetime] = None
    execution_time: float = 0.0
    availability_status: str = "available"
    execution_status: str = "pending"
    cached: bool = False
    persistence_error: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class QueryEngine:
    """Dispatches supported sources and reports unimplemented entries explicitly."""

    IMPLEMENTED_SOURCE_IDS = {"dns_resolver", "rdap_lookup", "crtsh"}

    def __init__(self, max_concurrent: int = 5, database_manager=None,
                 cache_ttl: int = 3600, connectors: Optional[Dict[str, Any]] = None):
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self.max_concurrent = max_concurrent
        self.database_manager = database_manager
        self.cache_ttl = cache_ttl
        self.connectors = connectors if connectors is not None else {
            "dns_resolver": DNSConnector(),
            "rdap_lookup": RDAPConnector(timeout=20),
            "crtsh": CrtshConnector(timeout=15),
        }
        self.results: List[QueryResult] = []

    def get_availability(self, source: Source) -> str:
        if source.id not in self.IMPLEMENTED_SOURCE_IDS:
            return "not_implemented"
        if source.requires_credentials:
            import os
            if not all(os.getenv(key) for key in source.credentials_keys):
                return "missing_credentials"
        return "available"

    def execute_query(self, target: str, sources: List[Source],
                      private_target: bool = False) -> List[QueryResult]:
        """Run each selected source independently and return one status per source."""
        self.results = asyncio.run(self._run_queries(target, sources, private_target))
        return self.results

    async def _run_queries(self, target: str, sources: List[Source],
                           private_target: bool) -> List[QueryResult]:
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [
            self._query_source(semaphore, target, source, private_target)
            for source in sources
        ]
        return await asyncio.gather(*tasks)

    async def _query_source(self, semaphore: asyncio.Semaphore, target: str,
                            source: Source, private_target: bool) -> QueryResult:
        result = QueryResult(
            source_id=source.id,
            source_name=source.name,
            target=target,
            availability_status=self.get_availability(source),
        )
        if result.availability_status != "available":
            result.execution_status = result.availability_status
            return result
        if private_target and source.id in self.IMPLEMENTED_SOURCE_IDS:
            result.availability_status = "available"
            result.execution_status = "blocked_private_target"
            result.error = (
                "Query blocked for a private or internal target because the "
                "configured resolver may use public infrastructure"
            )
            return result

        cache_key = self._cache_key(source.id, target)
        if self.database_manager is not None:
            try:
                cached = self.database_manager.get_cached_result(cache_key)
            except (sqlite3.Error, json.JSONDecodeError) as exc:
                result.persistence_error = f"Cache read failed: {exc}"
                logger.error(result.persistence_error)
                cached = None
            if cached is not None:
                result.success = True
                result.data = cached
                result.cached = True
                result.execution_status = "cached"
                self._update_source_status(result)
                return result

        start = time.monotonic()
        try:
            async with semaphore:
                loop = asyncio.get_running_loop()
                future = loop.run_in_executor(
                    None, self._execute_source_query, target, source
                )
                data = await asyncio.wait_for(future, timeout=source.timeout)

            result.data = data
            result.success = data.get("success") is True and not bool(data.get("error"))
            if result.success:
                result.execution_status = (
                    "successful" if data.get("success", True) else "successful_empty"
                )
                if self.database_manager is not None:
                    try:
                        self.database_manager.cache_result(
                            cache_key, data, source_id=source.id,
                            ttl_seconds=self.cache_ttl
                        )
                    except sqlite3.Error as exc:
                        result.persistence_error = f"Cache write failed: {exc}"
                        logger.error(result.persistence_error)
            else:
                result.error = str(
                    data.get("error") or "Connector did not confirm a successful response"
                )
                result.execution_status = self._error_status(result.error)
        except asyncio.TimeoutError:
            result.error = f"Timeout after {source.timeout}s"
            result.execution_status = "timeout"
        except Exception as exc:
            logger.exception("Source query failed for %s", source.id)
            result.error = str(exc)
            result.execution_status = self._error_status(result.error)
        finally:
            result.execution_time = time.monotonic() - start

        self._update_source_status(result)
        return result

    def _update_source_status(self, result: QueryResult) -> None:
        if self.database_manager is None:
            return
        try:
            self.database_manager.update_source_status(
                result.source_id, result.success, result.execution_time, result.error
            )
        except sqlite3.Error as exc:
            result.persistence_error = f"Source status update failed: {exc}"
            logger.error(result.persistence_error)

    @staticmethod
    def _error_status(error: str) -> str:
        lowered = error.lower()
        if "timeout" in lowered or "timed out" in lowered:
            return "timeout"
        if "server error" in lowered or any(
            f"{status} " in lowered for status in ("500", "502", "503", "504")
        ):
            return "service_error"
        if "connection" in lowered or "network" in lowered:
            return "connection_error"
        return "error"

    @staticmethod
    def _cache_key(source_id: str, target: str) -> str:
        normalized_target = target.strip().lower()
        digest = hashlib.sha256(normalized_target.encode("utf-8")).hexdigest()
        return f"{source_id}:{digest}"

    def _execute_source_query(self, target: str, source: Source) -> Dict[str, Any]:
        """Invoke a real connector method; never synthesize source data."""
        host = self._target_host(target)
        if source.id == "dns_resolver":
            if self._is_ip(host):
                return self.connectors[source.id].reverse_dns(host)
            return self.connectors[source.id].resolve_domain(host)
        if source.id == "rdap_lookup":
            if self._is_ip(host):
                return self.connectors[source.id].lookup_ip(host)
            return self.connectors[source.id].lookup_domain(host)
        if source.id == "crtsh":
            return self.connectors[source.id].search_domain(
                host, include_subdomains=False
            )
        raise NotImplementedError(f"Query connector not implemented for '{source.id}'")

    @staticmethod
    def _target_host(target: str) -> str:
        if "://" in target:
            host = urlsplit(target).hostname
            if not host:
                raise ValueError("URL target does not contain a hostname")
            return host
        return target.strip().strip("[]")

    def is_compatible(self, source: Source, target: str, target_type: str) -> bool:
        if target_type not in source.supported_targets:
            return False
        if target_type == "url":
            try:
                host = self._target_host(target)
            except ValueError:
                return False
            if source.id == "crtsh" and self._is_ip(host):
                return False
        return True

    @staticmethod
    def _is_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def get_results(self) -> List[QueryResult]:
        return self.results

    def get_successful_results(self) -> List[QueryResult]:
        return [result for result in self.results if result.success]

    def get_failed_results(self) -> List[QueryResult]:
        return [result for result in self.results if not result.success]

    def get_results_by_source(self, source_id: str) -> Optional[QueryResult]:
        return next((result for result in self.results if result.source_id == source_id), None)

    def get_summary(self) -> Dict[str, Any]:
        total = len(self.results)
        successful = len(self.get_successful_results())
        total_time = sum(result.execution_time for result in self.results)
        return {
            "total_queries": total,
            "successful": successful,
            "failed": total - successful,
            "success_rate": successful / total * 100 if total else 0,
            "total_execution_time": total_time,
            "average_time_per_query": total_time / total if total else 0,
        }
