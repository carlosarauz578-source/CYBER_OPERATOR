"""
Orchestrator Module
Coordinates all components: classification, selection, execution, and aggregation
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import os
import uuid

from cyber_operator.config import Config
from cyber_operator.database import DatabaseManager
from cyber_operator.utils.common import is_private_target
from .target_classifier import TargetClassifier, TargetType
from .source_registry import SourceRegistry
from .source_selector import SourceSelector, SelectionMode
from .query_engine import QueryEngine
from .result_aggregator import ResultAggregator


@dataclass
class IntelligenceQuery:
    """Represents an intelligence query"""
    target: str
    selection_mode: SelectionMode
    categories: List[str] = None
    source_ids: List[str] = None
    timestamp: datetime = None
    query_id: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.query_id is None:
            self.query_id = str(uuid.uuid4())


class Orchestrator:
    """Orchestrates the entire intelligence gathering workflow"""
    
    def __init__(self, database_manager=None, max_concurrent: int = None,
                 connectors=None):
        self.classifier = TargetClassifier()
        self.registry = SourceRegistry()
        self.selector = SourceSelector(
            self.registry,
            recommended_source_ids=QueryEngine.IMPLEMENTED_SOURCE_IDS,
        )
        self.database_manager = database_manager or DatabaseManager(Config.DATABASE_PATH)
        self.engine = QueryEngine(
            max_concurrent=max_concurrent or Config.MAX_CONCURRENT_QUERIES,
            database_manager=self.database_manager,
            cache_ttl=Config.DATABASE_CACHE_TTL,
            connectors=connectors,
        )
        self.aggregator = ResultAggregator()
        
        self.last_query: Optional[IntelligenceQuery] = None
        self.last_results: Optional[Dict] = None
    
    def analyze_target(self, target: str) -> Dict:
        """
        Analyze and classify a target.
        
        Args:
            target: The target to analyze
            
        Returns:
            Analysis dictionary with type and metadata
        """
        target_type, metadata = self.classifier.classify(target)
        compatible_categories = self.classifier.get_compatible_categories(target_type)
        
        return {
            "target": target,
            "type": target_type.value,
            "metadata": metadata,
            "compatible_categories": compatible_categories
        }
    
    def execute_query(self, query: IntelligenceQuery) -> Dict:
        """
        Execute a complete intelligence query.
        
        Args:
            query: IntelligenceQuery object
            
        Returns:
            Complete results dictionary
        """
        self.last_query = query
        
        # Step 1: Classify target
        target_type, metadata = self.classifier.classify(query.target)
        
        # Step 2: Select sources
        sources = []
        skipped_sources = []
        try:
            sources = self.selector.select_by_mode(
                mode=query.selection_mode,
                target_type=target_type,
                categories=query.categories,
                source_ids=query.source_ids
            )
            sources = [
                source for source in sources
                if self.engine.is_compatible(source, query.target, target_type.value)
            ]
        except ValueError as exc:
            skipped_sources.append({
                "source_id": None,
                "availability_status": "not_selected",
                "execution_status": "not_run",
                "error": str(exc),
            })

        private_target = is_private_target(query.target)
        if query.selection_mode == SelectionMode.MANUAL:
            selected_ids = list(dict.fromkeys(query.source_ids or []))
            executable_ids = {source.id for source in sources}
            for source_id in selected_ids:
                source = self.registry.get_source(source_id)
                if source_id in executable_ids:
                    continue
                if source is None:
                    reason = "unknown_source"
                elif not source.active:
                    reason = "inactive"
                elif private_target:
                    reason = "private_target"
                else:
                    reason = "not_compatible"
                skipped_sources.append({
                    "source_id": source_id,
                    "source_name": source.name if source else source_id,
                    "availability_status": reason,
                    "execution_status": "not_run",
                    "error": None,
                })

        # Step 3: Execute queries
        results = self.engine.execute_query(
            query.target, sources, private_target=private_target
        )
        
        # Step 4: Aggregate results
        aggregated = self.aggregator.aggregate(
            query.target, results=results, query_id=query.query_id
        )
        
        # Step 5: Add metadata
        execution_summary = self.engine.get_summary()
        query_succeeded = execution_summary["successful"] > 0
        failed = execution_summary["failed"] > 0 or bool(skipped_sources)
        final_result = {
            "success": query_succeeded,
            "status": (
                "partial" if query_succeeded and failed
                else "successful" if query_succeeded
                else "failed"
            ),
            "query_id": query.query_id,
            "query": {
                "target": query.target,
                "target_type": target_type.value,
                "selection_mode": query.selection_mode.value,
                "timestamp": query.timestamp.isoformat()
            },
            "sources": {
                "selected": len(sources),
                "list": [s.id for s in sources],
                "skipped": skipped_sources,
            },
            "execution_summary": execution_summary,
            "findings": aggregated
        }
        if not query_succeeded:
            final_result["error"] = "No selected source query succeeded"

        try:
            self.database_manager.save_query(
                target=query.target,
                target_type=target_type.value,
                selection_mode=query.selection_mode.value,
                execution_time=execution_summary["total_execution_time"],
                success=query_succeeded,
                results=final_result,
                query_id=query.query_id,
                selected_sources=[source.id for source in sources],
                status=final_result["status"],
            )
        except Exception as exc:
            final_result["persistence_error"] = str(exc)
        
        self.last_results = final_result
        return final_result
    
    def execute_simple_query(self, target: str, 
                            mode: str = "recommended") -> Dict:
        """
        Execute a query with simplified parameters.
        
        Args:
            target: The search target
            mode: Selection mode ("all", "recommended", "manual")
            
        Returns:
            Results dictionary
        """
        selection_mode = SelectionMode[mode.upper()]
        target_type, _ = self.classifier.classify(target)
        
        query = IntelligenceQuery(
            target=target,
            selection_mode=selection_mode
        )
        
        return self.execute_query(query)
    
    def get_available_sources(self) -> List[Dict]:
        """Get list of all available sources with details"""
        sources = []
        for source in self.registry.get_all_sources():
            sources.append({
                "id": source.id,
                "name": source.name,
                "description": source.description,
                "category": source.category,
                "type": source.source_type.value,
                "active": source.active,
                "requires_credentials": source.requires_credentials,
                "credentials_status": (
                    "available"
                    if all(
                        os.getenv(key)
                        for key in source.credentials_keys
                    )
                    else "missing_credentials"
                    if source.requires_credentials
                    else "not_required"
                ),
                "supported_targets": source.supported_targets,
                "priority": source.priority,
                "availability": self.engine.get_availability(source),
            })
        return sources
    
    def get_categories(self) -> List[str]:
        """Get all available categories"""
        return self.registry.get_categories()
    
    def enable_source(self, source_id: str) -> bool:
        """Enable a source"""
        return self.registry.enable_source(source_id)
    
    def disable_source(self, source_id: str) -> bool:
        """Disable a source"""
        return self.registry.disable_source(source_id)
    
    def get_last_results(self) -> Optional[Dict]:
        """Get results from the last executed query"""
        return self.last_results
    
    def get_last_query(self) -> Optional[IntelligenceQuery]:
        """Get the last executed query"""
        return self.last_query
