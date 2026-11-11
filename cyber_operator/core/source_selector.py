"""
Source Selector Module
Handles source selection based on categories, recommendations, or manual selection
"""

from typing import List, Set
from enum import Enum
from .source_registry import Source, SourceRegistry, SourceType
from .target_classifier import TargetType


class SelectionMode(Enum):
    """Source selection modes"""
    ALL = "all"
    RECOMMENDED = "recommended"
    MANUAL = "manual"


class SourceSelector:
    """Selects sources based on different modes"""
    
    def __init__(self, registry: SourceRegistry,
                 recommended_source_ids: Set[str] = None):
        self.registry = registry
        self.recommended_source_ids = recommended_source_ids
    
    def select_all_sources(self, target_type: TargetType = None,
                           categories: List[str] = None) -> List[Source]:
        """
        Select all active sources.
        
        Args:
            target_type: Optional target type to filter by
            
        Returns:
            List of selected sources
        """
        sources = self.registry.get_active_sources()
        
        if target_type:
            sources = [s for s in sources 
                      if target_type.value in s.supported_targets]
        if categories:
            sources = [source for source in sources if source.category in categories]
        
        # Sort by priority (descending)
        return sorted(sources, key=lambda s: s.priority, reverse=True)
    
    def select_recommended_sources(self, target_type: TargetType,
                                   categories: List[str] = None) -> List[Source]:
        """
        Select recommended sources for a target type.
        
        Args:
            target_type: The target type
            
        Returns:
            List of recommended sources sorted by priority
        """
        # Filter by compatibility and priority
        sources = self.registry.get_sources_for_target(target_type.value)
        if self.recommended_source_ids is not None:
            sources = [
                source for source in sources
                if source.id in self.recommended_source_ids
            ]
        if categories:
            sources = [source for source in sources if source.category in categories]
        
        # Exclude sources requiring credentials unless they're high priority
        recommended = []
        for source in sources:
            if source.requires_credentials and source.priority < 7:
                continue  # Skip low-priority sources requiring credentials
            recommended.append(source)
        
        # Sort by priority and filter top sources
        recommended = sorted(recommended, key=lambda s: s.priority, reverse=True)
        return recommended[:5]  # Return top 5 recommended
    
    def select_by_categories(self, categories: List[str]) -> List[Source]:
        """
        Select sources by categories.
        
        Args:
            categories: List of category names
            
        Returns:
            List of sources in the specified categories
        """
        sources = []
        for category in categories:
            sources.extend(self.registry.get_sources_by_category(category))
        
        # Remove duplicates and sort by priority
        unique_sources = {s.id: s for s in sources}
        return sorted(unique_sources.values(), key=lambda s: s.priority, reverse=True)
    
    def select_manual(self, source_ids: List[str],
                      target_type: TargetType = None,
                      categories: List[str] = None) -> List[Source]:
        """
        Select sources by specific IDs.
        
        Args:
            source_ids: List of source IDs to select
            
        Returns:
            List of selected sources
        """
        sources = []
        for source_id in source_ids:
            source = self.registry.get_source(source_id)
            if (
                source
                and source.active
                and (not categories or source.category in categories)
                and (
                    target_type is None
                    or target_type.value in source.supported_targets
                )
                and source not in sources
            ):
                sources.append(source)
        
        return sorted(sources, key=lambda s: s.priority, reverse=True)
    
    def select_by_mode(self, mode: SelectionMode, 
                      target_type: TargetType = None,
                      categories: List[str] = None,
                      source_ids: List[str] = None) -> List[Source]:
        """
        Select sources based on selection mode.
        
        Args:
            mode: Selection mode
            target_type: Target type (required for RECOMMENDED mode)
            categories: Categories (required for CATEGORIES mode)
            source_ids: Source IDs (required for MANUAL mode)
            
        Returns:
            List of selected sources
        """
        if mode == SelectionMode.ALL:
            return self.select_all_sources(target_type, categories)
        elif mode == SelectionMode.RECOMMENDED:
            if not target_type:
                raise ValueError("target_type required for RECOMMENDED mode")
            return self.select_recommended_sources(target_type, categories)
        elif mode == SelectionMode.MANUAL:
            if not source_ids:
                raise ValueError("source_ids required for MANUAL mode")
            return self.select_manual(source_ids, target_type, categories)
        else:
            return []
    
    def get_source_capabilities(self, source: Source) -> dict:
        """
        Get detailed capabilities of a source.
        
        Args:
            source: The source
            
        Returns:
            Dictionary with source capabilities
        """
        return {
            "id": source.id,
            "name": source.name,
            "description": source.description,
            "type": source.source_type.value,
            "category": source.category,
            "requires_credentials": source.requires_credentials,
            "credentials": source.credentials_keys,
            "supported_targets": source.supported_targets,
            "priority": source.priority,
            "timeout": source.timeout,
            "rate_limit": source.rate_limit,
            "active": source.active
        }
    
    def validate_selection(self, sources: List[Source]) -> dict:
        """
        Validate a selection of sources and provide analysis.
        
        Args:
            sources: List of selected sources
            
        Returns:
            Validation report
        """
        report = {
            "total_sources": len(sources),
            "local_tools": 0,
            "external_apis": 0,
            "databases": 0,
            "requires_credentials": [],
            "coverage": set()
        }
        
        for source in sources:
            if source.source_type == SourceType.LOCAL_TOOL:
                report["local_tools"] += 1
            elif source.source_type == SourceType.EXTERNAL_API:
                report["external_apis"] += 1
            elif source.source_type == SourceType.DATABASE:
                report["databases"] += 1
            
            if source.requires_credentials:
                report["requires_credentials"].append({
                    "source": source.name,
                    "keys": source.credentials_keys
                })
            
            report["coverage"].update(source.supported_targets)
        
        report["coverage"] = list(report["coverage"])
        return report
