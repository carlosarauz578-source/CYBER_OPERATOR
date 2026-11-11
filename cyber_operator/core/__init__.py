"""Core module initialization"""

from .target_classifier import TargetClassifier, TargetType
from .source_registry import SourceRegistry, Source, SourceType
from .source_selector import SourceSelector, SelectionMode
from .query_engine import QueryEngine, QueryResult
from .result_aggregator import ResultAggregator
from .orchestrator import Orchestrator, IntelligenceQuery

__all__ = [
    'TargetClassifier',
    'TargetType',
    'SourceRegistry',
    'Source',
    'SourceType',
    'SourceSelector',
    'SelectionMode',
    'QueryEngine',
    'QueryResult',
    'ResultAggregator',
    'Orchestrator',
    'IntelligenceQuery'
]
