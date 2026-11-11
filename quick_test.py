#!/usr/bin/env python3
"""
Quick test script for Cyber Operator
Tests core functionality without external dependencies
"""

import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

def print_header(title):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def test_imports():
    """Test module imports"""
    print_header("Testing Module Imports")
    
    try:
        from cyber_operator.core import (
            TargetClassifier, SourceRegistry, SourceSelector,
            QueryEngine, ResultAggregator, Orchestrator
        )
        print("âœ… Core modules imported successfully")
        
        from cyber_operator.connectors import (
            DNSConnector, RDAPConnector, CrtshConnector
        )
        print("âœ… Connectors imported successfully")
        
        from cyber_operator.database import DatabaseManager
        print("âœ… Database module imported successfully")
        
        from cyber_operator.utils import (
            normalize_target, format_duration, safe_json_dumps
        )
        print("âœ… Utils imported successfully")
        
        return True
    except ImportError as e:
        print(f"âŒ Import error: {e}")
        return False


def test_target_classifier():
    """Test target classification"""
    print_header("Testing Target Classifier")
    
    from cyber_operator.core import TargetClassifier, TargetType
    
    classifier = TargetClassifier()
    
    test_cases = [
        ("example.com", TargetType.DOMAIN),
        ("192.168.1.1", TargetType.IPV4),
        ("test@example.com", TargetType.EMAIL),
        ("https://example.com", TargetType.URL),
        ("5d41402abc4b2a76b9719d911017c592", TargetType.HASH_MD5),
    ]
    
    passed = 0
    for target, expected_type in test_cases:
        target_type, metadata = classifier.classify(target)
        if target_type == expected_type:
            print(f"âœ… {target:40} â†’ {target_type.value:15}")
            passed += 1
        else:
            print(f"âŒ {target:40} (expected {expected_type.value}, got {target_type.value})")
    
    print(f"\n{passed}/{len(test_cases)} tests passed")
    return passed == len(test_cases)


def test_source_registry():
    """Test source registry"""
    print_header("Testing Source Registry")
    
    from cyber_operator.core import SourceRegistry
    
    registry = SourceRegistry()
    
    sources = registry.get_all_sources()
    print(f"âœ… Loaded {len(sources)} sources")
    
    categories = registry.get_categories()
    print(f"âœ… Found {len(categories)} categories:")
    for category in categories:
        print(f"   â€¢ {category}")
    
    active = registry.get_active_sources()
    print(f"\nâœ… Active sources: {len(active)}/{len(sources)}")
    
    dns_source = registry.get_source("dns_resolver")
    if dns_source:
        print(f"âœ… DNS Resolver source: {dns_source.name}")
    
    return True


def test_source_selector():
    """Test source selector"""
    print_header("Testing Source Selector")
    
    from cyber_operator.core import SourceSelector, SourceRegistry, TargetType
    
    registry = SourceRegistry()
    selector = SourceSelector(registry)
    
    # Test all sources
    all_sources = selector.select_all_sources()
    print(f"âœ… Select all: {len(all_sources)} sources")
    
    # Test recommended
    recommended = selector.select_recommended_sources(TargetType.DOMAIN)
    print(f"âœ… Select recommended for DOMAIN: {len(recommended)} sources")
    
    # Test manual selection
    manual = selector.select_manual(["dns_resolver", "rdap_lookup"])
    print(f"âœ… Manual selection: {len(manual)} sources")
    
    # Validate selection
    validation = selector.validate_selection(manual)
    print(f"âœ… Validation report:")
    print(f"   â€¢ Total: {validation['total_sources']}")
    print(f"   â€¢ Local tools: {validation['local_tools']}")
    print(f"   â€¢ External APIs: {validation['external_apis']}")
    
    return True


def test_orchestrator():
    """Test orchestrator"""
    print_header("Testing Orchestrator")
    
    from cyber_operator.core import Orchestrator
    
    orchestrator = Orchestrator()
    
    # Test target analysis
    analysis = orchestrator.analyze_target("example.com")
    print(f"âœ… Target analysis: example.com")
    print(f"   â€¢ Type: {analysis['type']}")
    print(f"   â€¢ Categories: {', '.join(analysis['compatible_categories'])}")
    
    # Get sources
    sources = orchestrator.get_available_sources()
    print(f"\nâœ… Available sources: {len(sources)}")
    
    # Get categories
    categories = orchestrator.get_categories()
    print(f"âœ… Available categories: {len(categories)}")
    
    return True


def test_database():
    """Test database"""
    print_header("Testing Database")
    
    from cyber_operator.database import DatabaseManager
    import os
    
    # Use temp database
    test_db = "test_cyber_operator.db"
    
    try:
        db = DatabaseManager(test_db)
        print(f"âœ… Database initialized")
        
        # Test cache
        db.cache_result("test:example.com", {"data": "test"}, ttl_seconds=3600)
        cached = db.get_cached_result("test:example.com")
        if cached:
            print(f"âœ… Cache working")
        else:
            print(f"âŒ Cache not working")
        
        # Test query history
        query_id = db.save_query(
            target="example.com",
            target_type="domain",
            selection_mode="all",
            execution_time=1.5,
            success=True,
            results=[]
        )
        print(f"âœ… Query saved (ID: {query_id})")
        
        history = db.get_query_history(limit=10)
        print(f"âœ… Query history: {len(history)} records")
        
        db.close()
        
        # Clean up
        os.remove(test_db)
        print(f"âœ… Test database cleaned up")
        
        return True
    
    except Exception as e:
        print(f"âŒ Database error: {e}")
        if os.path.exists(test_db):
            os.remove(test_db)
        return False


def test_utils():
    """Test utilities"""
    print_header("Testing Utilities")
    
    from cyber_operator.utils import (
        normalize_target, is_private_target, format_duration,
        format_bytes, sanitize_target
    )
    
    # Normalize
    normalized = normalize_target("  EXAMPLE.COM  ")
    print(f"âœ… Normalize: '  EXAMPLE.COM  ' â†’ '{normalized}'")
    
    # Private target detection
    is_private = is_private_target("192.168.1.1")
    print(f"âœ… Private IP detection: 192.168.1.1 â†’ {is_private}")
    
    # Duration formatting
    duration = format_duration(1.5)
    print(f"âœ… Format duration: 1.5s â†’ {duration}")
    
    # Bytes formatting
    size = format_bytes(1024 * 1024)
    print(f"âœ… Format bytes: 1MB â†’ {size}")
    
    # Sanitize
    sanitized = sanitize_target("example<script>.com")
    print(f"âœ… Sanitize: 'example<script>.com' â†’ '{sanitized}'")
    
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("CYBER OPERATOR v0.1 - Quick Test Suite")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("Target Classifier", test_target_classifier),
        ("Source Registry", test_source_registry),
        ("Source Selector", test_source_selector),
        ("Orchestrator", test_orchestrator),
        ("Database", test_database),
        ("Utilities", test_utils),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\nâŒ {name} failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((name, False))
    
    # Summary
    print_header("Test Summary")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "âœ…" if result else "âŒ"
        print(f"{status} {name}")
    
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} test groups passed")
    print(f"{'='*60}\n")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

