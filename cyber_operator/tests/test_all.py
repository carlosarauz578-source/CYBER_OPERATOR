"""
Test suite for Cyber Operator
"""

import unittest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cyber_operator.core import (
    TargetClassifier, TargetType, SourceRegistry,
    SourceSelector, SelectionMode, Orchestrator, IntelligenceQuery
)
from cyber_operator.utils import (
    normalize_target, is_private_target, format_bytes, format_duration
)


class TestTargetClassifier(unittest.TestCase):
    """Test target classification"""
    
    def setUp(self):
        self.classifier = TargetClassifier()
    
    def test_domain_classification(self):
        """Test domain classification"""
        target_type, metadata = self.classifier.classify("example.com")
        self.assertEqual(target_type, TargetType.DOMAIN)
    
    def test_ipv4_classification(self):
        """Test IPv4 classification"""
        target_type, metadata = self.classifier.classify("192.168.1.1")
        self.assertEqual(target_type, TargetType.IPV4)
    
    def test_email_classification(self):
        """Test email classification"""
        target_type, metadata = self.classifier.classify("test@example.com")
        self.assertEqual(target_type, TargetType.EMAIL)
    
    def test_hash_classification(self):
        """Test hash classification"""
        # SHA256
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        target_type, metadata = self.classifier.classify(sha256_hash)
        self.assertEqual(target_type, TargetType.HASH_SHA256)
        
        # MD5
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        target_type, metadata = self.classifier.classify(md5_hash)
        self.assertEqual(target_type, TargetType.HASH_MD5)
    
    def test_url_classification(self):
        """Test URL classification"""
        target_type, metadata = self.classifier.classify("https://example.com/path")
        self.assertEqual(target_type, TargetType.URL)


class TestSourceRegistry(unittest.TestCase):
    """Test source registry"""
    
    def setUp(self):
        self.registry = SourceRegistry()
    
    def test_registry_initialization(self):
        """Test that registry initializes with default sources"""
        sources = self.registry.get_all_sources()
        self.assertGreater(len(sources), 0)
    
    def test_get_active_sources(self):
        """Test getting active sources"""
        active_sources = self.registry.get_active_sources()
        self.assertGreater(len(active_sources), 0)
    
    def test_get_sources_by_category(self):
        """Test getting sources by category"""
        categories = self.registry.get_categories()
        self.assertGreater(len(categories), 0)
        
        # Get sources for first category
        sources = self.registry.get_sources_by_category(categories[0])
        self.assertGreater(len(sources), 0)
    
    def test_enable_disable_source(self):
        """Test enabling and disabling sources"""
        dns_source = self.registry.get_source("dns_resolver")
        self.assertIsNotNone(dns_source)
        
        # Disable
        result = self.registry.disable_source("dns_resolver")
        self.assertTrue(result)
        self.assertFalse(dns_source.active)
        
        # Enable
        result = self.registry.enable_source("dns_resolver")
        self.assertTrue(result)
        self.assertTrue(dns_source.active)


class TestSourceSelector(unittest.TestCase):
    """Test source selector"""
    
    def setUp(self):
        self.registry = SourceRegistry()
        self.selector = SourceSelector(self.registry)
    
    def test_select_all_sources(self):
        """Test selecting all sources"""
        sources = self.selector.select_all_sources()
        self.assertGreater(len(sources), 0)
    
    def test_select_recommended(self):
        """Test selecting recommended sources"""
        sources = self.selector.select_recommended_sources(TargetType.DOMAIN)
        self.assertGreater(len(sources), 0)
        self.assertLessEqual(len(sources), 5)
    
    def test_select_by_categories(self):
        """Test selecting by categories"""
        sources = self.selector.select_by_categories(["OSINT / Cyber Intelligence"])
        self.assertGreater(len(sources), 0)
    
    def test_select_manual(self):
        """Test manual source selection"""
        sources = self.selector.select_manual(["dns_resolver", "rdap_lookup"])
        self.assertEqual(len(sources), 2)


class TestOrchestrator(unittest.TestCase):
    """Test orchestrator"""
    
    def setUp(self):
        self.orchestrator = Orchestrator()
    
    def test_analyze_target(self):
        """Test target analysis"""
        analysis = self.orchestrator.analyze_target("example.com")
        self.assertEqual(analysis['type'], 'domain')
        self.assertGreater(len(analysis['compatible_categories']), 0)
    
    def test_get_available_sources(self):
        """Test getting available sources"""
        sources = self.orchestrator.get_available_sources()
        self.assertGreater(len(sources), 0)
    
    def test_get_categories(self):
        """Test getting categories"""
        categories = self.orchestrator.get_categories()
        self.assertGreater(len(categories), 0)
    
    def test_enable_disable_source(self):
        """Test enabling/disabling sources"""
        result = self.orchestrator.disable_source("dns_resolver")
        self.assertTrue(result)
        
        result = self.orchestrator.enable_source("dns_resolver")
        self.assertTrue(result)

    def test_unimplemented_sources_are_reported_as_failures(self):
        """Queries without a connector must not appear successful."""
        query = IntelligenceQuery(
            target="example.com",
            selection_mode=SelectionMode.MANUAL,
            source_ids=["whois"]
        )
        result = self.orchestrator.execute_query(query)

        self.assertFalse(result["success"])
        self.assertEqual(result["execution_summary"]["successful"], 0)
        self.assertEqual(result["execution_summary"]["failed"], 1)
        self.assertEqual(
            result["findings"]["sources"]["whois"]["execution_status"],
            "not_implemented"
        )


class TestUtilities(unittest.TestCase):
    """Test utility functions"""
    
    def test_normalize_target(self):
        """Test target normalization"""
        normalized = normalize_target("  EXAMPLE.COM  ")
        self.assertEqual(normalized, "example.com")
    
    def test_is_private_target(self):
        """Test private target detection"""
        self.assertTrue(is_private_target("192.168.1.1"))
        self.assertTrue(is_private_target("10.0.0.1"))
        self.assertFalse(is_private_target("8.8.8.8"))
        self.assertFalse(is_private_target("example.com"))
    
    def test_format_bytes(self):
        """Test bytes formatting"""
        self.assertIn("B", format_bytes(512))
        self.assertIn("KB", format_bytes(1024 * 10))
        self.assertIn("MB", format_bytes(1024 * 1024 * 5))
    
    def test_format_duration(self):
        """Test duration formatting"""
        self.assertIn("ms", format_duration(0.5))
        self.assertIn("s", format_duration(5))
        self.assertIn("m", format_duration(120))


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestTargetClassifier))
    suite.addTests(loader.loadTestsFromTestCase(TestSourceRegistry))
    suite.addTests(loader.loadTestsFromTestCase(TestSourceSelector))
    suite.addTests(loader.loadTestsFromTestCase(TestOrchestrator))
    suite.addTests(loader.loadTestsFromTestCase(TestUtilities))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
