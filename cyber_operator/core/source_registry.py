"""
Source Registry Module
Manages and registers all available data sources
"""

from typing import Dict, List, Optional
from enum import Enum
from dataclasses import dataclass


class SourceType(Enum):
    """Type of data source"""
    EXTERNAL_API = "external_api"
    LOCAL_TOOL = "local_tool"
    DATABASE = "database"


@dataclass
class Source:
    """Represents a data source"""
    id: str
    name: str
    description: str
    source_type: SourceType
    category: str
    requires_credentials: bool = False
    credentials_keys: List[str] = None
    supported_targets: List[str] = None
    active: bool = True
    priority: int = 5  # 1-10, higher is more preferred
    timeout: int = 30
    rate_limit: int = 100  # requests per minute
    
    def __post_init__(self):
        if self.credentials_keys is None:
            self.credentials_keys = []
        if self.supported_targets is None:
            self.supported_targets = []


class SourceRegistry:
    """Registry for managing all data sources"""
    
    def __init__(self):
        self.sources: Dict[str, Source] = {}
        self._register_default_sources()
    
    def _register_default_sources(self):
        """Register all default sources"""
        
        # DNS Resolution
        self.register(Source(
            id="dns_resolver",
            name="DNS Resolver",
            description="Performs DNS lookups for domains and IP addresses",
            source_type=SourceType.LOCAL_TOOL,
            category="OSINT / Cyber Intelligence",
            supported_targets=["domain", "ipv4", "ipv6", "url"],
            priority=9,
            timeout=10
        ))
        
        # RDAP Lookup
        self.register(Source(
            id="rdap_lookup",
            name="RDAP Lookup",
            description="Retrieves registration data for domains and IP addresses",
            source_type=SourceType.LOCAL_TOOL,
            category="OSINT / Cyber Intelligence",
            supported_targets=["domain", "ipv4", "ipv6", "url"],
            priority=8,
            timeout=20
        ))
        
        # Certificate Transparency
        self.register(Source(
            id="crtsh",
            name="Crt.sh",
            description="Searches Certificate Transparency logs for SSL/TLS certificates",
            source_type=SourceType.EXTERNAL_API,
            category="Web Security",
            supported_targets=["domain", "url"],
            priority=8,
            timeout=15
        ))
        
        # VirusTotal (requires API key)
        self.register(Source(
            id="virustotal",
            name="VirusTotal",
            description="Checks domains and IPs for malware and security threats",
            source_type=SourceType.EXTERNAL_API,
            category="Blue Team / Threat Intelligence",
            requires_credentials=True,
            credentials_keys=["VIRUSTOTAL_API_KEY"],
            supported_targets=["domain", "ipv4", "url", "hash_md5", "hash_sha1", "hash_sha256"],
            priority=9,
            timeout=10
        ))
        
        # AbuseIPDB (requires API key)
        self.register(Source(
            id="abuseipdb",
            name="AbuseIPDB",
            description="Reports and queries IP addresses for abuse activity",
            source_type=SourceType.EXTERNAL_API,
            category="Blue Team / Threat Intelligence",
            requires_credentials=True,
            credentials_keys=["ABUSEIPDB_API_KEY"],
            supported_targets=["ipv4"],
            priority=8,
            timeout=10
        ))
        
        # Shodan (requires API key)
        self.register(Source(
            id="shodan",
            name="Shodan",
            description="Searches for connected devices and their vulnerabilities",
            source_type=SourceType.EXTERNAL_API,
            category="OSINT / Cyber Intelligence",
            requires_credentials=True,
            credentials_keys=["SHODAN_API_KEY"],
            supported_targets=["ipv4", "domain"],
            priority=9,
            timeout=15
        ))
        
        # WHOIS Data
        self.register(Source(
            id="whois",
            name="WHOIS",
            description="Retrieves domain and IP registration information",
            source_type=SourceType.LOCAL_TOOL,
            category="OSINT / Cyber Intelligence",
            supported_targets=["domain", "ipv4"],
            priority=7,
            timeout=15
        ))
        
        # UrlScan
        self.register(Source(
            id="urlscan",
            name="URLScan.io",
            description="Performs web page scans and threat analysis",
            source_type=SourceType.EXTERNAL_API,
            category="Web Security",
            supported_targets=["url", "domain"],
            priority=7,
            timeout=30
        ))
        
        # Hybrid Analysis
        self.register(Source(
            id="hybrid_analysis",
            name="Hybrid Analysis",
            description="Analyzes files and URLs for malware",
            source_type=SourceType.EXTERNAL_API,
            category="Blue Team / Threat Intelligence",
            supported_targets=["hash_md5", "hash_sha1", "hash_sha256", "url"],
            priority=7,
            timeout=20
        ))
        
        # Local Hash Analysis
        self.register(Source(
            id="local_hash_db",
            name="Local Hash Database",
            description="Queries local hash database for known malware",
            source_type=SourceType.DATABASE,
            category="Blue Team / Threat Intelligence",
            supported_targets=["hash_md5", "hash_sha1", "hash_sha256"],
            priority=6,
            timeout=5
        ))
        
        # GeoIP Database
        self.register(Source(
            id="geoip",
            name="GeoIP Lookup",
            description="Returns geographical information for IP addresses",
            source_type=SourceType.LOCAL_TOOL,
            category="OSINT / Cyber Intelligence",
            supported_targets=["ipv4"],
            priority=6,
            timeout=5
        ))
        
        # Network Analysis
        self.register(Source(
            id="nmap_scan",
            name="Network Port Scan",
            description="Scans network services and open ports",
            source_type=SourceType.LOCAL_TOOL,
            category="Blue Team / Threat Intelligence",
            supported_targets=["ipv4"],
            priority=5,
            timeout=60,
            active=False  # Disabled by default (requires user consent)
        ))
    
    def register(self, source: Source) -> None:
        """
        Register a new source.
        
        Args:
            source: Source object to register
        """
        self.sources[source.id] = source
    
    def get_source(self, source_id: str) -> Optional[Source]:
        """Get a source by ID"""
        return self.sources.get(source_id)
    
    def get_all_sources(self) -> List[Source]:
        """Get all registered sources"""
        return list(self.sources.values())
    
    def get_active_sources(self) -> List[Source]:
        """Get all active sources"""
        return [s for s in self.sources.values() if s.active]
    
    def get_sources_by_category(self, category: str) -> List[Source]:
        """Get sources by category"""
        return [s for s in self.sources.values() if s.category == category]
    
    def get_sources_for_target(self, target_type: str) -> List[Source]:
        """Get sources compatible with a target type"""
        return [s for s in self.sources.values() 
                if target_type in s.supported_targets and s.active]
    
    def get_sources_by_type(self, source_type: SourceType) -> List[Source]:
        """Get sources by source type"""
        return [s for s in self.sources.values() if s.source_type == source_type]
    
    def enable_source(self, source_id: str) -> bool:
        """Enable a source"""
        source = self.get_source(source_id)
        if source:
            source.active = True
            return True
        return False
    
    def disable_source(self, source_id: str) -> bool:
        """Disable a source"""
        source = self.get_source(source_id)
        if source:
            source.active = False
            return True
        return False
    
    def get_categories(self) -> List[str]:
        """Get all unique categories"""
        categories = set()
        for source in self.sources.values():
            categories.add(source.category)
        return sorted(list(categories))
