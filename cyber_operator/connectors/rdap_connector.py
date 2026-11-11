"""
RDAP Connector Module
Provides RDAP (Registration Data Access Protocol) lookups
"""

import requests
from threading import Lock
from typing import Dict, Any, Optional
from urllib.parse import quote, urljoin
import logging

logger = logging.getLogger(__name__)


class RDAPConnector:
    """Connector for RDAP-based OSINT gathering"""
    
    # RDAP bootstrap URLs
    RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
    RDAP_SERVERS = {
        "ipv4": "https://rdap.arin.net/registry/",
        "ipv6": "https://rdap.arin.net/registry/",
        "asn": "https://rdap.arin.net/registry/"
    }
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self._bootstrap_lock = Lock()
        self._domain_bootstrap = None
        self.session.headers.update({
            'Accept': 'application/rdap+json',
            'User-Agent': 'CyberOperator/0.1'
        })
    
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """
        Lookup domain registration information via RDAP.
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            Dictionary with domain RDAP information
        """
        result = {
            "domain": domain,
            "registrar": None,
            "registrar_url": None,
            "created_date": None,
            "updated_date": None,
            "expiration_date": None,
            "nameservers": [],
            "registrant_country": None,
            "status": [],
            "success": False,
            "error": None,
            "raw_data": {}
        }
        
        try:
            # Build RDAP domain lookup URL
            clean_domain = domain.lower().strip()
            rdap_url = self._get_domain_rdap_url(clean_domain)
            
            response = self.session.get(rdap_url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            result["raw_data"] = data
            
            # Parse RDAP response
            if 'entities' in data:
                for entity in data['entities']:
                    if 'roles' in entity and 'registrar' in entity['roles']:
                        result["registrar"] = entity.get('handle')
            
            # Get dates
            if 'events' in data:
                for event in data['events']:
                    event_action = event.get('eventAction', '')
                    event_date = event.get('eventDate')
                    
                    if event_action == 'registration':
                        result["created_date"] = event_date
                    elif event_action == 'last update':
                        result["updated_date"] = event_date
                    elif event_action == 'expiration':
                        result["expiration_date"] = event_date
            
            # Get nameservers
            if 'nameservers' in data:
                result["nameservers"] = [
                    ns.get('ldhName', ns.get('handle')) 
                    for ns in data['nameservers']
                ]
            
            # Get status
            if 'status' in data:
                result["status"] = data['status']
            
            result["success"] = True
            
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.error(f"RDAP domain lookup failed for {domain}: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"RDAP parsing error for {domain}: {e}")
        
        return result

    def _get_domain_rdap_url(self, domain: str) -> str:
        """Resolve the authoritative RDAP base URL through IANA's DNS bootstrap."""
        with self._bootstrap_lock:
            if self._domain_bootstrap is None:
                try:
                    response = self.session.get(
                        self.RDAP_BOOTSTRAP,
                        timeout=min(self.timeout, 5)
                    )
                    response.raise_for_status()
                    self._domain_bootstrap = response.json()
                except (requests.exceptions.RequestException, ValueError) as exc:
                    logger.warning("RDAP bootstrap unavailable; using rdap.org: %s", exc)
                    self._domain_bootstrap = {}

        tld = domain.rstrip(".").rsplit(".", 1)[-1].lower()
        for match, servers in self._domain_bootstrap.get("services", []):
            if tld in (value.lower() for value in match):
                if servers:
                    base_url = servers[0].rstrip("/") + "/"
                    encoded_domain = quote(domain, safe=".-")
                    return urljoin(base_url, f"domain/{encoded_domain}")
        return f"https://rdap.org/domain/{quote(domain, safe='.-')}"
    
    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP address information via RDAP.
        
        Args:
            ip_address: IP address to lookup (IPv4 or IPv6)
            
        Returns:
            Dictionary with IP RDAP information
        """
        result = {
            "ip_address": ip_address,
            "asn": None,
            "network": None,
            "organization": None,
            "country": None,
            "type": None,
            "status": [],
            "success": False,
            "error": None,
            "raw_data": {}
        }
        
        try:
            # Use ARIN RDAP for IP lookups
            rdap_url = f"https://rdap.arin.net/registry/ip/{ip_address}"
            
            response = self.session.get(rdap_url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            result["raw_data"] = data
            
            # Parse RDAP response
            if 'startAddress' in data and 'endAddress' in data:
                result["network"] = f"{data['startAddress']} - {data['endAddress']}"
            
            # Get organization
            if 'entities' in data:
                for entity in data['entities']:
                    if 'roles' in entity and 'registrant' in entity['roles']:
                        result["organization"] = entity.get('handle')
            
            # Get status
            if 'status' in data:
                result["status"] = data['status']
            
            result["success"] = True
            
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.warning(f"RDAP IP lookup failed for {ip_address}: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"RDAP parsing error for {ip_address}: {e}")
        
        return result
    
    def lookup_asn(self, asn: str) -> Dict[str, Any]:
        """
        Lookup ASN information via RDAP.
        
        Args:
            asn: Autonomous System Number (AS12345 or 12345 format)
            
        Returns:
            Dictionary with ASN RDAP information
        """
        result = {
            "asn": asn,
            "organization": None,
            "country": None,
            "prefixes": [],
            "status": [],
            "success": False,
            "error": None,
            "raw_data": {}
        }
        
        try:
            # Normalize ASN format
            clean_asn = asn.replace('AS', '').replace('as', '')
            rdap_url = f"https://rdap.arin.net/registry/autnum/{clean_asn}"
            
            response = self.session.get(rdap_url, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            result["raw_data"] = data
            
            # Parse RDAP response
            if 'entities' in data:
                for entity in data['entities']:
                    if 'roles' in entity and 'registrant' in entity['roles']:
                        result["organization"] = entity.get('handle')
            
            # Get status
            if 'status' in data:
                result["status"] = data['status']
            
            result["success"] = True
            
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.warning(f"RDAP ASN lookup failed for {asn}: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"RDAP parsing error for {asn}: {e}")
        
        return result
