"""
DNS Connector Module
Provides DNS resolution and enumeration capabilities
"""

import socket
import dns.resolver
import dns.rdatatype
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """Represents a DNS record"""
    record_type: str
    value: str
    ttl: Optional[int] = None


class DNSConnector:
    """Connector for DNS-based intelligence gathering"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
    
    def resolve_domain(self, domain: str) -> Dict[str, Any]:
        """
        Resolve a domain name to IP addresses.
        
        Args:
            domain: Domain name to resolve
            
        Returns:
            Dictionary with A and AAAA records
        """
        result = {
            "domain": domain,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "success": False,
            "error": None
        }
        
        try:
            # A records (IPv4)
            try:
                a_answers = self.resolver.resolve(domain, 'A')
                result["a_records"] = [str(rdata) for rdata in a_answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # AAAA records (IPv6)
            try:
                aaaa_answers = self.resolver.resolve(domain, 'AAAA')
                result["aaaa_records"] = [str(rdata) for rdata in aaaa_answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # MX records
            try:
                mx_answers = self.resolver.resolve(domain, 'MX')
                result["mx_records"] = [str(rdata.exchange).rstrip('.') 
                                       for rdata in mx_answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # NS records
            try:
                ns_answers = self.resolver.resolve(domain, 'NS')
                result["ns_records"] = [str(rdata).rstrip('.') for rdata in ns_answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            result["success"] = True
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"DNS resolution error for {domain}: {e}")
        
        return result
    
    def reverse_dns(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip_address: IP address to reverse lookup
            
        Returns:
            Dictionary with reverse DNS results
        """
        result = {
            "ip_address": ip_address,
            "hostnames": [],
            "success": False,
            "error": None
        }
        
        try:
            answers = self.resolver.resolve_address(ip_address)
            result["hostnames"] = sorted({
                str(answer).rstrip(".") for answer in answers
            })
            result["success"] = True
        except Exception as e:
            result["error"] = str(e)
            logger.warning(f"Reverse DNS failed for {ip_address}: {e}")
        
        return result
    
    def dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """
        Attempt basic DNS enumeration.
        
        Args:
            domain: Domain to enumerate
            
        Returns:
            Dictionary with enumeration results
        """
        result = {
            "domain": domain,
            "records": {},
            "subdomains": [],
            "success": False,
            "error": None
        }
        
        common_subdomains = [
            "www", "mail", "ftp", "admin", "test", "staging",
            "api", "dns", "ns1", "ns2", "vpn", "dev"
        ]
        
        try:
            # Try common subdomains
            for subdomain in common_subdomains:
                test_domain = f"{subdomain}.{domain}"
                try:
                    answers = self.resolver.resolve(test_domain, 'A')
                    result["subdomains"].append({
                        "subdomain": test_domain,
                        "ips": [str(rdata) for rdata in answers]
                    })
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
            
            result["success"] = len(result["subdomains"]) > 0
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"DNS enumeration error for {domain}: {e}")
        
        return result
    
    def get_txt_records(self, domain: str) -> Dict[str, Any]:
        """
        Retrieve TXT records (DMARC, SPF, etc.)
        
        Args:
            domain: Domain to query
            
        Returns:
            Dictionary with TXT records
        """
        result = {
            "domain": domain,
            "txt_records": [],
            "spf": None,
            "dmarc": None,
            "success": False,
            "error": None
        }
        
        try:
            # TXT records
            try:
                txt_answers = self.resolver.resolve(domain, 'TXT')
                result["txt_records"] = [str(rdata) for rdata in txt_answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # SPF records
            try:
                spf_answers = self.resolver.resolve(domain, 'TXT')
                for rdata in spf_answers:
                    spf_str = str(rdata)
                    if 'v=spf1' in spf_str:
                        result["spf"] = spf_str
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            # DMARC records
            try:
                dmarc_answers = self.resolver.resolve(f"_dmarc.{domain}", 'TXT')
                for rdata in dmarc_answers:
                    result["dmarc"] = str(rdata)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            result["success"] = True
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"TXT record retrieval error for {domain}: {e}")
        
        return result
