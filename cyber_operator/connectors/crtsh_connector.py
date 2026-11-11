"""
Certificate Transparency (Crt.sh) Connector Module
Searches for SSL/TLS certificates via Certificate Transparency logs
"""

import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class CrtshConnector:
    """Connector for Certificate Transparency searches via crt.sh"""
    
    BASE_URL = "https://crt.sh"
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberOperator/0.1'
        })
    
    def search_domain(self, domain: str, include_subdomains: bool = True) -> Dict[str, Any]:
        """
        Search for SSL/TLS certificates issued for a domain.
        
        Args:
            domain: Domain to search for
            include_subdomains: Whether to include subdomains (uses wildcards)
            
        Returns:
            Dictionary with certificate results
        """
        result = {
            "domain": domain,
            "certificates_found": 0,
            "certificates": [],
            "subdomains": set(),
            "issuers": set(),
            "success": False,
            "error": None
        }
        
        try:
            # Build search query
            if include_subdomains:
                search_query = f"%.{domain}"
            else:
                search_query = domain
            
            params = {
                "q": search_query,
                "output": "json"
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/api/certs",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            
            if isinstance(data, list):
                result["certificates_found"] = len(data)
                
                for cert in data:
                    cert_info = {
                        "id": cert.get('id'),
                        "logged_at": cert.get('logged_at'),
                        "not_before": cert.get('not_before'),
                        "not_after": cert.get('not_after'),
                        "issuer": cert.get('issuer_name'),
                        "common_name": cert.get('common_name'),
                        "subject_alternative_names": cert.get('name_value', '').split('\n'),
                        "url": f"{self.BASE_URL}/?id={cert.get('id')}"
                    }
                    
                    result["certificates"].append(cert_info)
                    
                    # Extract subdomains
                    if cert.get('name_value'):
                        names = cert.get('name_value').split('\n')
                        for name in names:
                            clean_name = name.strip().lower()
                            if clean_name and clean_name != domain:
                                result["subdomains"].add(clean_name)
                    
                    # Extract issuers
                    if cert.get('issuer_name'):
                        result["issuers"].add(cert.get('issuer_name'))
                
                result["success"] = True
            
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.error(f"Crt.sh search failed for {domain}: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Crt.sh parsing error for {domain}: {e}")
        
        # Convert sets to lists for JSON serialization
        result["subdomains"] = sorted(list(result["subdomains"]))
        result["issuers"] = sorted(list(result["issuers"]))
        
        return result
    
    def get_certificate_details(self, cert_id: int) -> Dict[str, Any]:
        """
        Get detailed information about a specific certificate.
        
        Args:
            cert_id: Certificate ID from crt.sh
            
        Returns:
            Dictionary with detailed certificate information
        """
        result = {
            "cert_id": cert_id,
            "details": {},
            "success": False,
            "error": None
        }
        
        try:
            params = {
                "id": cert_id,
                "output": "json"
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/api/certs",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            
            if isinstance(data, list) and len(data) > 0:
                cert = data[0]
                result["details"] = cert
                result["success"] = True
            
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.error(f"Failed to get certificate details {cert_id}: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Error parsing certificate {cert_id}: {e}")
        
        return result
    
    def search_issuer(self, issuer: str) -> Dict[str, Any]:
        """
        Search for certificates issued by a specific issuer.
        
        Args:
            issuer: Issuer name to search for
            
        Returns:
            Dictionary with certificates by issuer
        """
        result = {
            "issuer": issuer,
            "certificates_found": 0,
            "certificates": [],
            "domains": set(),
            "success": False,
            "error": None
        }
        
        try:
            params = {
                "q": issuer,
                "output": "json"
            }
            
            response = self.session.get(
                f"{self.BASE_URL}/api/certs",
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
            
            data = response.json()
            
            if isinstance(data, list):
                # Filter by issuer
                matching_certs = [
                    cert for cert in data 
                    if issuer.lower() in cert.get('issuer_name', '').lower()
                ]
                
                result["certificates_found"] = len(matching_certs)
                
                for cert in matching_certs[:100]:  # Limit to 100 results
                    cert_info = {
                        "id": cert.get('id'),
                        "logged_at": cert.get('logged_at'),
                        "common_name": cert.get('common_name'),
                        "not_before": cert.get('not_before'),
                        "not_after": cert.get('not_after')
                    }
                    
                    result["certificates"].append(cert_info)
                    
                    # Extract domains
                    if cert.get('common_name'):
                        result["domains"].add(cert.get('common_name'))
                
                result["success"] = True
            
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            logger.error(f"Issuer search failed for {issuer}: {e}")
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Issuer search parsing error for {issuer}: {e}")
        
        result["domains"] = sorted(list(result["domains"]))
        
        return result
