"""
Target Classification Module
Analyzes and classifies the search target (domain, IP, hash, etc.)
"""

import re
import ipaddress
from typing import Dict, List, Tuple
from enum import Enum


class TargetType(Enum):
    """Enumeration of supported target types"""
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    URL = "url"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    UNKNOWN = "unknown"


class TargetClassifier:
    """Classifies and validates target types"""
    
    @staticmethod
    def classify(target: str) -> Tuple[TargetType, Dict]:
        """
        Classify a target string and return its type with metadata.
        
        Args:
            target: The target string to classify
            
        Returns:
            Tuple of (TargetType, metadata_dict)
        """
        if not target:
            return TargetType.UNKNOWN, {}
        
        target = target.strip().lower()
        metadata = {"original": target, "normalized": target}
        
        # Check for URL
        if TargetClassifier._is_url(target):
            return TargetType.URL, metadata
        
        try:
            address = ipaddress.ip_address(target)
            target_type = TargetType.IPV4 if address.version == 4 else TargetType.IPV6
            return target_type, metadata
        except ValueError:
            pass

        # Check for domain
        if TargetClassifier._is_domain(target):
            return TargetType.DOMAIN, metadata
        
        # Check for email
        if TargetClassifier._is_email(target):
            return TargetType.EMAIL, metadata
        
        # Check for hash
        hash_type = TargetClassifier._is_hash(target)
        if hash_type:
            return hash_type, metadata
        
        # Check for phone
        if TargetClassifier._is_phone(target):
            return TargetType.PHONE, metadata
        
        return TargetType.UNKNOWN, metadata
    
    @staticmethod
    def _is_domain(target: str) -> bool:
        """Check if target is a valid domain"""
        domain_pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]{2,}$'
        return bool(re.match(domain_pattern, target)) and '://' not in target
    
    @staticmethod
    def _is_url(target: str) -> bool:
        """Check if target is a URL"""
        return target.startswith(('http://', 'https://', 'ftp://'))
    
    @staticmethod
    def _is_ipv4(target: str) -> bool:
        """Check if target is an IPv4 address"""
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return bool(re.match(ipv4_pattern, target))
    
    @staticmethod
    def _is_ipv6(target: str) -> bool:
        """Check if target is an IPv6 address"""
        try:
            return ipaddress.ip_address(target).version == 6
        except ValueError:
            return False
    
    @staticmethod
    def _is_email(target: str) -> bool:
        """Check if target is an email address"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, target))
    
    @staticmethod
    def _is_hash(target: str) -> bool:
        """Check if target is a hash and return the type"""
        if len(target) == 32 and re.match(r'^[a-fA-F0-9]{32}$', target):
            return TargetType.HASH_MD5
        elif len(target) == 40 and re.match(r'^[a-fA-F0-9]{40}$', target):
            return TargetType.HASH_SHA1
        elif len(target) == 64 and re.match(r'^[a-fA-F0-9]{64}$', target):
            return TargetType.HASH_SHA256
        return False
    
    @staticmethod
    def _is_phone(target: str) -> bool:
        """Check if target looks like a phone number"""
        phone_pattern = r'^\+?[1-9]\d{1,14}$'
        return bool(re.match(phone_pattern, target.replace('-', '').replace(' ', '')))
    
    @staticmethod
    def get_compatible_categories(target_type: TargetType) -> List[str]:
        """
        Get compatible search categories for a target type.
        
        Args:
            target_type: The target type
            
        Returns:
            List of compatible categories
        """
        compatibility = {
            TargetType.DOMAIN: ["OSINT / Cyber Intelligence", "Web Security"],
            TargetType.IPV4: ["OSINT / Cyber Intelligence", "Blue Team / Threat Intelligence"],
            TargetType.IPV6: ["OSINT / Cyber Intelligence", "Blue Team / Threat Intelligence"],
            TargetType.URL: ["Web Security", "OSINT / Cyber Intelligence"],
            TargetType.HASH_MD5: ["Blue Team / Threat Intelligence", "Cyber Range / Lab Analysis"],
            TargetType.HASH_SHA1: ["Blue Team / Threat Intelligence", "Cyber Range / Lab Analysis"],
            TargetType.HASH_SHA256: ["Blue Team / Threat Intelligence", "Cyber Range / Lab Analysis"],
            TargetType.EMAIL: ["OSINT / Cyber Intelligence"],
            TargetType.PHONE: ["OSINT / Cyber Intelligence"],
            TargetType.USERNAME: ["OSINT / Cyber Intelligence"],
            TargetType.UNKNOWN: ["OSINT / Cyber Intelligence", "Blue Team / Threat Intelligence"],
        }
        return compatibility.get(target_type, ["OSINT / Cyber Intelligence"])
