"""
Utility Functions Module
Common utilities and helpers
"""

import json
import hashlib
import ipaddress
from typing import Any, Dict, List
from datetime import datetime
from urllib.parse import urlsplit


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """
    Hash a string using specified algorithm.
    
    Args:
        text: String to hash
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hexadecimal hash string
    """
    if algorithm == "md5":
        return hashlib.md5(text.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(text.encode()).hexdigest()
    else:  # sha256
        return hashlib.sha256(text.encode()).hexdigest()


def normalize_target(target: str) -> str:
    """
    Normalize a search target.
    
    Args:
        target: Raw target string
        
    Returns:
        Normalized target
    """
    return target.strip().lower()


def sanitize_target(target: str) -> str:
    """
    Sanitize a search target for safety.
    
    Args:
        target: Target string
        
    Returns:
        Sanitized target
    """
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", ';', '`', '|', '&']
    sanitized = target
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()


def is_private_target(target: str) -> bool:
    """
    Check if target appears to be private/internal.
    
    Args:
        target: Target string
        
    Returns:
        True if target appears private
    """
    value = target.strip().lower()
    if not value:
        return False

    if "://" in value:
        value = urlsplit(value).hostname or value
    elif "@" in value:
        value = value.rsplit("@", 1)[-1]

    value = value.rstrip(".")
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        pass

    private_suffixes = (
        ".local", ".internal", ".intranet", ".lan", ".home", ".home.arpa",
        ".localhost", ".test", ".invalid"
    )
    return (
        value == "localhost"
        or "." not in value
        or value.endswith(private_suffixes)
    )


def format_timestamp(dt: datetime = None) -> str:
    """
    Format datetime to ISO string.
    
    Args:
        dt: Datetime object (defaults to now)
        
    Returns:
        ISO formatted string
    """
    if dt is None:
        dt = datetime.now()
    return dt.isoformat()


def parse_timestamp(ts_string: str) -> datetime:
    """
    Parse ISO timestamp string.
    
    Args:
        ts_string: ISO timestamp string
        
    Returns:
        Datetime object
    """
    return datetime.fromisoformat(ts_string)


def format_bytes(bytes_size: int) -> str:
    """
    Format bytes to human readable format.
    
    Args:
        bytes_size: Size in bytes
        
    Returns:
        Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    
    return f"{bytes_size:.2f} TB"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted string
    """
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.2f}h"


def merge_dicts(dict1: Dict, dict2: Dict, deep: bool = True) -> Dict:
    """
    Merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        deep: Whether to do deep merge
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict) and deep:
            result[key] = merge_dicts(result[key], value, deep=True)
        else:
            result[key] = value
    
    return result


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """
    Flatten a nested dictionary.
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key prefix
        sep: Separator for keys
        
    Returns:
        Flattened dictionary
    """
    items = []
    
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    
    return dict(items)


def safe_json_dumps(obj: Any, **kwargs) -> str:
    """
    Safely dump object to JSON string.
    
    Args:
        obj: Object to serialize
        **kwargs: Additional arguments for json.dumps
        
    Returns:
        JSON string
    """
    return json.dumps(obj, default=str, **kwargs)


def safe_json_loads(json_str: str) -> Any:
    """
    Safely load JSON string.
    
    Args:
        json_str: JSON string
        
    Returns:
        Parsed object
    """
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        return None
