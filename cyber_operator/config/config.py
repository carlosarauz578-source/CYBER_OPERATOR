"""
Configuration Module
Manages application settings and environment variables
"""

import os
from pathlib import Path
from typing import Optional
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


class Config:
    """Application configuration"""
    
    # Base paths
    BASE_DIR = Path(__file__).parent.parent.parent
    DATA_DIR = BASE_DIR / "data"
    LOGS_DIR = BASE_DIR / "logs"
    DB_DIR = BASE_DIR / "database"
    
    # Database
    DATABASE_PATH = DB_DIR / "cyber_operator.db"
    DATABASE_CACHE_TTL = 3600  # 1 hour
    DATABASE_CLEANUP_DAYS = 90
    
    # API Configuration
    API_TIMEOUT = 30
    MAX_CONCURRENT_QUERIES = 5
    RATE_LIMIT = 100  # requests per minute
    
    # DNS Configuration
    DNS_TIMEOUT = 10
    DNS_RETRIES = 3
    
    # RDAP Configuration
    RDAP_TIMEOUT = 15
    RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
    
    # Crt.sh Configuration
    CRTSH_TIMEOUT = 20
    CRTSH_BASE_URL = "https://crt.sh"
    
    # External API Keys (load from environment)
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY")
    SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY")
    URLSCAN_API_KEY: Optional[str] = os.getenv("URLSCAN_API_KEY")
    
    # Feature Flags
    ENABLE_EXTERNAL_APIS = True
    ENABLE_NETWORK_SCANS = False  # Disabled by default (requires user consent)
    ENABLE_CACHING = True
    ENABLE_QUERY_HISTORY = True
    
    # Streamlit Configuration
    STREAMLIT_THEME = "light"
    STREAMLIT_LAYOUT = "wide"
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories"""
        for directory in [cls.DATA_DIR, cls.LOGS_DIR, cls.DB_DIR]:
            directory.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def get_api_key(cls, service_name: str) -> Optional[str]:
        """Get API key for a service"""
        key_attr = f"{service_name.upper()}_API_KEY"
        return getattr(cls, key_attr, None)
    
    @classmethod
    def has_credentials(cls, service_name: str) -> bool:
        """Check if credentials are available for a service"""
        return cls.get_api_key(service_name) is not None
    
    @classmethod
    def load_env_file(cls, env_file: str = ".env"):
        """Load environment variables from .env file"""
        env_path = cls.BASE_DIR / env_file
        
        if not env_path.exists():
            logger.warning(f".env file not found at {env_path}")
            return
        
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
            logger.info(f"Environment variables loaded from {env_path}")
        except Exception as e:
            logger.error(f"Failed to load .env file: {e}")


# Initialize configuration
Config.ensure_directories()
