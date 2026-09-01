import os
import json
import uuid
import base64
import hashlib
from typing import Dict, List, Optional
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration with Neon.tech PostgreSQL support"""
    
    # Telegram API
    TELEGRAM_API_ID = int(os.getenv('TELEGRAM_API_ID', '0'))
    TELEGRAM_API_HASH = os.getenv('TELEGRAM_API_HASH', '')
    
    # API Authentication
    API_KEY = os.getenv('API_KEY', 'your-secret-api-key')
    
    # Worker
    WORKER_ID = os.getenv('WORKER_ID', str(uuid.uuid4())[:8])
    MAX_CONCURRENT_SESSIONS = int(os.getenv('MAX_CONCURRENT_SESSIONS', '5'))
    DEFAULT_SESSION_TIMEOUT = int(os.getenv('DEFAULT_SESSION_TIMEOUT', '300'))
    
    # Main Server
    MAIN_SERVER_URL = os.getenv('MAIN_SERVER_URL', 'https://tg-server-t88w.onrender.com')
    
    # Profile defaults
    DEFAULT_PROFILE_PHOTO_URL = os.getenv('DEFAULT_PROFILE_PHOTO_URL', '')
    DEFAULT_WATERMARK = os.getenv('DEFAULT_WATERMARK', 'digital_marketplace')
    DEFAULT_BIO = os.getenv('DEFAULT_BIO', '')
    
    # ============================================
    # NEON.TECH DATABASE CONFIGURATION
    # ============================================
    @staticmethod
    def get_db_config() -> Dict:
        """
        Get database configuration for Neon.tech PostgreSQL
        Supports both DATABASE_URL and individual fields
        """
        # Option 1: DATABASE_URL (Recommended)
        database_url = os.getenv('DATABASE_URL', '')
        
        if database_url:
            try:
                parsed = urlparse(database_url)
                
                # Parse Neon.tech connection string
                db_config = {
                    'host': parsed.hostname,
                    'port': parsed.port or 5432,
                    'database': parsed.path.lstrip('/') if parsed.path else 'neondb',
                    'user': parsed.username or 'postgres',
                    'password': parsed.password or '',
                    'ssl': 'require'  # Neon.tech requires SSL
                }
                
                # Add connection string for reference
                db_config['connection_string'] = database_url
                
                return db_config
            except Exception as e:
                print(f"⚠️ Error parsing DATABASE_URL: {e}")
        
        # Option 2: Individual fields
        db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', '5432')),
            'database': os.getenv('DB_NAME', 'neondb'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD', ''),
            'ssl': os.getenv('DB_SSL', 'require')  # 'require' for Neon.tech
        }
        
        # Build connection string
        if db_config['password']:
            db_config['connection_string'] = (
                f"postgresql://{db_config['user']}:{db_config['password']}"
                f"@{db_config['host']}:{db_config['port']}/{db_config['database']}"
                f"?sslmode={db_config['ssl']}"
            )
        
        return db_config
    
    # Database config as property
    @property
    def DB_CONFIG(self) -> Dict:
        """Get database configuration"""
        return self.get_db_config()
    
    # ============================================
    # ENCRYPTION KEY
    # ============================================
    @staticmethod
    def get_encryption_key() -> bytes:
        """Get or generate encryption key for sensitive data"""
        # Check environment variable first
        env_key = os.getenv('ENCRYPTION_KEY', '')
        if env_key:
            try:
                return base64.b64decode(env_key)
            except:
                pass
        
        # Generate from API key or random
        seed = os.getenv('API_KEY', os.urandom(32).hex())
        key = hashlib.sha256(seed.encode()).digest()
        return base64.urlsafe_b64encode(key)
    
    ENCRYPTION_KEY = get_encryption_key()
    
    # ============================================
    # PROXY CONFIGURATION
    # ============================================
    @staticmethod
    def parse_proxies() -> List[Dict]:
        """Parse proxy list from environment"""
        proxy_list = os.getenv('PROXY_LIST', '')
        if not proxy_list:
            return []
        
        proxies = []
        for proxy_str in proxy_list.split(','):
            proxy_str = proxy_str.strip()
            if proxy_str:
                proxy = Config.parse_proxy_string(proxy_str)
                if proxy:
                    proxies.append(proxy)
        return proxies
    
    @staticmethod
    def parse_proxy_string(proxy_str: str) -> Optional[Dict]:
        """Parse single proxy string to dict"""
        try:
            if '://' not in proxy_str:
                return None
            
            scheme, rest = proxy_str.split('://', 1)
            proxy = {'scheme': scheme}
            
            if '@' in rest:
                auth, host_port = rest.split('@', 1)
                if ':' in auth:
                    username, password = auth.split(':', 1)
                    proxy['username'] = username
                    proxy['password'] = password
            else:
                host_port = rest
            
            if ':' in host_port:
                hostname, port = host_port.rsplit(':', 1)
                proxy['hostname'] = hostname
                proxy['port'] = int(port)
            else:
                proxy['hostname'] = host_port
                proxy['port'] = 1080 if scheme == 'socks5' else 8080
            
            return proxy
        except Exception:
            return None
    
    @staticmethod
    def parse_proxy_country_mapping() -> Dict[str, Dict]:
        """Parse country to proxy mapping"""
        mapping_str = os.getenv('PROXY_COUNTRY_MAPPING', '{}')
        try:
            mapping = json.loads(mapping_str)
            result = {}
            for country, proxy_str in mapping.items():
                proxy = Config.parse_proxy_string(proxy_str)
                if proxy:
                    result[country.upper()] = proxy
            return result
        except Exception:
            return {}
    
    @staticmethod
    def get_all_proxies() -> List[Dict]:
        """Get all proxies"""
        proxies = Config.parse_proxies()
        country_proxies = list(Config.parse_proxy_country_mapping().values())
        
        for proxy in country_proxies:
            if proxy not in proxies:
                proxies.append(proxy)
        
        return proxies