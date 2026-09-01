import asyncio
import logging
import random
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ProxyManager:
    """Manage proxy rotation and assignment"""
    
    def __init__(self, config, database):
        self.config = config
        self.database = database
        self.active_proxies: Dict[str, Dict] = {}  # session_id -> proxy
        self.proxy_usage: Dict[str, int] = {}  # proxy_key -> usage_count
        self.proxy_lock = asyncio.Lock()
    
    async def initialize(self):
        """Load proxies from config to database"""
        proxies = self.config.get_all_proxies()
        country_mapping = self.config.parse_proxy_country_mapping()
        
        for proxy in proxies:
            # Determine country for proxy
            country_code = None
            for code, p in country_mapping.items():
                if p == proxy:
                    country_code = code
                    break
            
            await self.database.add_proxy(proxy, country_code)
        
        logger.info(f"✅ Loaded {len(proxies)} proxies")
    
    async def get_proxy(self, country_code: Optional[str] = None) -> Optional[Dict]:
        """Get proxy for session (by country or any available)"""
        async with self.proxy_lock:
            proxy = None
            
            if country_code:
                proxy = await self.database.get_proxy_for_country(country_code)
            
            if not proxy:
                proxy = await self.database.get_any_proxy()
            
            if proxy:
                proxy_key = self._get_proxy_key(proxy)
                self.proxy_usage[proxy_key] = self.proxy_usage.get(proxy_key, 0) + 1
                logger.info(f"✅ Proxy assigned: {proxy.get('hostname', 'unknown')} (country: {country_code or 'any'})")
            
            return proxy
    
    async def release_proxy(self, proxy: Dict):
        """Release proxy back to pool"""
        if not proxy:
            return
        
        async with self.proxy_lock:
            proxy_key = self._get_proxy_key(proxy)
            if proxy_key in self.proxy_usage and self.proxy_usage[proxy_key] > 0:
                self.proxy_usage[proxy_key] -= 1
            
            await self.database.release_proxy(proxy)
            logger.info(f"🔄 Proxy released: {proxy.get('hostname', 'unknown')}")
    
    def _get_proxy_key(self, proxy: Dict) -> str:
        """Generate unique key for proxy"""
        scheme = proxy.get('scheme', 'http')
        hostname = proxy.get('hostname', '')
        port = proxy.get('port', 80)
        username = proxy.get('username', '')
        return f"{scheme}://{username}@{hostname}:{port}"
    
    def get_active_proxy_count(self) -> int:
        """Get count of active proxies in use"""
        return sum(self.proxy_usage.values())
    
    def get_available_proxy_count(self) -> int:
        """Get count of available proxies"""
        total = len(self.config.get_all_proxies())
        active = sum(self.proxy_usage.values())
        return max(0, total - active)