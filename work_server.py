import asyncio
import os
import uuid
import random
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, status, Header, Depends
from pydantic import BaseModel, Field, validator
from pyrogram import Client
from pyrogram.errors import (
    SessionPasswordNeeded,
    PhoneCodeInvalid,
    PhoneCodeExpired,
    PasswordHashInvalid,
    FloodWait,
    PhoneNumberInvalid,
    PhoneNumberBanned
)
from dotenv import load_dotenv
import logging
import httpx
import asyncpg
from asyncpg.pool import Pool

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== CONFIGURATION ====================
TELEGRAM_API_ID = int(os.getenv('TELEGRAM_API_ID'))
TELEGRAM_API_HASH = os.getenv('TELEGRAM_API_HASH')
API_KEY = os.getenv('API_KEY', 'your-secret-api-key')
ADMIN_API_KEY = os.getenv('ADMIN_API_KEY', 'your-admin-secret-key')
WORKER_ID = os.getenv('WORKER_ID', str(uuid.uuid4())[:8])
MAX_CONCURRENT_SESSIONS = int(os.getenv('MAX_CONCURRENT_SESSIONS', '100'))
DEFAULT_SESSION_TIMEOUT = int(os.getenv('DEFAULT_SESSION_TIMEOUT', '300'))
MAIN_SERVER_URL = os.getenv('MAIN_SERVER_URL', 'https://tg-server-t88w.onrender.com')

# PostgreSQL Configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost:5432/telegram_proxies')

# Country code mapping
COUNTRY_CODE_MAP = {
    '880': 'BD', '91': 'IN', '1': 'US', '44': 'GB', '81': 'JP',
    '86': 'CN', '82': 'KR', '49': 'DE', '33': 'FR', '39': 'IT',
    '7': 'RU', '55': 'BR', '34': 'ES', '61': 'AU', '31': 'NL',
    '46': 'SE', '41': 'CH', '43': 'AT', '32': 'BE', '45': 'DK',
    '47': 'NO', '48': 'PL', '351': 'PT', '353': 'IE', '358': 'FI',
    '30': 'GR', '36': 'HU', '40': 'RO', '380': 'UA', '90': 'TR',
    '972': 'IL', '966': 'SA', '971': 'AE', '65': 'SG', '60': 'MY',
    '66': 'TH', '84': 'VN', '62': 'ID', '63': 'PH', '92': 'PK',
    '94': 'LK', '98': 'IR', '20': 'EG', '27': 'ZA', '234': 'NG',
    '254': 'KE', '212': 'MA', '216': 'TN', '213': 'DZ', '52': 'MX',
    '54': 'AR', '56': 'CL', '57': 'CO', '58': 'VE', '51': 'PE',
    '593': 'EC', '595': 'PY', '598': 'UY', '506': 'CR', '507': 'PA',
    '503': 'SV', '502': 'GT', '504': 'HN', '505': 'NI', '852': 'HK',
    '853': 'MO', '886': 'TW', '64': 'NZ', '356': 'MT', '357': 'CY',
    '370': 'LT', '371': 'LV', '372': 'EE', '373': 'MD', '374': 'AM',
    '375': 'BY', '376': 'AD', '377': 'MC', '378': 'SM', '381': 'RS',
    '382': 'ME', '383': 'XK', '385': 'HR', '386': 'SI', '387': 'BA',
    '389': 'MK', '420': 'CZ', '421': 'SK', '423': 'LI', '994': 'AZ',
    '995': 'GE', '996': 'KG', '998': 'UZ', '993': 'TM', '992': 'TJ',
    '977': 'NP', '975': 'BT', '960': 'MV', '856': 'LA', '855': 'KH',
    '673': 'BN', '679': 'FJ', '675': 'PG', '686': 'KI',
    '692': 'MH', '691': 'FM', '680': 'PW', '677': 'SB', '678': 'VU',
    '685': 'WS', '676': 'TO', '674': 'NR', '688': 'TV', '690': 'TK',
    '687': 'NC', '689': 'PF', '263': 'ZW', '260': 'ZM', '265': 'MW',
    '258': 'MZ', '267': 'BW', '266': 'LS', '268': 'SZ', '264': 'NA',
    '244': 'AO', '243': 'CD', '242': 'CG', '241': 'GA', '240': 'GQ',
    '239': 'ST', '238': 'CV', '237': 'CM', '236': 'CF', '235': 'TD',
    '233': 'GH', '232': 'SL', '231': 'LR', '230': 'MU', '229': 'BJ',
    '228': 'TG', '227': 'NE', '226': 'BF', '225': 'CI', '224': 'GN',
    '223': 'ML', '222': 'MR', '221': 'SN', '220': 'GM', '218': 'LY',
    '249': 'SD', '252': 'SO', '253': 'DJ', '256': 'UG', '257': 'BI',
    '255': 'TZ', '250': 'RW', '251': 'ET', '291': 'ER',
    '262': 'RE', '269': 'KM', '261': 'MG', '248': 'SC', '246': 'IO',
    '245': 'GW', '211': 'SS'
}

# ==================== DATA MODELS ====================
class WorkerOTPRequest(BaseModel):
    session_id: str
    phone_number: str
    reject_2fa: bool = Field(False, description="Reject if account has 2FA")
    timeout_seconds: Optional[int] = Field(None, description="Custom session timeout in seconds")
    use_proxy: bool = Field(False, description="Use proxy for this session")
    country_code: Optional[str] = Field(None, description="Country code like +880, BD, Bangladesh")

class WorkerVerifyOTP(BaseModel):
    session_id: str
    otp_code: str

class WorkerVerify2FA(BaseModel):
    session_id: str
    password: str

class ProxyInfo(BaseModel):
    id: Optional[int] = None
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    country_code: str
    country_name: str
    protocol: str = "socks5"
    is_active: bool = True
    max_sessions: int = 10

class AdminProxyAddRequest(BaseModel):
    proxies: List[ProxyInfo]

class AdminProxyCheckRequest(BaseModel):
    country_codes: Optional[List[str]] = None
    limit: Optional[int] = 10

# ==================== PROXY MANAGER ====================
class ProxyManager:
    """Manage proxies from PostgreSQL database"""
    
    def __init__(self):
        self.pool: Optional[Pool] = None
        self.proxy_cache: Dict[str, List[ProxyInfo]] = {}
        self.cache_timestamp: Dict[str, datetime] = {}
        self.cache_ttl = 30  # Cache for 30 seconds
        self.db_lock = asyncio.Lock()
        self.cache_lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize database connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                DATABASE_URL,
                min_size=2,
                max_size=10,
                command_timeout=60
            )
            logger.info("✅ PostgreSQL connection pool initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize PostgreSQL pool: {e}")
            self.pool = None
    
    async def close(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("✅ PostgreSQL connection pool closed")
    
    def extract_country_code(self, phone_number: str) -> str:
        """Extract country code from phone number"""
        clean_number = ''.join(filter(str.isdigit, phone_number))
        
        sorted_codes = sorted(COUNTRY_CODE_MAP.keys(), key=len, reverse=True)
        for code in sorted_codes:
            if clean_number.startswith(code):
                return COUNTRY_CODE_MAP[code]
        
        return "UNKNOWN"
    
    def normalize_country_code(self, country_code: str) -> str:
        """Normalize country code to ISO format"""
        if not country_code:
            return "UNKNOWN"
        
        country_code = country_code.strip().upper()
        
        if len(country_code) == 2 and country_code in COUNTRY_CODE_MAP.values():
            return country_code
        
        if country_code.startswith('+'):
            country_code = country_code[1:]
        
        if country_code in COUNTRY_CODE_MAP:
            return COUNTRY_CODE_MAP[country_code]
        
        country_names = {
            'BANGLADESH': 'BD', 'INDIA': 'IN', 'UNITED STATES': 'US', 'USA': 'US',
            'UNITED KINGDOM': 'GB', 'UK': 'GB', 'JAPAN': 'JP', 'CHINA': 'CN',
            'SOUTH KOREA': 'KR', 'GERMANY': 'DE', 'FRANCE': 'FR', 'ITALY': 'IT',
            'RUSSIA': 'RU', 'BRAZIL': 'BR', 'SPAIN': 'ES', 'AUSTRALIA': 'AU',
            'NETHERLANDS': 'NL', 'SWEDEN': 'SE', 'SWITZERLAND': 'CH', 'AUSTRIA': 'AT',
            'BELGIUM': 'BE', 'DENMARK': 'DK', 'NORWAY': 'NO', 'POLAND': 'PL',
            'PORTUGAL': 'PT', 'IRELAND': 'IE', 'FINLAND': 'FI', 'GREECE': 'GR',
            'HUNGARY': 'HU', 'ROMANIA': 'RO', 'UKRAINE': 'UA', 'TURKEY': 'TR',
            'ISRAEL': 'IL', 'SAUDI ARABIA': 'SA', 'UAE': 'AE', 'SINGAPORE': 'SG',
            'MALAYSIA': 'MY', 'THAILAND': 'TH', 'VIETNAM': 'VN', 'INDONESIA': 'ID',
            'PHILIPPINES': 'PH', 'PAKISTAN': 'PK', 'SRI LANKA': 'LK'
        }
        
        if country_code in country_names:
            return country_names[country_code]
        
        return country_code
    
    async def invalidate_country_cache(self, country_code: str):
        """Immediately invalidate cache for specific country"""
        async with self.cache_lock:
            normalized_country = self.normalize_country_code(country_code)
            self.proxy_cache.pop(normalized_country, None)
            self.cache_timestamp.pop(normalized_country, None)
            logger.info(f"🔄 Cache invalidated for country: {normalized_country}")
    
    async def get_proxies_for_country(self, country_code: str) -> List[ProxyInfo]:
        """Get proxies for a specific country from database"""
        normalized_country = self.normalize_country_code(country_code)
        
        # Check cache first
        cache_key = normalized_country
        if cache_key in self.proxy_cache:
            cache_time = self.cache_timestamp.get(cache_key)
            if cache_time and (datetime.now() - cache_time).seconds < self.cache_ttl:
                logger.info(f"📦 Returning cached proxies for {normalized_country}")
                return self.proxy_cache[cache_key]
        
        if not self.pool:
            logger.error("❌ Database pool not initialized")
            return []
        
        async with self.db_lock:
            try:
               async with self.pool.acquire() as conn:
                    rows = await conn.fetch(
                        """
                        SELECT id, proxy_data, country_code, is_active, 
                               last_used, success_count, fail_count, ping_ms
                        FROM proxies 
                        WHERE country_code = $1 
                          AND is_active = true 
                          AND (last_used IS NULL OR last_used < NOW() - INTERVAL '30 seconds')
                          AND current_usage < max_usage
                        ORDER BY 
                            CASE 
                                WHEN fail_count > 3 THEN 1 
                                ELSE 0 
                            END,
                            ping_ms ASC NULLS LAST,
                            success_count DESC,
                            RANDOM()
                        LIMIT 10
                        """,
                        normalized_country
                    )
                    
                    proxies = []
                    for row in rows:
                        proxy_data = row['proxy_data']
                        proxy = ProxyInfo(
                            id=row['id'],
                            host=proxy_data.get('host', ''),
                            port=proxy_data.get('port', 0),
                            username=proxy_data.get('username'),
                            password=proxy_data.get('password'),
                            country_code=row['country_code'],
                            country_name=proxy_data.get('country_name', ''),
                            protocol=proxy_data.get('protocol', 'socks5'),
                            is_active=row['is_active']
                        )
                        proxies.append(proxy)
                
                    # Update cache
                    async with self.cache_lock:
                        self.proxy_cache[cache_key] = proxies
                        self.cache_timestamp[cache_key] = datetime.now()
                    
                    logger.info(f"🌍 Found {len(proxies)} proxies for {normalized_country}")
                    return proxies
                    
            except Exception as e:
                logger.error(f"❌ Error fetching proxies from database: {e}")
                return []
    
    async def update_proxy_status(self, proxy_id: int, success: bool):
        """Update proxy success/failure status"""
        if not self.pool:
            return
        
        try:
            async with self.pool.acquire() as conn:
                if success:
                    await conn.execute(
                        """
                        UPDATE proxies 
                        SET success_count = success_count + 1,
                            last_used = NOW(),
                            last_success = NOW()
                        WHERE id = $1
                        """,
                        proxy_id
                    )
                else:
                    # Get country code before updating
                    proxy = await conn.fetchrow(
                        "SELECT country_code FROM proxies WHERE id = $1",
                        proxy_id
                    )
                    
                    await conn.execute(
                        """
                        UPDATE proxies 
                        SET fail_count = fail_count + 1,
                            last_used = NOW(),
                            last_fail = NOW(),
                            is_active = CASE WHEN fail_count >= 3 THEN false ELSE is_active END
                        WHERE id = $1
                        """,
                        proxy_id
                    )
                    
                    # Invalidate cache for this country immediately on failure
                    if proxy and proxy['country_code']:
                        await self.invalidate_country_cache(proxy['country_code'])
                    
        except Exception as e:
            logger.error(f"❌ Error updating proxy status: {e}")
    
    def get_proxy_dict(self, proxy: ProxyInfo) -> Dict[str, Any]:
        """Convert ProxyInfo to Pyrogram proxy dict"""
        if not proxy:
            return None
        
        proxy_dict = {
            "scheme": proxy.protocol,
            "hostname": proxy.host,
            "port": proxy.port
        }
        
        if proxy.username and proxy.password:
            proxy_dict["username"] = proxy.username
            proxy_dict["password"] = proxy.password
        
        return proxy_dict
    
    async def get_proxy_for_phone(self, phone_number: str, country_code: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get appropriate proxy for phone number"""
        if country_code:
            target_country = self.normalize_country_code(country_code)
        else:
            target_country = self.extract_country_code(phone_number)
        
        if target_country == "UNKNOWN":
            logger.warning(f"⚠️ Unknown country code for phone: {phone_number}")
            return None
        
        proxies = await self.get_proxies_for_country(target_country)
        
        if not proxies:
            logger.warning(f"⚠️ No proxies available for country: {target_country}")
            return None
        
        proxy = random.choice(proxies)
        logger.info(f"🌍 Selected proxy for {target_country}: {proxy.host}:{proxy.port}")
        
        await self.update_proxy_status(proxy.id, True)
        
        return {
            "proxy_dict": self.get_proxy_dict(proxy),
            "proxy_info": proxy
        }

# ==================== TELEGRAM CLIENT MANAGER ====================
class TelegramClientManager:
    """Manage Pyrogram client instances for this worker"""
    
    def __init__(self, proxy_manager: ProxyManager):
        self.active_clients: Dict[str, Client] = {}
        self.session_data: Dict[str, Dict[str, Any]] = {}
        self.max_sessions = MAX_CONCURRENT_SESSIONS
        self.default_session_timeout = DEFAULT_SESSION_TIMEOUT
        self.cleanup_task: Optional[asyncio.Task] = None
        self.http_client = httpx.AsyncClient(timeout=10.0)
        self.proxy_manager = proxy_manager
        self.clients_lock = asyncio.Lock()
        self.session_lock = asyncio.Lock()
    
    async def start_background_cleanup(self):
        """Start background task to check for expired sessions"""
        self.cleanup_task = asyncio.create_task(self._cleanup_expired_sessions())
        logger.info("🔄 Background cleanup task started")
    
    async def _cleanup_expired_sessions(self):
        """Background task to clean up expired sessions every 60 seconds"""
        while True:
            try:
                await asyncio.sleep(60)  # Run every 60 seconds
                
                current_time = datetime.utcnow()
                expired_sessions = []
                
                async with self.session_lock:
                    for session_id, session_info in self.session_data.items():
                        created_at = session_info.get('created_at')
                        timeout_seconds = session_info.get('timeout_seconds', self.default_session_timeout)
                        
                        if created_at:
                            expiry_time = created_at + timedelta(seconds=timeout_seconds)
                            if current_time >= expiry_time:
                                expired_sessions.append(session_id)
                
                # Disconnect expired sessions
                for session_id in expired_sessions:
                    logger.info(f"⏰ Session {session_id} expired, disconnecting...")
                    await self.disconnect_client(session_id)
                    await self.notify_session_expired(session_id)
                    
            except asyncio.CancelledError:
                logger.info("🛑 Background cleanup task cancelled")
                break
            except Exception as e:
                logger.error(f"❌ Error in cleanup task: {e}")
    
    async def create_client(self, session_id: str, proxy: Optional[Dict[str, Any]] = None) -> Client:
        """Create a new Pyrogram client with optional proxy"""
        if len(self.active_clients) >= self.max_sessions:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Worker server is at maximum capacity"
            )
        
        try:
            session_name = f"worker_{WORKER_ID}_session_{session_id[:8]}"
            
            client_params = {
                "name": session_name,
                "api_id": TELEGRAM_API_ID,
                "api_hash": TELEGRAM_API_HASH,
                "in_memory": True,
                "workdir": "/tmp/telegram_sessions"
            }
            
            if proxy:
                client_params["proxy"] = proxy
                logger.info(f"🔄 Using proxy: {proxy.get('hostname', 'unknown')}:{proxy.get('port', 'unknown')}")
            
            client = Client(**client_params)
            
            await client.connect()
            
            async with self.clients_lock:
                self.active_clients[session_id] = client
            
            logger.info(f"✅ Telegram client created for session: {session_id}")
            return client
        except Exception as e:
            logger.error(f"❌ Error creating Telegram client: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create Telegram client"
            )
    
    async def request_otp(
        self, 
        session_id: str, 
        phone_number: str, 
        reject_2fa: bool = False, 
        timeout_seconds: Optional[int] = None,
        use_proxy: bool = False,
        country_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Send OTP to phone number with optional proxy support"""
        
        proxy_dict = None
        proxy_info = None
        
        if use_proxy:
            proxy_result = await self.proxy_manager.get_proxy_for_phone(phone_number, country_code)
            if proxy_result:
                proxy_dict = proxy_result["proxy_dict"]
                proxy_info = proxy_result["proxy_info"]
            else:
                logger.warning(f"⚠️ No proxy available for {phone_number}, continuing without proxy")
        
        client = await self.create_client(session_id, proxy_dict)
        
        try:
            sent_code = await client.send_code(phone_number)
            
            if timeout_seconds is None:
                timeout_seconds = self.default_session_timeout
            
            async with self.session_lock:
                self.session_data[session_id] = {
                    'phone_number': phone_number,
                    'phone_code_hash': sent_code.phone_code_hash,
                    'client': client,
                    'reject_2fa': reject_2fa,
                    'timeout_seconds': timeout_seconds,
                    'created_at': datetime.utcnow(),
                    'proxy_info': proxy_info,
                    'use_proxy': use_proxy
                }
            
            logger.info(f"✅ OTP sent to {phone_number} for session {session_id} (reject_2fa: {reject_2fa}, proxy: {use_proxy})")
            
            return {
                'success': True,
                'phone_code_hash': sent_code.phone_code_hash,
                'proxy_used': use_proxy and proxy_info is not None,
                'country_code': self.proxy_manager.extract_country_code(phone_number) if use_proxy else None
            }
        except PhoneNumberInvalid:
            await self.disconnect_client(session_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid phone number"
            )
        except PhoneNumberBanned:
            await self.disconnect_client(session_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This phone number is banned"
            )
        except FloodWait as e:
            await self.disconnect_client(session_id)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests. Please wait {e.value} seconds"
            )
        except Exception as e:
            await self.disconnect_client(session_id)
            logger.error(f"❌ Error sending OTP: {e}")
            
            if proxy_info:
                await self.proxy_manager.update_proxy_status(proxy_info.id, False)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to send OTP: {str(e)}"
            )
    
    async def verify_otp(self, session_id: str, otp_code: str) -> Dict[str, Any]:
        """Verify OTP code with immediate disconnect on failure"""
        client = None
        session_info = None
        
        async with self.clients_lock:
            client = self.active_clients.get(session_id)
        
        async with self.session_lock:
            session_info = self.session_data.get(session_id)
        
        if not client or not session_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or expired"
            )
        
        try:
            result = await client.sign_in(
                phone_number=session_info['phone_number'],
                phone_code_hash=session_info['phone_code_hash'],
                phone_code=otp_code
            )
            
            me = await client.get_me()
            user_info = {
                'id': me.id,
                'username': me.username,
                'first_name': me.first_name,
                'last_name': me.last_name
            }
            
            session_string = await client.export_session_string()
            
            if session_info.get('proxy_info'):
                await self.proxy_manager.update_proxy_status(session_info['proxy_info'].id, True)
            
            logger.info(f"✅ OTP verified for session {session_id} (no 2FA)")
            
            return {
                'success': True,
                'requires_2fa': False,
                'is_rejected': False,
                'session_string': session_string,
                'user_info': user_info
            }
        except SessionPasswordNeeded:
            if session_info.get('reject_2fa', False):
                logger.info(f"🔄 2FA account rejected for session {session_id}")
                await self.disconnect_client(session_id)
                
                return {
                    'success': False,
                    'requires_2fa': False,
                    'is_rejected': True,
                    'reject_reason': '2FA_ACCOUNT_REJECTED',
                    'message': 'Account has 2FA enabled. Rejected based on endpoint configuration'
                }
            else:
                logger.info(f"🔄 2FA required for session {session_id}")
                return {
                    'success': False,
                    'requires_2fa': True,
                    'is_rejected': False,
                    'message': '2FA_REQUIRED'
                }
        except PhoneCodeInvalid:
            logger.warning(f"⚠️ Invalid OTP code for session {session_id}, disconnecting...")
            await self.disconnect_client(session_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP code"
            )
        except PhoneCodeExpired:
            logger.warning(f"⚠️ Expired OTP code for session {session_id}, disconnecting...")
            await self.disconnect_client(session_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP code has expired"
            )
        except Exception as e:
            logger.error(f"❌ Error verifying OTP: {e}")
            
            if session_info.get('proxy_info'):
                await self.proxy_manager.update_proxy_status(session_info['proxy_info'].id, False)
            
            await self.disconnect_client(session_id)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify OTP"
            )
    
    async def verify_2fa(self, session_id: str, password: str) -> Dict[str, Any]:
        """Verify 2FA password with immediate disconnect on failure"""
        client = None
        session_info = None
        
        async with self.clients_lock:
            client = self.active_clients.get(session_id)
        
        async with self.session_lock:
            session_info = self.session_data.get(session_id)
        
        if not client:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or expired"
            )
        
        try:
            await client.check_password(password)
            
            me = await client.get_me()
            user_info = {
                'id': me.id,
                'username': me.username,
                'first_name': me.first_name,
                'last_name': me.last_name
            }
            
            session_string = await client.export_session_string()
            
            if session_info and session_info.get('proxy_info'):
                await self.proxy_manager.update_proxy_status(session_info['proxy_info'].id, True)
            
            logger.info(f"✅ 2FA verified for session {session_id}")
            
            return {
                'success': True,
                'session_string': session_string,
                'user_info': user_info
            }
        except PasswordHashInvalid:
            logger.warning(f"⚠️ Invalid 2FA password for session {session_id}, disconnecting...")
            await self.disconnect_client(session_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid 2FA password"
            )
        except Exception as e:
            logger.error(f"❌ Error verifying 2FA: {e}")
            
            if session_info and session_info.get('proxy_info'):
                await self.proxy_manager.update_proxy_status(session_info['proxy_info'].id, False)
            
            await self.disconnect_client(session_id)
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify 2FA"
            )
    
    async def disconnect_client(self, session_id: str) -> None:
        """Disconnect and remove client with proper locking"""
        client = None
        
        async with self.clients_lock:
            client = self.active_clients.get(session_id)
            if client:
                self.active_clients.pop(session_id, None)
        
        async with self.session_lock:
            self.session_data.pop(session_id, None)
        
        if client:
            try:
                await client.disconnect()
                logger.info(f"✅ Client disconnected: {session_id}")
            except Exception as e:
                logger.warning(f"⚠️ Error disconnecting client: {e}")
    
    async def notify_session_expired(self, session_id: str) -> None:
        """Notify Main Server about session expiry"""
        try:
            response = await self.http_client.post(
                f"{MAIN_SERVER_URL}/worker/session-expired",
                json={"session_id": session_id},
                headers={"X-API-Key": API_KEY}
            )
            if response.status_code == 200:
                logger.info(f"📤 Expiry notification sent to Main Server: {session_id}")
            else:
                logger.warning(f"⚠️ Failed to notify Main Server: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Error notifying Main Server: {e}")
    
    async def cleanup_all(self):
        """Cleanup all clients"""
        for session_id in list(self.active_clients.keys()):
            await self.disconnect_client(session_id)
        await self.http_client.aclose()
        logger.info("✅ All clients cleaned up")

# ==================== AUTHENTICATION ====================
async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    """Verify API key for authentication"""
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    return x_api_key

async def verify_admin_api_key(x_admin_api_key: str = Header(..., alias="X-Admin-API-Key")):
    """Verify admin API key for admin endpoints"""
    if x_admin_api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API key"
        )
    return x_admin_api_key

# ==================== PROXY TESTING FUNCTION ====================
async def test_proxy_ping(proxy: ProxyInfo) -> Dict[str, Any]:
    """Test proxy ping using HTTP request"""
    try:
        start_time = datetime.utcnow()
        
        proxy_url = f"{proxy.protocol}://"
        if proxy.username and proxy.password:
            proxy_url += f"{proxy.username}:{proxy.password}@"
        proxy_url += f"{proxy.host}:{proxy.port}"
        
        async with httpx.AsyncClient(proxies=proxy_url, timeout=5.0) as client:
            response = await client.get("http://www.gstatic.com/generate_204")
            
            end_time = datetime.utcnow()
            ping_ms = (end_time - start_time).total_seconds() * 1000
            
            return {
                "success": True,
                "ping_ms": round(ping_ms, 2),
                "status_code": response.status_code
            }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "ping_ms": None
        }

# ==================== FASTAPI APPLICATION ====================
proxy_manager = ProxyManager()
telegram_manager = TelegramClientManager(proxy_manager)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info(f"🚀 Starting Worker Server (ID: {WORKER_ID})...")
    logger.info(f"📊 Max concurrent sessions: {MAX_CONCURRENT_SESSIONS}")
    
    await proxy_manager.initialize()
    
    # Start background cleanup task
    await telegram_manager.start_background_cleanup()
    
    yield
    
    logger.info("🔧 Cleaning up...")
    
    # Cancel background tasks
    if telegram_manager.cleanup_task:
        telegram_manager.cleanup_task.cancel()
        try:
            await telegram_manager.cleanup_task
        except asyncio.CancelledError:
            pass
    
    await telegram_manager.cleanup_all()
    await proxy_manager.close()
    logger.info("✅ Shutdown complete")

app = FastAPI(
    title=f"Telegram Authentication Worker - {WORKER_ID}",
    description="Worker server for Telegram authentication operations with proxy support",
    version="4.1.0",
    lifespan=lifespan
)

# ==================== WORKER ENDPOINTS ====================

@app.post("/worker/request-otp")
async def worker_request_otp(request: WorkerOTPRequest, api_key: str = Depends(verify_api_key)):
    """Worker endpoint to request OTP with proxy support"""
    try:
        result = await telegram_manager.request_otp(
            request.session_id,
            request.phone_number,
            request.reject_2fa,
            request.timeout_seconds,
            request.use_proxy,
            request.country_code
        )
        
        return {
            "success": True,
            "message": "OTP sent successfully",
            "data": result
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in worker_request_otp: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal worker error"
        )

@app.post("/worker/verify-otp")
async def worker_verify_otp(request: WorkerVerifyOTP, api_key: str = Depends(verify_api_key)):
    """Worker endpoint to verify OTP with 2FA rejection support"""
    try:
        result = await telegram_manager.verify_otp(
            request.session_id,
            request.otp_code
        )
        
        # Disconnect client if authentication successful or rejected
        if not result.get('requires_2fa'):
            await telegram_manager.disconnect_client(request.session_id)
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in worker_verify_otp: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal worker error"
        )

@app.post("/worker/verify-2fa")
async def worker_verify_2fa(request: WorkerVerify2FA, api_key: str = Depends(verify_api_key)):
    """Worker endpoint to verify 2FA"""
    try:
        result = await telegram_manager.verify_2fa(
            request.session_id,
            request.password
        )
        
        # Disconnect client after successful authentication
        await telegram_manager.disconnect_client(request.session_id)
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in worker_verify_2fa: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal worker error"
        )

@app.get("/worker/proxies")
async def get_available_proxies(country_code: Optional[str] = None, api_key: str = Depends(verify_api_key)):
    """Get available proxies (for monitoring)"""
    try:
        if country_code:
            proxies = await proxy_manager.get_proxies_for_country(country_code)
        else:
            all_proxies = []
            for cached_proxies in proxy_manager.proxy_cache.values():
                all_proxies.extend(cached_proxies)
            proxies = all_proxies
        
        return {
            "success": True,
            "total_proxies": len(proxies),
            "proxies": [
                {
                    "id": p.id,
                    "host": p.host,
                    "port": p.port,
                    "country_code": p.country_code,
                    "country_name": p.country_name,
                    "protocol": p.protocol,
                    "is_active": p.is_active,
                    "username": p.username,  # Added for debugging
                    "ping_ms": getattr(p, 'ping_ms', None)  # Added if available
                }
                for p in proxies[:20]
            ]
        }
    except Exception as e:
        logger.error(f"❌ Error getting proxies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get proxy information"
        )

@app.get("/worker/health")
async def worker_health(api_key: str = Depends(verify_api_key)):
    """Worker health check endpoint with cleanup status"""
    return {
        "status": "healthy",
        "worker_id": WORKER_ID,
        "active_sessions": len(telegram_manager.active_clients),
        "max_sessions": telegram_manager.max_sessions,
        "load_percentage": (len(telegram_manager.active_clients) / telegram_manager.max_sessions) * 100,
        "default_session_timeout": telegram_manager.default_session_timeout,
        "database_connected": proxy_manager.pool is not None,
        "proxy_cache_size": sum(len(v) for v in proxy_manager.proxy_cache.values()),
        "cleanup_task_running": telegram_manager.cleanup_task is not None and not telegram_manager.cleanup_task.done(),
        "background_tasks": {
            "cleanup_active": telegram_manager.cleanup_task is not None,
            "cleanup_running": telegram_manager.cleanup_task is not None and not telegram_manager.cleanup_task.done()
        }
    }

@app.get("/health")
async def health_check():
    """Public health check endpoint"""
    return {
        "status": "healthy",
        "worker_id": WORKER_ID,
        "service": "Telegram Authentication Worker",
        "version": "4.1.0",
        "database_connected": proxy_manager.pool is not None
    }

# ==================== ADMIN ENDPOINTS ====================

@app.post("/admin/proxies/add")
async def admin_add_proxies(
    request: AdminProxyAddRequest,
    admin_api_key: str = Depends(verify_admin_api_key)
):
    """Admin endpoint to add multiple proxies"""
    if not proxy_manager.pool:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not connected"
        )
    
    added_count = 0
    failed_proxies = []
    
    try:
        async with proxy_manager.pool.acquire() as conn:
            for proxy in request.proxies:
                try:
                    # Build proxy_data JSON
                    proxy_data = {
                        "host": proxy.host,
                        "port": proxy.port,
                        "username": proxy.username,
                        "password": proxy.password,
                        "protocol": proxy.protocol,
                        "country_name": proxy.country_name
                    }
                    
                    # Check for duplicates
                    existing = await conn.fetchrow(
                        """
                        SELECT id FROM proxies 
                        WHERE proxy_data->>'host' = $1 
                        AND (proxy_data->>'port')::int = $2
                        """,
                        proxy.host, proxy.port
                    )
                    
                    if existing:
                        failed_proxies.append({
                            "host": proxy.host,
                            "port": proxy.port,
                            "reason": "duplicate"
                        })
                        continue
                    
                    # Insert new proxy with JSONB data
                    # Convert dict to JSON string for asyncpg
                    import json
                    proxy_data_json = json.dumps(proxy_data)
                    
                    await conn.execute(
                        """
                        INSERT INTO proxies 
                        (proxy_data, country_code, is_active, max_usage, current_usage)
                        VALUES ($1::jsonb, $2, true, $3, 0)
                        """,
                        proxy_data_json,
                        proxy.country_code,
                        proxy.max_sessions if hasattr(proxy, 'max_sessions') else 10
                    )
                    added_count += 1
                    logger.info(f"✅ Added proxy: {proxy.host}:{proxy.port} ({proxy.country_code})")
                    
                except Exception as e:
                    failed_proxies.append({
                        "host": proxy.host,
                        "port": proxy.port,
                        "reason": str(e)
                    })
        
        # Invalidate cache after adding new proxies
        async with proxy_manager.cache_lock:
            proxy_manager.proxy_cache.clear()
            proxy_manager.cache_timestamp.clear()
        
        return {
            "success": True,
            "added_count": added_count,
            "failed_count": len(failed_proxies),
            "failed_proxies": failed_proxies
        }
        
    except Exception as e:
        logger.error(f"❌ Error adding proxies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add proxies"
        )

@app.post("/admin/proxies/check")
async def admin_check_proxies(
    request: AdminProxyCheckRequest,
    admin_api_key: str = Depends(verify_admin_api_key)
):
    """Admin endpoint to ping test proxies and get ranking"""
    if not proxy_manager.pool:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not connected"
        )
    
    try:
        # Build query based on request - using proxy_data JSONB
        query = """
            SELECT id, proxy_data, country_code, is_active, ping_ms
            FROM proxies 
            WHERE is_active = true
        """
        params = []
        
        if request.country_codes:
            placeholders = ', '.join([f'${i+1}' for i in range(len(request.country_codes))])
            query += f" AND country_code IN ({placeholders})"
            params.extend(request.country_codes)
        
        query += " ORDER BY ping_ms ASC NULLS LAST LIMIT $"+str(len(params)+1)
        params.append(request.limit or 10)
        
        async with proxy_manager.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
        
        # Test each proxy
        tested_proxies = []
        for row in rows:
            proxy_data = row['proxy_data']
            proxy = ProxyInfo(
                id=row['id'],
                host=proxy_data.get('host', ''),
                port=proxy_data.get('port', 0),
                username=proxy_data.get('username'),
                password=proxy_data.get('password'),
                country_code=row['country_code'],
                country_name=proxy_data.get('country_name', ''),
                protocol=proxy_data.get('protocol', 'socks5'),
                is_active=row['is_active']
            )
            
            # Test proxy ping
            ping_result = await test_proxy_ping(proxy)
            
            # Update database with ping time
            if ping_result['success']:
                async with proxy_manager.pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE proxies SET ping_ms = $1 WHERE id = $2",
                        ping_result['ping_ms'], proxy.id
                    )
            
            tested_proxies.append({
                "proxy": proxy,
                "ping_result": ping_result
            })
        
        # Sort by ping time
        tested_proxies.sort(key=lambda x: x['ping_result'].get('ping_ms', float('inf')))
        
        return {
            "success": True,
            "total_tested": len(tested_proxies),
            "proxies": [
                {
                    "id": item['proxy'].id,
                    "host": item['proxy'].host,
                    "port": item['proxy'].port,
                    "country_code": item['proxy'].country_code,
                    "country_name": item['proxy'].country_name,
                    "protocol": item['proxy'].protocol,
                    "ping_ms": item['ping_result'].get('ping_ms'),
                    "is_alive": item['ping_result'].get('success', False),
                    "response_time_ms": item['ping_result'].get('ping_ms'),
                    "error": item['ping_result'].get('error')
                }
                for item in tested_proxies
            ]
        }
        
    except Exception as e:
        logger.error(f"❌ Error checking proxies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check proxies"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        reload=False
    )
