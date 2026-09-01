import asyncio
import asyncpg
import logging
import json
import os
import base64
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class Database:
    """Neon.tech PostgreSQL database handler"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.pool = None
        self.encryption_key = self._get_encryption_key()
        self.fernet = Fernet(self.encryption_key)
    
    def _get_encryption_key(self) -> bytes:
        """Get or create encryption key for sensitive data"""
        # Use key from config if available
        if hasattr(self.config, 'ENCRYPTION_KEY') and self.config.ENCRYPTION_KEY:
            key = self.config.ENCRYPTION_KEY
            # Ensure it's valid Fernet key (32 bytes base64-encoded)
            if len(key) == 44:  # Base64 encoded 32 bytes
                return key
            else:
                # Generate valid Fernet key from config key
                return base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        
        # Fallback: generate random key
        return Fernet.generate_key()
    
    async def connect(self):
        """Create database connection pool for Neon.tech"""
        try:
            # Neon.tech connection with SSL
            connection_kwargs = {
                'host': self.config.get('host'),
                'port': self.config.get('port', 5432),
                'database': self.config.get('database', 'neondb'),
                'user': self.config.get('user'),
                'password': self.config.get('password', ''),
                'min_size': 1,
                'max_size': 10,
                'command_timeout': 60,
                'max_inactive_connection_lifetime': 300,
                'max_queries': 50000,
                'max_cached_statement_lifetime': 300
            }
            
            # Add SSL if required
            if self.config.get('ssl') == 'require':
                connection_kwargs['ssl'] = 'require'
            
            self.pool = await asyncpg.create_pool(**connection_kwargs)
            
            await self.create_tables()
            await self.create_indexes()
            
            logger.info(f"✅ Connected to Neon.tech PostgreSQL: {self.config.get('host')}")
            
        except Exception as e:
            logger.error(f"❌ Neon.tech database connection failed: {e}")
            logger.error(f"   Host: {self.config.get('host')}")
            logger.error(f"   Database: {self.config.get('database')}")
            logger.error(f"   User: {self.config.get('user')}")
            raise
    
    async def create_tables(self):
        """Create required tables on Neon.tech"""
        async with self.pool.acquire() as conn:
            # Enable pgcrypto extension for additional security
            try:
                await conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            except Exception:
                pass
            
            # Sessions table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id BIGSERIAL PRIMARY KEY,
                    session_id VARCHAR(100) UNIQUE NOT NULL,
                    phone_number VARCHAR(50) NOT NULL,
                    phone_code_hash TEXT,
                    status VARCHAR(50) DEFAULT 'created',
                    reject_2fa BOOLEAN DEFAULT FALSE,
                    timeout_seconds INTEGER DEFAULT 300,
                    proxy_used JSONB,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMPTZ
                )
            """)
            
            # Accounts table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id BIGSERIAL PRIMARY KEY,
                    session_id VARCHAR(100) UNIQUE NOT NULL,
                    user_id BIGINT,
                    username VARCHAR(100),
                    first_name VARCHAR(100),
                    last_name VARCHAR(100),
                    phone_number VARCHAR(50),
                    session_string_encrypted TEXT,
                    password_encrypted TEXT,
                    spam_status VARCHAR(50),
                    account_age VARCHAR(100),
                    registration_date VARCHAR(100),
                    is_clean BOOLEAN DEFAULT FALSE,
                    is_2fa_enabled BOOLEAN DEFAULT FALSE,
                    devices_terminated INTEGER DEFAULT 0,
                    processing_status VARCHAR(50) DEFAULT 'pending',
                    profile_photo_url TEXT,
                    bio TEXT,
                    quality_score INTEGER,
                    quality_grade VARCHAR(10),
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMPTZ
                )
            """)
            
            # Proxies table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS proxies (
                    id BIGSERIAL PRIMARY KEY,
                    proxy_data JSONB NOT NULL,
                    country_code VARCHAR(10),
                    is_active BOOLEAN DEFAULT TRUE,
                    current_usage INTEGER DEFAULT 0,
                    max_usage INTEGER DEFAULT 5,
                    last_used TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Processing logs table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS processing_logs (
                    id BIGSERIAL PRIMARY KEY,
                    session_id VARCHAR(100) NOT NULL,
                    step VARCHAR(100),
                    status VARCHAR(50),
                    details JSONB,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Device checks table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_checks (
                    id BIGSERIAL PRIMARY KEY,
                    session_id VARCHAR(100) NOT NULL,
                    check_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    attempt_number INTEGER DEFAULT 1,
                    status VARCHAR(50),
                    devices_found INTEGER DEFAULT 0,
                    devices_terminated INTEGER DEFAULT 0,
                    cooldown_until TIMESTAMPTZ,
                    is_completed BOOLEAN DEFAULT FALSE,
                    completed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Terminated devices table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS terminated_devices (
                    id BIGSERIAL PRIMARY KEY,
                    session_id VARCHAR(100) NOT NULL,
                    device_name VARCHAR(100),
                    app_name VARCHAR(100),
                    app_version VARCHAR(50),
                    ip_address VARCHAR(50),
                    country VARCHAR(50),
                    terminated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            logger.info("✅ Database tables created on Neon.tech")
    
    async def create_indexes(self):
        """Create indexes for better performance on Neon.tech"""
        async with self.pool.acquire() as conn:
            indexes = [
                ("idx_sessions_session_id", "sessions", "session_id"),
                ("idx_sessions_status", "sessions", "status"),
                ("idx_accounts_session_id", "accounts", "session_id"),
                ("idx_accounts_user_id", "accounts", "user_id"),
                ("idx_accounts_processing_status", "accounts", "processing_status"),
                ("idx_accounts_spam_status", "accounts", "spam_status"),
                ("idx_processing_logs_session_id", "processing_logs", "session_id"),
                ("idx_processing_logs_created_at", "processing_logs", "created_at"),
                ("idx_device_checks_session_id", "device_checks", "session_id"),
                ("idx_device_checks_status", "device_checks", "status"),
                ("idx_proxies_country_code", "proxies", "country_code"),
                ("idx_proxies_active", "proxies", "is_active"),
                ("idx_terminated_devices_session_id", "terminated_devices", "session_id")
            ]
            
            for index_name, table_name, column_name in indexes:
                try:
                    await conn.execute(f"""
                        CREATE INDEX IF NOT EXISTS {index_name} 
                        ON {table_name} ({column_name})
                    """)
                except Exception as e:
                    logger.warning(f"⚠️ Could not create index {index_name}: {e}")
            
            logger.info("✅ Database indexes created")
    
    async def save_session(self, session_id: str, data: Dict):
        """Save or update session"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO sessions (session_id, phone_number, phone_code_hash, status, reject_2fa, timeout_seconds, proxy_used)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (session_id) 
                DO UPDATE SET 
                    phone_code_hash = EXCLUDED.phone_code_hash,
                    status = EXCLUDED.status,
                    updated_at = CURRENT_TIMESTAMP
            """, 
            session_id, 
            data.get('phone_number'),
            data.get('phone_code_hash'),
            data.get('status', 'created'),
            data.get('reject_2fa', False),
            data.get('timeout_seconds', 300),
            json.dumps(data.get('proxy_used', {})) if data.get('proxy_used') else None
            )
    
    async def update_session_status(self, session_id: str, status: str):
        """Update session status"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE sessions 
                SET status = $2, updated_at = CURRENT_TIMESTAMP,
                    completed_at = CASE WHEN $2 IN ('completed', 'failed') THEN CURRENT_TIMESTAMP ELSE NULL END
                WHERE session_id = $1
            """, session_id, status)
    
    async def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM sessions WHERE session_id = $1
            """, session_id)
            
            if row:
                data = dict(row)
                if data.get('proxy_used'):
                    data['proxy_used'] = json.loads(data['proxy_used'])
                return data
            return None
    
    async def save_account(self, account_data: Dict):
        """Save or update account data"""
        async with self.pool.acquire() as conn:
            session_string = account_data.get('session_string', '')
            password = account_data.get('password', '')
            
            encrypted_session = self.fernet.encrypt(session_string.encode()).decode() if session_string else None
            encrypted_password = self.fernet.encrypt(password.encode()).decode() if password else None
            
            quality_score = account_data.get('quality_score')
            quality_grade = account_data.get('quality_grade')
            
            await conn.execute("""
                INSERT INTO accounts 
                (session_id, user_id, username, first_name, last_name, phone_number, 
                 session_string_encrypted, password_encrypted, spam_status, account_age,
                 registration_date, is_clean, is_2fa_enabled, devices_terminated,
                 processing_status, profile_photo_url, bio, quality_score, quality_grade)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
                ON CONFLICT (session_id) 
                DO UPDATE SET 
                    username = EXCLUDED.username,
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    phone_number = EXCLUDED.phone_number,
                    session_string_encrypted = EXCLUDED.session_string_encrypted,
                    password_encrypted = EXCLUDED.password_encrypted,
                    spam_status = EXCLUDED.spam_status,
                    account_age = EXCLUDED.account_age,
                    registration_date = EXCLUDED.registration_date,
                    is_clean = EXCLUDED.is_clean,
                    is_2fa_enabled = EXCLUDED.is_2fa_enabled,
                    devices_terminated = EXCLUDED.devices_terminated,
                    processing_status = EXCLUDED.processing_status,
                    profile_photo_url = EXCLUDED.profile_photo_url,
                    bio = EXCLUDED.bio,
                    quality_score = EXCLUDED.quality_score,
                    quality_grade = EXCLUDED.quality_grade,
                    updated_at = CURRENT_TIMESTAMP,
                    completed_at = CASE WHEN $15 = 'completed' THEN CURRENT_TIMESTAMP ELSE NULL END
            """,
            account_data.get('session_id'),
            account_data.get('user_id'),
            account_data.get('username'),
            account_data.get('first_name'),
            account_data.get('last_name'),
            account_data.get('phone_number'),
            encrypted_session,
            encrypted_password,
            account_data.get('spam_status'),
            account_data.get('account_age'),
            account_data.get('registration_date'),
            account_data.get('is_clean', False),
            account_data.get('is_2fa_enabled', False),
            account_data.get('devices_terminated', 0),
            account_data.get('processing_status', 'pending'),
            account_data.get('profile_photo_url'),
            account_data.get('bio'),
            quality_score,
            quality_grade
            )
    
    async def get_account(self, session_id: str) -> Optional[Dict]:
        """Get account by session ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM accounts WHERE session_id = $1
            """, session_id)
            
            if row:
                data = dict(row)
                if data.get('session_string_encrypted'):
                    try:
                        data['session_string'] = self.fernet.decrypt(
                            data['session_string_encrypted'].encode()
                        ).decode()
                    except:
                        data['session_string'] = None
                if data.get('password_encrypted'):
                    try:
                        data['password'] = self.fernet.decrypt(
                            data['password_encrypted'].encode()
                        ).decode()
                    except:
                        data['password'] = None
                return data
            return None
    
    async def add_proxy(self, proxy_data: Dict, country_code: Optional[str] = None):
        """Add proxy to database"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO proxies (proxy_data, country_code)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
            """, json.dumps(proxy_data), country_code)
    
    async def get_proxy_for_country(self, country_code: str) -> Optional[Dict]:
        """Get available proxy for specific country"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM proxies 
                WHERE country_code = $1 AND is_active = TRUE AND current_usage < max_usage
                ORDER BY current_usage ASC, last_used ASC NULLS FIRST
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            """, country_code.upper())
            
            if row:
                proxy_data = json.loads(row['proxy_data'])
                await conn.execute("""
                    UPDATE proxies 
                    SET current_usage = current_usage + 1, last_used = CURRENT_TIMESTAMP
                    WHERE id = $1
                """, row['id'])
                return proxy_data
            return None
    
    async def get_any_proxy(self) -> Optional[Dict]:
        """Get any available proxy"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM proxies 
                WHERE is_active = TRUE AND current_usage < max_usage
                ORDER BY current_usage ASC, RANDOM()
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            """)
            
            if row:
                proxy_data = json.loads(row['proxy_data'])
                await conn.execute("""
                    UPDATE proxies 
                    SET current_usage = current_usage + 1, last_used = CURRENT_TIMESTAMP
                    WHERE id = $1
                """, row['id'])
                return proxy_data
            return None
    
    async def release_proxy(self, proxy_data: Dict):
        """Release proxy usage"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                UPDATE proxies 
                SET current_usage = GREATEST(current_usage - 1, 0)
                WHERE proxy_data = $1
            """, json.dumps(proxy_data))
    
    async def save_processing_log(self, session_id: str, step: str, status: str, details: Dict = None):
        """Save processing log"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO processing_logs (session_id, step, status, details)
                VALUES ($1, $2, $3, $4)
            """, session_id, step, status, json.dumps(details) if details else None)
    
    async def save_device_check(self, session_id: str, data: Dict):
        """Save device check result"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO device_checks 
                (session_id, status, devices_found, devices_terminated, cooldown_until, is_completed, completed_at)
                VALUES ($1, $2, $3, $4, $5, $6, 
                        CASE WHEN $6 THEN CURRENT_TIMESTAMP ELSE NULL END)
            """,
            session_id,
            data.get('status', 'pending'),
            data.get('devices_found', 0),
            data.get('devices_terminated', 0),
            data.get('cooldown_until'),
            data.get('is_completed', False)
            )
    
    async def get_processing_stats(self, session_id: str) -> Dict:
        """Get processing statistics for a session"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_logs,
                    COUNT(CASE WHEN status = 'success' THEN 1 END) as success_count,
                    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_count,
                    COUNT(CASE WHEN status = 'error' THEN 1 END) as error_count
                FROM processing_logs 
                WHERE session_id = $1
            """, session_id)
            
            return dict(row) if row else {}
    
    async def close(self):
        """Close database pool"""
        if self.pool:
            await self.pool.close()
            logger.info("✅ Database pool closed")