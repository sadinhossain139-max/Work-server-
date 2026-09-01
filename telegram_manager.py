import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pyrogram import Client
from pyrogram.errors import (
    SessionPasswordNeeded, PhoneCodeInvalid, PhoneCodeExpired,
    PasswordHashInvalid, FloodWait, PhoneNumberInvalid, PhoneNumberBanned
)
from fastapi import HTTPException, status
import httpx

logger = logging.getLogger(__name__)

class TelegramClientManager:
    """Manage Pyrogram client instances"""
    
    def __init__(self, config, database, proxy_manager):
        self.config = config
        self.database = database
        self.proxy_manager = proxy_manager
        self.active_clients: Dict[str, Client] = {}
        self.session_data: Dict[str, Dict[str, Any]] = {}
        self.processing_tasks: Dict[str, asyncio.Task] = {}
        self.http_client = httpx.AsyncClient(timeout=30.0)
    
    async def create_client(self, session_id: str, use_proxy: bool = False, country_code: Optional[str] = None) -> Client:
        """Create a new Pyrogram client"""
        if len(self.active_clients) >= self.config.MAX_CONCURRENT_SESSIONS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Worker server is at maximum capacity"
            )
        
        try:
            # Get proxy if needed
            proxy = None
            if use_proxy:
                proxy = await self.proxy_manager.get_proxy(country_code)
                if not proxy:
                    logger.warning(f"⚠️ No proxy available for session {session_id}")
            
            session_name = f"worker_{self.config.WORKER_ID}_session_{session_id[:8]}"
            
            client_kwargs = {
                'name': session_name,
                'api_id': self.config.TELEGRAM_API_ID,
                'api_hash': self.config.TELEGRAM_API_HASH,
                'in_memory': True,
                'workdir': "/tmp/telegram_sessions"
            }
            
            if proxy:
                client_kwargs['proxy'] = proxy
            
            client = Client(**client_kwargs)
            
            await client.connect()
            self.active_clients[session_id] = client
            
            # Store proxy info
            self.session_data.setdefault(session_id, {})['proxy'] = proxy
            self.session_data[session_id]['proxy_used'] = proxy is not None
            
            logger.info(f"✅ Telegram client created for session: {session_id} (proxy: {proxy is not None})")
            return client
            
        except Exception as e:
            logger.error(f"❌ Error creating Telegram client: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create Telegram client"
            )
    
    async def request_otp(self, request_data: Dict) -> Dict[str, Any]:
        """Send OTP to phone number"""
        session_id = request_data['session_id']
        phone_number = request_data['phone_number']
        reject_2fa = request_data.get('reject_2fa', False)
        use_proxy = request_data.get('use_proxy', False)
        country_code = request_data.get('country_code')
        timeout_seconds = request_data.get('timeout_seconds', self.config.DEFAULT_SESSION_TIMEOUT)
        
        client = await self.create_client(session_id, use_proxy, country_code)
        
        try:
            sent_code = await client.send_code(phone_number)
            
            # Store session data
            self.session_data[session_id].update({
                'phone_number': phone_number,
                'phone_code_hash': sent_code.phone_code_hash,
                'reject_2fa': reject_2fa,
                'timeout_seconds': timeout_seconds,
                'created_at': datetime.utcnow(),
                'use_proxy': use_proxy,
                'country_code': country_code
            })
            
            # Save to database
            await self.database.save_session(session_id, {
                'phone_number': phone_number,
                'phone_code_hash': sent_code.phone_code_hash,
                'status': 'otp_sent',
                'reject_2fa': reject_2fa,
                'timeout_seconds': timeout_seconds,
                'proxy_used': self.session_data[session_id].get('proxy')
            })
            
            await self.database.save_processing_log(session_id, 'request_otp', 'success', {
                'phone_number': phone_number
            })
            
            logger.info(f"✅ OTP sent to {phone_number} for session {session_id}")
            
            return {
                'success': True,
                'phone_code_hash': sent_code.phone_code_hash
            }
            
        except PhoneNumberInvalid:
            await self.disconnect_client(session_id)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid phone number")
        except PhoneNumberBanned:
            await self.disconnect_client(session_id)
            raise HTTPException(status.HTTP_403_FORBIDDEN, "This phone number is banned")
        except FloodWait as e:
            await self.disconnect_client(session_id)
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, f"Too many requests. Wait {e.value} seconds")
        except Exception as e:
            await self.disconnect_client(session_id)
            logger.error(f"❌ Error sending OTP: {e}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to send OTP")
    
    async def verify_otp(self, session_id: str, otp_code: str) -> Dict[str, Any]:
        """Verify OTP code"""
        client = self.active_clients.get(session_id)
        session_info = self.session_data.get(session_id)
        
        if not client or not session_info:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found or expired")
        
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
                'last_name': me.last_name,
                'phone_number': me.phone_number
            }
            
            session_string = await client.export_session_string()
            
            await self.database.save_processing_log(session_id, 'verify_otp', 'success', user_info)
            
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
                    'message': 'Account has 2FA enabled. Rejected based on configuration'
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
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OTP code")
        except PhoneCodeExpired:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP code has expired")
        except Exception as e:
            logger.error(f"❌ Error verifying OTP: {e}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to verify OTP")
    
    async def verify_2fa(self, session_id: str, password: str) -> Dict[str, Any]:
        """Verify 2FA password"""
        client = self.active_clients.get(session_id)
        
        if not client:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Session not found or expired")
        
        try:
            await client.check_password(password)
            
            me = await client.get_me()
            user_info = {
                'id': me.id,
                'username': me.username,
                'first_name': me.first_name,
                'last_name': me.last_name,
                'phone_number': me.phone_number
            }
            
            session_string = await client.export_session_string()
            
            await self.database.save_processing_log(session_id, 'verify_2fa', 'success', user_info)
            
            logger.info(f"✅ 2FA verified for session {session_id}")
            
            return {
                'success': True,
                'session_string': session_string,
                'user_info': user_info
            }
            
        except PasswordHashInvalid:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid 2FA password")
        except Exception as e:
            logger.error(f"❌ Error verifying 2FA: {e}")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to verify 2FA")
    
    async def disconnect_client(self, session_id: str) -> None:
        """Disconnect and remove client"""
        client = self.active_clients.get(session_id)
        if client:
            try:
                await client.disconnect()
                logger.info(f"✅ Client disconnected: {session_id}")
            except Exception as e:
                logger.warning(f"⚠️ Error disconnecting client: {e}")
            finally:
                self.active_clients.pop(session_id, None)
                
                # Release proxy
                proxy = self.session_data.get(session_id, {}).get('proxy')
                if proxy:
                    await self.proxy_manager.release_proxy(proxy)
                
                self.session_data.pop(session_id, None)
    
    async def notify_main_server(self, endpoint: str, data: Dict) -> bool:
        """Send notification to main server"""
        try:
            response = await self.http_client.post(
                f"{self.config.MAIN_SERVER_URL}{endpoint}",
                json=data,
                headers={"X-API-Key": self.config.API_KEY}
            )
            if response.status_code == 200:
                logger.info(f"📤 Notification sent to Main Server: {endpoint}")
                return True
            else:
                logger.warning(f"⚠️ Failed to notify Main Server: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"❌ Error notifying Main Server: {e}")
            return False
    
    async def cleanup_all(self):
        """Cleanup all clients"""
        for session_id in list(self.active_clients.keys()):
            await self.disconnect_client(session_id)
        
        # Cancel processing tasks
        for task in self.processing_tasks.values():
            task.cancel()
        
        await self.http_client.aclose()
        logger.info("✅ All clients cleaned up")