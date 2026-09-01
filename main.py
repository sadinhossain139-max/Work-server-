import asyncio
import logging
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status, Header, Depends, BackgroundTasks
from pyrogram import Client

from config import Config
from database import Database
from telegram_manager import TelegramClientManager
from proxy_manager import ProxyManager
from account_processor import AccountProcessor
from models import (
    WorkerOTPRequest, WorkerVerifyOTP, WorkerVerify2FA,
    AccountSetupRequest, ProfileConfig
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize components
config = Config()
database = Database(config.DB_CONFIG)
proxy_manager = ProxyManager(config, database)
telegram_manager = TelegramClientManager(config, database, proxy_manager)
account_processor = AccountProcessor(config, database, telegram_manager)

# ==================== AUTHENTICATION ====================
async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    """Verify API key for authentication"""
    if x_api_key != config.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    return x_api_key

# ==================== FASTAPI APPLICATION ====================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info(f"🚀 Starting Worker Server (ID: {config.WORKER_ID})...")
    
    # Initialize database
    await database.connect()
    
    # Initialize proxies
    await proxy_manager.initialize()
    
    logger.info(f"📊 Max concurrent sessions: {config.MAX_CONCURRENT_SESSIONS}")
    logger.info(f"🌐 Available proxies: {len(config.get_all_proxies())}")
    
    yield
    
    logger.info("🔧 Cleaning up...")
    await telegram_manager.cleanup_all()
    await account_processor.close()
    await database.close()
    logger.info("✅ Shutdown complete")

app = FastAPI(
    title=f"Telegram Authentication Worker - {config.WORKER_ID}",
    description="Worker server for Telegram authentication with full account processing",
    version="4.0.0",
    lifespan=lifespan
)

# ==================== WORKER ENDPOINTS ====================

@app.post("/worker/request-otp")
async def worker_request_otp(request: WorkerOTPRequest, api_key: str = Depends(verify_api_key)):
    """Worker endpoint to request OTP with proxy support"""
    try:
        result = await telegram_manager.request_otp(request.dict())
        
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
    """Worker endpoint to verify OTP"""
    try:
        result = await telegram_manager.verify_otp(
            request.session_id,
            request.otp_code
        )
        
        # If successful and no 2FA needed, disconnect client
        if result.get('success') and not result.get('requires_2fa'):
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
        if result.get('success'):
            await telegram_manager.disconnect_client(request.session_id)
        
        return result    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in worker_verify_2fa: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal worker error"
        )

@app.post("/worker/setup-account")
async def worker_setup_account(
    request: AccountSetupRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Setup account after successful verification (runs in background)
    """
    try:
        # Get session data
        session_data = await database.get_session(request.session_id)
        account_data = await database.get_account(request.session_id)
        
        if not session_data and not account_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found"
            )
        
        # Get session string and user info
        session_string = account_data.get('session_string') if account_data else None
        user_info = {
            'id': account_data.get('user_id') if account_data else None,
            'username': account_data.get('username') if account_data else None,
            'first_name': account_data.get('first_name') if account_data else None,
            'last_name': account_data.get('last_name') if account_data else None
        }
        
        if not session_string:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Session string not found. Account must be verified first."
            )
        
        # Get proxy if needed
        proxy = session_data.get('proxy_used') if session_data else None
        
        # Schedule background processing
        background_tasks.add_task(
            account_processor.process_account_background,
            session_id=request.session_id,
            session_string=session_string,
            user_info=user_info,
            profile_config=request.profile_config.dict() if request.profile_config else None,
            new_password=request.new_password,
            old_password=None,  # Will need to be provided if 2FA exists
            perform_spam_check=request.perform_spam_check,
            perform_device_check=request.perform_device_check,
            perform_cleanup=request.perform_cleanup,
            proxy=proxy
        )
        
        return {
            "success": True,
            "message": "Account setup started in background",
            "session_id": request.session_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in worker_setup_account: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal worker error"
        )

@app.post("/worker/complete-authentication")
async def worker_complete_authentication(
    request: Dict[str, Any],
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Complete authentication and start background processing
    This is called after successful OTP verification or 2FA verification
    """
    try:
        session_id = request.get('session_id')
        session_string = request.get('session_string')
        user_info = request.get('user_info', {})
        
        if not session_id or not session_string:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="session_id and session_string are required"
            )
        
        # Get profile config
        profile_config = request.get('profile_config')
        new_password = request.get('new_password')
        old_password = request.get('old_password')
        perform_spam_check = request.get('perform_spam_check', True)
        perform_device_check = request.get('perform_device_check', True)
        perform_cleanup = request.get('perform_cleanup', True)
        
        # Get proxy from session data
        session_data = await database.get_session(session_id)
        proxy = session_data.get('proxy_used') if session_data else None
        
        # Notify main server immediately that authentication is complete
        await telegram_manager.notify_main_server('/worker/auth-complete', {
            'session_id': session_id,
            'user_info': user_info
        })
        
        # Start background processing
        background_tasks.add_task(
            account_processor.process_account_background,
            session_id=session_id,
            session_string=session_string,
            user_info=user_info,
            profile_config=profile_config,
            new_password=new_password,
            old_password=old_password,
            perform_spam_check=perform_spam_check,
            perform_device_check=perform_device_check,
            perform_cleanup=perform_cleanup,
            proxy=proxy
        )
        
        return {
            "success": True,
            "message": "Authentication complete. Processing started in background.",
            "session_id": session_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in worker_complete_authentication: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal worker error"
        )

@app.get("/worker/health")
async def worker_health(api_key: str = Depends(verify_api_key)):
    """Worker health check endpoint"""
    return {
        "status": "healthy",
        "worker_id": config.WORKER_ID,
        "active_sessions": len(telegram_manager.active_clients),
        "max_sessions": config.MAX_CONCURRENT_SESSIONS,
        "load_percentage": (len(telegram_manager.active_clients) / config.MAX_CONCURRENT_SESSIONS) * 100,
        "default_session_timeout": config.DEFAULT_SESSION_TIMEOUT,
        "active_proxies": proxy_manager.get_active_proxy_count(),
        "available_proxies": proxy_manager.get_available_proxy_count(),
        "processing_tasks": len(telegram_manager.processing_tasks)
    }

@app.get("/health")
async def health_check():
    """Public health check endpoint"""
    return {
        "status": "healthy",
        "worker_id": config.WORKER_ID,
        "service": "Telegram Authentication Worker",
        "version": "4.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8001,
        reload=False
    )