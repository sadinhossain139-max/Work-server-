from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field, validator
from datetime import datetime

class WorkerOTPRequest(BaseModel):
    session_id: str
    phone_number: str
    reject_2fa: bool = Field(False, description="Reject if account has 2FA")
    timeout_seconds: Optional[int] = Field(None, description="Custom session timeout in seconds")
    use_proxy: bool = Field(False, description="Use proxy for this request")
    country_code: Optional[str] = Field(None, description="Country code for proxy selection")
    reject_2fa: bool = Field(False)

class WorkerVerifyOTP(BaseModel):
    session_id: str
    otp_code: str

class WorkerVerify2FA(BaseModel):
    session_id: str
    password: str
    new_password: Optional[str] = Field(None, description="New password to set after verification")
    profile_config: Optional[Dict[str, Any]] = Field(None, description="Profile configuration")
    
class ProfileConfig(BaseModel):
    """Profile configuration for account setup"""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None
    photo_url: Optional[str] = None
    username: Optional[str] = None
    watermark: Optional[str] = None
    generate_name: bool = Field(True, description="Generate name using Faker")
    
class AccountSetupRequest(BaseModel):
    """Request to setup account after verification"""
    session_id: str
    profile_config: Optional[ProfileConfig] = None
    new_password: str = Field(..., description="New 2FA password to set")
    perform_spam_check: bool = Field(True, description="Check spam status")
    perform_device_check: bool = Field(True, description="Check and terminate other devices")
    perform_cleanup: bool = Field(True, description="Clean account (leave groups, block bots)")
    
class AccountResult(BaseModel):
    """Result of account processing"""
    session_id: str
    success: bool
    user_info: Dict[str, Any]
    session_string: str
    password_set: bool
    profile_updated: Dict[str, Any]
    spam_status: Optional[str]
    account_age: Optional[str]
    devices_terminated: int
    is_clean: bool
    processing_status: str
    error: Optional[str] = None
    processing_details: Optional[Dict[str, Any]] = None