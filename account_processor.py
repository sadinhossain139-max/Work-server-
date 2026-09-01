import asyncio
import logging
import random
import string
import re
import aiohttp
import aiofiles
import os
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from io import BytesIO

from pyrogram import Client
from pyrogram.errors import (
    FloodWait, 
    SessionPasswordNeeded,
    PasswordHashInvalid,
    UsernameNotModified,
    UsernameInvalid,
    UsernameOccupied,
    PhotoInvalidDimensions,
    FilePartMissing
)
from faker import Faker
from PIL import Image

logger = logging.getLogger(__name__)

class AccountProcessor:
    """Handle all account processing operations"""
    
    def __init__(self, config, database, telegram_manager):
        self.config = config
        self.database = database
        self.telegram_manager = telegram_manager
        self.faker = Faker()
        self.http_client = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60))
        
        # Temporary directory for profile photos
        self.temp_dir = Path("/tmp/profile_photos")
        self.temp_dir.mkdir(exist_ok=True)
    
    async def process_account_background(self, session_id: str, session_string: str, 
                                        user_info: Dict, profile_config: Optional[Dict] = None,
                                        new_password: Optional[str] = None,
                                        old_password: Optional[str] = None,
                                        perform_spam_check: bool = True,
                                        perform_device_check: bool = True,
                                        perform_cleanup: bool = True,
                                        proxy: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Process account in background after successful authentication
        
        Steps:
        1. Set/Change 2FA password
        2. Update profile (photo, name, bio)
        3. Set username
        4. Check spam status
        5. Check account age
        6. Clean account (leave groups, block bots)
        7. Check devices
        8. Calculate quality score
        """
        
        processing_details = {}
        client = None
        
        try:
            # Create client from session string
            client = await self._create_client_from_session(session_id, session_string, proxy)
            
            if not client:
                raise Exception("Failed to create client from session string")
            
            async with client:
                # Step 1: Set/Change 2FA password
                if new_password:
                    logger.info(f"🔐 Setting 2FA password for session {session_id}")
                    password_result = await self._set_2fa_password(client, old_password, new_password)
                    processing_details['password_set'] = password_result
                    
                    if password_result['success']:
                        await self.database.save_processing_log(
                            session_id, 'set_2fa_password', 'success', 
                            {'password_set': True}
                        )
                    else:
                        await self.database.save_processing_log(
                            session_id, 'set_2fa_password', 'failed',
                            {'error': password_result.get('error')}
                        )
                
                # Step 2: Update profile
                logger.info(f"👤 Updating profile for session {session_id}")
                profile_result = await self._update_profile(client, profile_config)
                processing_details['profile'] = profile_result
                
                await self.database.save_processing_log(
                    session_id, 'update_profile', 'success', profile_result
                )
                
                # Step 3: Set username
                logger.info(f"📝 Setting username for session {session_id}")
                username_result = await self._set_username(client, profile_config)
                processing_details['username'] = username_result
                
                await self.database.save_processing_log(
                    session_id, 'set_username', 'success', username_result
                )
                
                # Step 4: Check spam status
                spam_status = 'unknown'
                if perform_spam_check:
                    logger.info(f"🛡️ Checking spam status for session {session_id}")
                    spam_status = await self._check_spam_status(client)
                    processing_details['spam_status'] = spam_status
                    
                    await self.database.save_processing_log(
                        session_id, 'check_spam', 'success', 
                        {'status': spam_status}
                    )
                
                # Step 5: Check account age
                logger.info(f"📅 Checking account age for session {session_id}")
                account_age = await self._check_account_age(client)
                processing_details['account_age'] = account_age
                
                await self.database.save_processing_log(
                    session_id, 'check_account_age', 'success',
                    {'account_age': account_age}
                )
                
                # Step 6: Clean account
                cleanup_result = {'left_groups': 0, 'blocked_bots': 0}
                if perform_cleanup:
                    logger.info(f"🧹 Cleaning account for session {session_id}")
                    cleanup_result = await self._clean_account(client)
                    processing_details['cleanup'] = cleanup_result
                    
                    await self.database.save_processing_log(
                        session_id, 'clean_account', 'success', cleanup_result
                    )
                
                # Step 7: Check devices
                device_result = {'devices_found': 0, 'devices_terminated': 0, 'status': 'clean'}
                if perform_device_check:
                    logger.info(f"📱 Checking devices for session {session_id}")
                    device_result = await self._check_and_terminate_devices(client, session_id)
                    processing_details['devices'] = device_result
                    
                    await self.database.save_processing_log(
                        session_id, 'check_devices', device_result['status'], device_result
                    )
                
                # Step 8: Calculate quality score
                quality_score = self._calculate_quality_score(
                    spam_status=spam_status,
                    account_age=account_age,
                    device_count=device_result['devices_found'],
                    has_username=bool(username_result.get('username')),
                    has_profile_photo=bool(profile_result.get('photo_set'))
                )
                processing_details['quality_score'] = quality_score
                
                # Get final user info
                me = await client.get_me()
                final_user_info = {
                    'id': me.id,
                    'username': me.username,
                    'first_name': me.first_name,
                    'last_name': me.last_name,
                    'phone_number': me.phone_number
                }
                
                # Save complete account data to database
                account_data = {
                    'session_id': session_id,
                    'user_id': final_user_info['id'],
                    'username': final_user_info.get('username'),
                    'first_name': final_user_info.get('first_name'),
                    'last_name': final_user_info.get('last_name'),
                    'phone_number': final_user_info.get('phone_number'),
                    'session_string': session_string,
                    'password': new_password or '',
                    'spam_status': spam_status,
                    'account_age': account_age,
                    'registration_date': account_age,
                    'is_clean': device_result['status'] == 'clean' or device_result['status'] == 'completed',
                    'is_2fa_enabled': bool(new_password),
                    'devices_terminated': device_result.get('devices_terminated', 0),
                    'processing_status': 'completed' if device_result['status'] in ['clean', 'completed'] else device_result['status'],
                    'profile_photo_url': profile_result.get('photo_url'),
                    'bio': profile_result.get('bio')
                }
                
                await self.database.save_account(account_data)
                
                # Prepare final result
                final_result = {
                    'session_id': session_id,
                    'success': True,
                    'user_info': final_user_info,
                    'session_string': session_string,
                    'password_set': bool(new_password),
                    'profile_updated': {
                        'first_name': final_user_info.get('first_name'),
                        'last_name': final_user_info.get('last_name'),
                        'bio': profile_result.get('bio'),
                        'username': username_result.get('username'),
                        'photo_url': profile_result.get('photo_url')
                    },
                    'spam_status': spam_status,
                    'account_age': account_age,
                    'devices_terminated': device_result.get('devices_terminated', 0),
                    'is_clean': device_result['status'] in ['clean', 'completed'],
                    'processing_status': device_result['status'],
                    'quality_score': quality_score,
                    'processing_details': processing_details
                }
                
                # Notify main server with complete details
                await self._notify_main_server_complete(session_id, final_result)
                
                return final_result
                
        except Exception as e:
            logger.error(f"❌ Error processing account {session_id}: {e}")
            
            # Save error to database
            await self.database.save_processing_log(
                session_id, 'process_account', 'error', {'error': str(e)}
            )
            
            # Notify main server about error
            await self.telegram_manager.notify_main_server('/worker/account-processing-failed', {
                'session_id': session_id,
                'error': str(e),
                'processing_details': processing_details
            })
            
            return {
                'session_id': session_id,
                'success': False,
                'error': str(e),
                'processing_status': 'error',
                'processing_details': processing_details
            }
        finally:
            if client:
                try:
                    await client.disconnect()
                except:
                    pass
    
    async def _create_client_from_session(self, session_id: str, session_string: str, 
                                         proxy: Optional[Dict] = None) -> Optional[Client]:
        """Create client from session string"""
        try:
            session_name = f"processor_{self.config.WORKER_ID}_{session_id[:8]}"
            
            client_kwargs = {
                'name': session_name,
                'api_id': self.config.TELEGRAM_API_ID,
                'api_hash': self.config.TELEGRAM_API_HASH,
                'in_memory': True,
                'workdir': "/tmp/telegram_processing_sessions"
            }
            
            if proxy:
                client_kwargs['proxy'] = proxy
            
            client = Client(**client_kwargs)
            await client.connect()
            
            # Import session string
            await client.import_session_string(session_string)
            
            logger.info(f"✅ Processing client created for session: {session_id}")
            return client
            
        except Exception as e:
            logger.error(f"❌ Error creating processing client: {e}")
            return None
    
    async def _set_2fa_password(self, client: Client, old_password: Optional[str], 
                               new_password: str) -> Dict[str, Any]:
        """Set or change 2FA password"""
        try:
            # Check if 2FA is enabled
            has_2fa = await client.is_cloud_password_enabled()
            
            if has_2fa:
                # Remove old password first
                if old_password:
                    await client.remove_cloud_password(old_password)
                    logger.info("✅ Old 2FA password removed")
                else:
                    # If no old password provided but 2FA exists, can't proceed
                    return {
                        'success': False,
                        'error': '2FA exists but no old password provided'
                    }
            
            # Set new password
            await client.enable_cloud_password(new_password)
            logger.info("✅ New 2FA password set successfully")
            
            return {
                'success': True,
                'password_set': True,
                'had_previous_2fa': has_2fa
            }
            
        except PasswordHashInvalid:
            return {
                'success': False,
                'error': 'Invalid old password'
            }
        except Exception as e:
            logger.error(f"❌ Error setting 2FA password: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _update_profile(self, client: Client, profile_config: Optional[Dict]) -> Dict[str, Any]:
        """Update profile photo, name, and bio"""
        result = {
            'photo_set': False,
            'first_name': None,
            'last_name': None,
            'bio': None,
            'photo_url': None
        }
        
        try:
            # Generate or use provided name
            if profile_config and profile_config.get('generate_name', True):
                first_name = self.faker.first_name()
                last_name = self.faker.last_name()
            else:
                first_name = profile_config.get('first_name') if profile_config else None
                last_name = profile_config.get('last_name') if profile_config else None
            
            # Get bio
            bio = (profile_config.get('bio') if profile_config else None) or self.config.DEFAULT_BIO
            
            # Update profile
            await client.update_profile(
                first_name=first_name,
                last_name=last_name,
                bio=bio
            )
            
            result['first_name'] = first_name
            result['last_name'] = last_name
            result['bio'] = bio
            
            # Set profile photo if provided
            photo_url = (profile_config.get('photo_url') if profile_config else None) or self.config.DEFAULT_PROFILE_PHOTO_URL
            
            if photo_url:
                photo_path = await self._download_photo(photo_url)
                if photo_path:
                    await client.set_profile_photo(photo=photo_path)
                    result['photo_set'] = True
                    result['photo_url'] = photo_url
                    
                    # Clean up temp file
                    os.remove(photo_path)
            
            logger.info(f"✅ Profile updated: {first_name} {last_name}")
            return result
            
        except Exception as e:
            logger.error(f"❌ Error updating profile: {e}")
            return result
    
    async def _download_photo(self, url: str) -> Optional[str]:
        """Download profile photo from URL"""
        try:
            async with self.http_client.get(url) as response:
                if response.status == 200:
                    content = await response.read()
                    
                    # Save to temp file
                    filename = f"photo_{random.randint(1000, 9999)}.jpg"
                    filepath = self.temp_dir / filename
                    
                    async with aiofiles.open(filepath, 'wb') as f:
                        await f.write(content)
                    
                    # Validate image
                    img = Image.open(filepath)
                    img.verify()
                    
                    return str(filepath)
                    
        except Exception as e:
            logger.error(f"❌ Error downloading photo: {e}")
            return None
    
    async def _set_username(self, client: Client, profile_config: Optional[Dict]) -> Dict[str, Any]:
        """Set username with watermark pattern"""
        try:
            # Check if username already exists
            me = await client.get_me()
            
            if me.username:
                logger.info(f"✅ Username already exists: @{me.username}")
                return {
                    'success': True,
                    'username': me.username,
                    'already_existed': True
                }
            
            # Get watermark from config or profile_config
            watermark = (profile_config.get('watermark') if profile_config else None) or self.config.DEFAULT_WATERMARK
            
            # Clean watermark
            base_username = watermark.replace("_", "").replace("-", "").lower()
            base_username = re.sub(r'[^a-z0-9]', '', base_username)
            
            if not base_username:
                base_username = "user"
            
            # Try different patterns
            patterns = [
                f"{base_username}{random.randint(1000, 9999)}",
                f"{base_username}{random.choice(string.ascii_lowercase)}{random.randint(100, 999)}",
                f"{base_username}_{random.randint(10, 99)}",
                f"{base_username}{''.join(random.choices(string.digits, k=4))}"
            ]
            
            for username in patterns:
                try:
                    await client.set_username(username)
                    logger.info(f"✅ Username set: @{username}")
                    return {
                        'success': True,
                        'username': username,
                        'already_existed': False
                    }
                except UsernameOccupied:
                    continue
                except UsernameInvalid:
                    continue
                except Exception as e:
                    continue
            
            # Final random attempt
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            final_username = f"{base_username}{random_suffix}"
            
            try:
                await client.set_username(final_username)
                return {
                    'success': True,
                    'username': final_username,
                    'already_existed': False
                }
            except:
                return {
                    'success': False,
                    'username': None,
                    'error': 'Failed to set username'
                }
                
        except Exception as e:
            logger.error(f"❌ Error setting username: {e}")
            return {
                'success': False,
                'username': None,
                'error': str(e)
            }
    
    async def _check_spam_status(self, client: Client) -> str:
        """Check spam status via SpamBot"""
        try:
            # Send /start to SpamBot
            await client.send_message("SpamBot", "/start")
            await asyncio.sleep(3)
            
            # Get response
            messages = []
            async for msg in client.get_chat_history("SpamBot", limit=5):
                messages.append(msg)
            
            account_status = "unknown"
            
            for msg in messages:
                if msg.text:
                    text_lower = msg.text.lower()
                    
                    # Check for banned
                    if any(word in text_lower for word in ["banned", "permanently banned", "blocked", "deleted"]):
                        account_status = "banned"
                        break
                    
                    # Check for limited
                    elif any(word in text_lower for word in ["limited", "restricted", "spam", "reported"]):
                        account_status = "limited"
                        break
                    
                    # Check for free
                    elif any(word in text_lower for word in ["fine", "good", "free", "no issues", "normal", "okay"]):
                        account_status = "free"
                        break
            
            logger.info(f"📊 Spam status for account: {account_status}")
            return account_status
            
        except FloodWait as e:
            logger.warning(f"⏳ FloodWait during spam check: {e.value}s")
            await asyncio.sleep(min(e.value, 30))
            return "rate_limited"
        except Exception as e:
            logger.error(f"❌ Error checking spam: {e}")
            return "error"
    
    async def _check_account_age(self, client: Client) -> str:
        """Check account registration date via @idbot and @id_bot"""
        try:
            # Step 1: Send message to @idbot
            await client.send_message("idbot", "Hi")
            await asyncio.sleep(2)
            
            # Step 2: Send /start to @id_bot
            await client.send_message("id_bot", "/start")
            await asyncio.sleep(3)
            
            # Step 3: Get response from @id_bot
            async for message in client.get_chat_history("id_bot", limit=5):
                if message.text and "Registered:" in message.text:
                    match = re.search(r"Registered:\s*(.+?)(?:\n|$)", message.text)
                    if match:
                        reg_date = match.group(1).strip()
                        logger.info(f"✅ Account registration date: {reg_date}")
                        return reg_date
            
            # Try to extract from @idbot response as fallback
            async for message in client.get_chat_history("idbot", limit=5):
                if message.text and any(word in message.text.lower() for word in ["registration", "registered", "created"]):
                    match = re.search(r"(?:Registered|Registration|Created):\s*(.+?)(?:\n|$)", message.text, re.IGNORECASE)
                    if match:
                        reg_date = match.group(1).strip()
                        return reg_date
            
            logger.warning("⚠️ Could not determine account registration date")
            return "unknown"
            
        except Exception as e:
            logger.error(f"❌ Error checking account age: {e}")
            return "unknown"
    
    async def _clean_account(self, client: Client) -> Dict[str, int]:
        """Clean account by leaving groups and blocking bots"""
        result = {
            'left_groups': 0,
            'blocked_bots': 0
        }
        
        try:
            # Leave all groups and channels
            async for dialog in client.get_dialogs():
                chat = dialog.chat
                
                if chat.type in ["group", "supergroup", "channel"]:
                    try:
                        await client.leave_chat(chat.id)
                        result['left_groups'] += 1
                        await asyncio.sleep(1)
                    except FloodWait as e:
                        await asyncio.sleep(min(e.value, 30))
                    except:
                        pass
                
                elif chat.type == "bot":
                    try:
                        await client.block_user(chat.id)
                        result['blocked_bots'] += 1
                        await asyncio.sleep(1)
                    except FloodWait as e:
                        await asyncio.sleep(min(e.value, 30))
                    except:
                        pass
            
            logger.info(f"✅ Cleanup complete: Left {result['left_groups']} groups, Blocked {result['blocked_bots']} bots")
            return result
            
        except Exception as e:
            logger.error(f"❌ Error cleaning account: {e}")
            return result
    
    async def _check_and_terminate_devices(self, client: Client, session_id: str) -> Dict[str, Any]:
        """Check and terminate other devices"""
        try:
            # Get all sessions
            sessions = await client.get_sessions()
            
            other_devices = []
            for session in sessions:
                if not session.is_current:
                    device_info = {
                        'device': session.device_model or 'Unknown',
                        'app': session.app_name or 'Unknown',
                        'app_version': session.app_version or 'Unknown',
                        'ip': session.ip or 'Unknown',
                        'country': session.country or 'Unknown',
                        'hash': session.hash
                    }
                    other_devices.append(device_info)
            
            if not other_devices:
                logger.info("✅ No other devices found. Account is clean.")
                return {
                    'devices_found': 0,
                    'devices_terminated': 0,
                    'status': 'clean'
                }
            
            logger.info(f"📱 Found {len(other_devices)} other device(s)")
            
            terminated_count = 0
            needs_cooldown = False
            
            for device in other_devices:
                try:
                    await client.terminate_session(device['hash'])
                    terminated_count += 1
                    logger.info(f"✅ Terminated device: {device['device']}")
                    await asyncio.sleep(2)
                    
                except FloodWait as e:
                    wait_time = e.value
                    logger.warning(f"⏳ FloodWait during device termination: {wait_time}s")
                    
                    if wait_time > 300:  # More than 5 minutes
                        needs_cooldown = True
                        break
                    else:
                        await asyncio.sleep(wait_time + 1)
                        try:
                            await client.terminate_session(device['hash'])
                            terminated_count += 1
                        except:
                            needs_cooldown = True
                            break
                except Exception as e:
                    logger.error(f"❌ Error terminating device: {e}")
                    needs_cooldown = True
                    break
            
            remaining = len(other_devices) - terminated_count
            
            if needs_cooldown and remaining > 0:
                # Save device check with cooldown
                await self.database.save_device_check(session_id, {
                    'status': 'cooldown',
                    'devices_found': len(other_devices),
                    'devices_terminated': terminated_count,
                    'cooldown_until': datetime.now() + timedelta(hours=24),
                    'is_completed': False
                })
                
                return {
                    'devices_found': len(other_devices),
                    'devices_terminated': terminated_count,
                    'remaining': remaining,
                    'status': 'waiting_24h',
                    'cooldown_until': (datetime.now() + timedelta(hours=24)).isoformat()
                }
            
            elif remaining == 0:
                # All devices terminated
                await self.database.save_device_check(session_id, {
                    'status': 'completed',
                    'devices_found': len(other_devices),
                    'devices_terminated': terminated_count,
                    'is_completed': True
                })
                
                return {
                    'devices_found': len(other_devices),
                    'devices_terminated': terminated_count,
                    'remaining': 0,
                    'status': 'completed'
                }
            
            else:
                return {
                    'devices_found': len(other_devices),
                    'devices_terminated': terminated_count,
                    'remaining': remaining,
                    'status': 'partial'
                }
                
        except Exception as e:
            logger.error(f"❌ Error checking devices: {e}")
            return {
                'devices_found': 0,
                'devices_terminated': 0,
                'status': 'error',
                'error': str(e)
            }
    
    def _calculate_quality_score(self, spam_status: str, account_age: str, 
                                 device_count: int, has_username: bool, 
                                 has_profile_photo: bool) -> Dict[str, Any]:
        """Calculate account quality score"""
        score = 100
        factors = {}
        
        # Spam status scoring
        if spam_status == "banned":
            score -= 100
            factors['spam'] = 'banned'
        elif spam_status == "limited":
            score -= 50
            factors['spam'] = 'limited'
        elif spam_status == "free":
            score += 10
            factors['spam'] = 'free'
        elif spam_status == "unknown":
            score -= 20
            factors['spam'] = 'unknown'
        elif spam_status == "rate_limited":
            score -= 10
            factors['spam'] = 'rate_limited'
        
        # Account age scoring (approximate)
        if account_age and account_age != "unknown":
            # Try to parse year/month
            year_match = re.search(r'20\d{2}', account_age)
            month_match = re.search(r'(January|February|March|April|May|June|July|August|September|October|November|December)', account_age, re.IGNORECASE)
            
            if year_match:
                year = int(year_match.group())
                current_year = datetime.now().year
                age_years = current_year - year
                
                if age_years >= 2:
                    score += 15
                    factors['age'] = f'{age_years} years (excellent)'
                elif age_years >= 1:
                    score += 10
                    factors['age'] = f'{age_years} year (good)'
                elif age_years >= 0:
                    score -= 5
                    factors['age'] = 'Less than 1 year (new)'
                else:
                    score -= 10
                    factors['age'] = 'Invalid age'
            else:
                score -= 5
                factors['age'] = 'Unknown'
        else:
            score -= 10
            factors['age'] = 'Unknown'
        
        # Device count scoring
        if device_count == 0:
            score += 10
            factors['devices'] = 'No other devices (clean)'
        elif device_count <= 2:
            score -= 5
            factors['devices'] = f'{device_count} other device(s)'
        else:
            score -= 15
            factors['devices'] = f'{device_count} other devices (risky)'
        
        # Username scoring
        if has_username:
            score += 5
            factors['username'] = 'Has username'
        else:
            score -= 5
            factors['username'] = 'No username'
        
        # Profile photo scoring
        if has_profile_photo:
            score += 5
            factors['profile_photo'] = 'Has profile photo'
        else:
            score -= 5
            factors['profile_photo'] = 'No profile photo'
        
        # Determine quality grade
        grade = 'A' if score >= 90 else 'B' if score >= 75 else 'C' if score >= 60 else 'D' if score >= 40 else 'F'
        
        return {
            'score': max(0, min(100, score)),
            'grade': grade,
            'factors': factors,
            'is_high_quality': score >= 75,
            'is_medium_quality': 50 <= score < 75,
            'is_low_quality': score < 50
        }
    
    async def _notify_main_server_complete(self, session_id: str, result: Dict[str, Any]):
        """Notify main server with complete processing details"""
        await self.telegram_manager.notify_main_server('/worker/account-processing-complete', result)
        logger.info(f"📤 Complete account details sent to main server for session: {session_id}")
    
    async def close(self):
        """Close HTTP client"""
        if self.http_client:
            await self.http_client.close()