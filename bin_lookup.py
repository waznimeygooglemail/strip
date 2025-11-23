#!/usr/bin/env python3
"""
BIN Lookup Module
Gets card type, bank name, and country from BIN (first 6-8 digits)
Uses binlist.net API (free, no API key required)
"""

import requests
import re
from typing import Dict, Optional, Tuple
import time

# Cache for BIN lookups (to avoid too many API calls)
bin_cache = {}
cache_expiry = 3600  # 1 hour cache


def get_bin_from_cc(cc_string: str) -> Optional[str]:
    """
    Extract BIN (first 6-8 digits) from CC string
    
    Args:
        cc_string: Credit card string (e.g., "4111111111111111|12|2025|123")
    
    Returns:
        BIN string (6-8 digits) or None
    """
    # Extract only digits from CC part
    if '|' in cc_string:
        cc_part = cc_string.split('|')[0]
    elif ' ' in cc_string:
        cc_part = cc_string.split()[0]
    else:
        cc_part = cc_string
    
    # Extract digits only
    digits = ''.join(filter(str.isdigit, cc_part))
    
    # Get first 6-8 digits as BIN
    if len(digits) >= 8:
        return digits[:8]  # Use 8 digits for better accuracy
    elif len(digits) >= 6:
        return digits[:6]  # Use 6 digits minimum
    
    return None


def get_card_type_emoji(card_type: str) -> str:
    """Get emoji for card type"""
    card_type_lower = card_type.lower()
    if 'visa' in card_type_lower:
        return '💳'
    elif 'mastercard' in card_type_lower or 'master' in card_type_lower:
        return '💳'
    elif 'amex' in card_type_lower or 'american express' in card_type_lower:
        return '💳'
    elif 'discover' in card_type_lower:
        return '💳'
    else:
        return '💳'


def get_country_emoji(country_code: str) -> str:
    """Get flag emoji for country code"""
    if not country_code or len(country_code) != 2:
        return '🌍'
    
    # Convert country code to flag emoji
    # Country codes are like "US", "GB", "CA", etc.
    # Flag emojis are made from regional indicator symbols
    try:
        # Convert to uppercase
        code = country_code.upper()
        # Each letter becomes a regional indicator symbol
        # Unicode: A = 0x1F1E6, so we add offset
        flag = ''.join(chr(0x1F1E6 + ord(char) - ord('A')) for char in code)
        return flag
    except:
        return '🌍'


def get_bin_info(bin_number: str, use_cache: bool = True) -> Dict[str, Optional[str]]:
    """
    Get BIN information from binlist.net API
    
    Args:
        bin_number: BIN number (6-8 digits)
        use_cache: Whether to use cached results
    
    Returns:
        Dict with 'type', 'brand', 'bank', 'country', 'country_code'
    """
    if not bin_number or len(bin_number) < 6:
        return {
            'type': None,
            'brand': None,
            'bank': None,
            'country': None,
            'country_code': None,
            'level': None
        }
    
    # Check cache first
    if use_cache and bin_number in bin_cache:
        cached_data, cached_time = bin_cache[bin_number]
        if time.time() - cached_time < cache_expiry:
            return cached_data
    
    try:
        # Call binlist.net API (free, no API key needed)
        # Rate limit: 1 request per second
        url = f"https://lookup.binlist.net/{bin_number}"
        headers = {
            'Accept-Version': '3',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract information
            brand = data.get('scheme', '') or data.get('brand', '')
            card_type = data.get('type', '')
            level = data.get('level', '')  # debit, credit, prepaid, etc.
            
            # Format card type: "Visa Gold" or "Mastercard Platinum" etc.
            if brand and level:
                formatted_type = f"{brand} {level.title()}"
            elif brand and card_type:
                formatted_type = f"{brand} {card_type.title()}"
            elif brand:
                formatted_type = brand.title()
            else:
                formatted_type = card_type.title() if card_type else "Unknown"
            
            # Get bank name
            bank_data = data.get('bank', {})
            bank_name = bank_data.get('name', '') if isinstance(bank_data, dict) else ''
            
            # Get country
            country_data = data.get('country', {})
            country_name = country_data.get('name', '') if isinstance(country_data, dict) else ''
            country_code = country_data.get('alpha2', '') if isinstance(country_data, dict) else ''
            
            result = {
                'type': formatted_type,
                'brand': brand.title() if brand else None,
                'bank': bank_name,
                'country': country_name,
                'country_code': country_code,
                'level': level.title() if level else None
            }
            
            # Cache the result
            if use_cache:
                bin_cache[bin_number] = (result, time.time())
            
            return result
        else:
            # API error, return empty result
            result = {
                'type': None,
                'brand': None,
                'bank': None,
                'country': None,
                'country_code': None,
                'level': None
            }
            # Cache empty result for shorter time (5 minutes) to retry later
            if use_cache:
                bin_cache[bin_number] = (result, time.time() - (cache_expiry - 300))
            return result
            
    except Exception as e:
        # Error calling API, return empty result
        result = {
            'type': None,
            'brand': None,
            'bank': None,
            'country': None,
            'country_code': None,
            'level': None
        }
        return result


def get_card_info_from_cc(cc_string: str) -> Dict[str, Optional[str]]:
    """
    Get card information from CC string
    
    Args:
        cc_string: Credit card string (e.g., "4111111111111111|12|2025|123")
    
    Returns:
        Dict with card type, bank, country information
    """
    bin_number = get_bin_from_cc(cc_string)
    if not bin_number:
        return {
            'type': None,
            'bank': None,
            'country': None,
            'country_code': None
        }
    
    bin_info = get_bin_info(bin_number)
    
    return {
        'type': bin_info.get('type'),
        'bank': bin_info.get('bank'),
        'country': bin_info.get('country'),
        'country_code': bin_info.get('country_code')
    }


def format_card_info_for_response(card_info: Dict[str, Optional[str]]) -> str:
    """
    Format card info for bot response
    
    Args:
        card_info: Dict with 'type', 'bank', 'country', 'country_code'
    
    Returns:
        Formatted string with emojis
    """
    card_type = card_info.get('type') or 'Unknown'
    bank_name = card_info.get('bank') or 'Unknown'
    country = card_info.get('country') or 'Unknown'
    country_code = card_info.get('country_code') or ''
    
    # Get emojis
    card_emoji = get_card_type_emoji(card_type)
    bank_emoji = '🏦'
    country_emoji = get_country_emoji(country_code)
    
    # Format response
    info_text = f"\n\n{bank_emoji} Bank: {bank_name}\n"
    info_text += f"{card_emoji} Card Type: {card_type}\n"
    info_text += f"{country_emoji} Country: {country}"
    
    return info_text


if __name__ == "__main__":
    # Test the module
    test_cc = "4111111111111111|12|2025|123"
    info = get_card_info_from_cc(test_cc)
    print(f"Card Info: {info}")
    print(f"Formatted: {format_card_info_for_response(info)}")

