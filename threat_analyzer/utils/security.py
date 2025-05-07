import re
import time
from typing import Dict, Optional, Callable
from functools import wraps
import ipaddress
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_calls: int, time_window: int):
        """
        Initialize rate limiter
        :param max_calls: Maximum number of calls allowed in the time window
        :param time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls: Dict[str, list] = {}  # Store timestamps for each IP/domain

    def is_allowed(self, identifier: str) -> bool:
        """
        Check if a request is allowed based on rate limiting rules
        :param identifier: IP address or domain name
        :return: True if request is allowed, False otherwise
        """
        now = time.time()
        
        # Clean up old timestamps
        if identifier in self.calls:
            self.calls[identifier] = [ts for ts in self.calls[identifier] 
                                    if now - ts < self.time_window]
        
        # Check if we've exceeded the rate limit
        if identifier in self.calls and len(self.calls[identifier]) >= self.max_calls:
            return False
        
        # Add current timestamp
        if identifier not in self.calls:
            self.calls[identifier] = []
        self.calls[identifier].append(now)
        
        return True

def rate_limit(max_calls: int = 60, time_window: int = 60):
    """
    Decorator for rate limiting API calls
    :param max_calls: Maximum number of calls allowed in the time window
    :param time_window: Time window in seconds
    """
    limiter = RateLimiter(max_calls, time_window)
    
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Use the first argument (IP/domain) as the identifier
            identifier = args[0] if args else kwargs.get('ip_address') or kwargs.get('domain')
            if not identifier:
                raise ValueError("No identifier provided for rate limiting")
            
            if not limiter.is_allowed(identifier):
                logger.warning(f"Rate limit exceeded for {identifier}")
                raise Exception(f"Rate limit exceeded. Please try again later.")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

class InputValidator:
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """
        Validate IP address format
        :param ip: IP address to validate
        :return: True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """
        Validate domain name format
        :param domain: Domain name to validate
        :return: True if valid, False otherwise
        """
        # Basic domain validation regex
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))

    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """
        Sanitize user input to prevent injection attacks
        :param input_str: Input string to sanitize
        :return: Sanitized string
        """
        # Remove potentially dangerous characters
        return re.sub(r'[<>"\']', '', input_str)

def validate_input(func: Callable):
    """
    Decorator for input validation
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Skip first argument if it's a method (self)
        input_param = args[1] if len(args) > 1 else kwargs.get('ip_address') or kwargs.get('domain')
        if not input_param:
            raise ValueError("No input parameter provided")
        
        # Ensure input is a string
        if not isinstance(input_param, str):
            input_param = str(input_param)
        
        # Sanitize input
        sanitized_input = InputValidator.sanitize_input(input_param)
        
        # Validate based on input type
        if '.' in sanitized_input and not sanitized_input.startswith('http'):
            if not InputValidator.validate_ip(sanitized_input) and not InputValidator.validate_domain(sanitized_input):
                raise ValueError(f"Invalid input format: {sanitized_input}")
        
        # Update args or kwargs with sanitized input
        if len(args) > 1:
            args = (args[0], sanitized_input) + args[2:]
        else:
            kwargs['ip_address' if 'ip_address' in kwargs else 'domain'] = sanitized_input
        
        return func(*args, **kwargs)
    return wrapper 