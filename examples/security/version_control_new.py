#!/usr/bin/env python3
"""
User authentication module for secure login system.
Handles password validation and session management.
"""

import hashlib
import secrets
import hmac
from datetime import datetime, timedelta

class UserAuth:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.secret_key = secrets.token_bytes(32)
    
    def hash_password(self, password):
        """Hash password using PBKDF2 with SHA-256"""
        salt = secrets.token_bytes(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt + password_hash
    
    def verify_password(self, password, stored_hash):
        """Verify password against stored hash using constant-time comparison"""
        salt = stored_hash[:32]
        stored_password_hash = stored_hash[32:]
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hmac.compare_digest(password_hash, stored_password_hash)
    
    def login(self, username, password):
        """Authenticate user login with timing attack protection"""
        dummy_hash = b'\x00' * 64
        stored_hash = self.users.get(username, {}).get('password', dummy_hash)
        
        if self.verify_password(password, stored_hash) and username in self.users:
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = {
                'username': username,
                'created': datetime.now(),
                'expires': datetime.now() + timedelta(hours=24)
            }
            return session_id
        return False
    
    def register_user(self, username, password):
        """Register new user account with enhanced security"""
        if username in self.users:
            raise ValueError("User already exists")
        
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        self.users[username] = {
            'password': self.hash_password(password),
            'created': datetime.now()
        }
        return True