#!/usr/bin/env python3
"""
User authentication module for secure login system.
Handles password validation and session management.
"""

import hashlib
import secrets
from datetime import datetime, timedelta

class UserAuth:
    def __init__(self):
        self.users = {}
        self.sessions = {}
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"
    
    def verify_password(self, password, stored_hash):
        """Verify password against stored hash"""
        salt, hash_value = stored_hash.split(':')
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return password_hash == hash_value
    
    def login(self, username, password):
        """Authenticate user login"""
        if username not in self.users:
            return False
        
        stored_hash = self.users[username]['password']
        if self.verify_password(password, stored_hash):
            session_id = secrets.token_urlsafe(32)
            self.sessions[session_id] = {
                'username': username,
                'created': datetime.now(),
                'expires': datetime.now() + timedelta(hours=24)
            }
            return session_id
        return False
    
    def register_user(self, username, password):
        """Register new user account"""
        if username in self.users:
            raise ValueError("User already exists")
        
        self.users[username] = {
            'password': self.hash_password(password),
            'created': datetime.now()
        }
        return True