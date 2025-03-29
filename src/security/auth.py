import win32security
import win32api
import win32con
import logging
import json
import os
import hashlib
import secrets
from typing import Optional, Tuple

class AuthManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.auth_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'security.json'
        )
        self.load_auth_data()
        
    def load_auth_data(self):
        """Load authentication data from file"""
        try:
            if os.path.exists(self.auth_file):
                with open(self.auth_file, 'r') as f:
                    self.auth_data = json.load(f)
            else:
                self.logger.info("No existing auth data found, creating new")
                self.auth_data = {'users': {}}
                # Create default admin account if no users exist
                if not self.auth_data['users']:
                    self.create_user('admin', 'admin123', is_admin=True)
                self.save_auth_data()
        except Exception as e:
            self.logger.error(f"Error loading auth data: {e}")
            self.auth_data = {'users': {}}
            # Create default admin account if error occurred
            if not self.auth_data['users']:
                self.create_user('admin', 'admin123', is_admin=True)
            
    def save_auth_data(self):
        """Save authentication data to file"""
        try:
            os.makedirs(os.path.dirname(self.auth_file), exist_ok=True)
            with open(self.auth_file, 'w') as f:
                json.dump(self.auth_data, f, indent=4)
            self.logger.debug("Auth data saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving auth data: {e}")
            
    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt using SHA-256"""
        if not salt:
            salt = secrets.token_hex(16)
        
        salted = password + salt
        hashed = hashlib.sha256(salted.encode()).hexdigest()
        return hashed, salt
        
    def create_user(self, username: str, password: str, is_admin: bool = False) -> bool:
        """Create a new user"""
        if username in self.auth_data['users']:
            self.logger.warning(f"User {username} already exists")
            return False
            
        hashed_pass, salt = self._hash_password(password)
        
        self.auth_data['users'][username] = {
            'password_hash': hashed_pass,
            'salt': salt,
            'is_admin': is_admin
        }
        
        self.save_auth_data()
        self.logger.info(f"Created new user: {username}")
        return True
        
    def authenticate(self, username: str, password: str) -> bool:
        """Authenticate a user"""
        if username not in self.auth_data['users']:
            self.logger.warning(f"Authentication failed: User {username} not found")
            return False
            
        user_data = self.auth_data['users'][username]
        salt = user_data['salt']
        stored_hash = user_data['password_hash']
        
        hashed_input, _ = self._hash_password(password, salt)
        
        if hashed_input == stored_hash:
            self.logger.info(f"User {username} authenticated successfully")
            return True
            
        self.logger.warning(f"Authentication failed for user {username}")
        return False
        
    def is_admin(self, username: str) -> bool:
        """Check if user is an admin"""
        if username not in self.auth_data['users']:
            return False
        return self.auth_data['users'][username]['is_admin']
        
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change user's password"""
        if not self.authenticate(username, old_password):
            return False
            
        hashed_pass, salt = self._hash_password(new_password)
        self.auth_data['users'][username]['password_hash'] = hashed_pass
        self.auth_data['users'][username]['salt'] = salt
        
        self.save_auth_data()
        self.logger.info(f"Password changed for user {username}")
        return True
        
    def delete_user(self, username: str) -> bool:
        """Delete a user"""
        if username not in self.auth_data['users']:
            return False
            
        del self.auth_data['users'][username]
        self.save_auth_data()
        self.logger.info(f"Deleted user: {username}")
        return True
