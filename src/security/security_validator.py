import win32security
import win32api
import win32con
import logging
import json
import os
import sys

# Add parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.default_config import DEFAULT_SECURITY_CONFIG
from typing import Dict, Optional

class SecurityValidator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'security_config.json'
        )
        self.load_security_config()
        
    def load_security_config(self):
        """Load security configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = DEFAULT_SECURITY_CONFIG.copy()
                self.save_security_config()
        except Exception as e:
            self.logger.error(f"Error loading security config: {e}")
            self.config = DEFAULT_SECURITY_CONFIG.copy()
            
    def save_security_config(self):
        """Save security configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error saving security config: {e}")
            
    def get_default_config(self) -> Dict:
        """Get default security configuration"""
        return DEFAULT_SECURITY_CONFIG.copy()
        
    def validate_process_access(self, pid: int) -> bool:
        """Validate if the current user has permission to monitor the process"""
        try:
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            # Get process token
            token_handle = win32security.OpenProcessToken(
                process_handle,
                win32con.TOKEN_QUERY
            )
            
            # Get token information
            token_info = win32security.GetTokenInformation(
                token_handle,
                win32security.TokenUser
            )
            
            # Get user SID
            user_sid = token_info[0]
            
            # Get user name from SID
            username = win32security.LookupAccountSid(None, user_sid)[0]
            
            win32api.CloseHandle(process_handle)
            win32api.CloseHandle(token_handle)
            
            return username in self.config['allowed_users']
            
        except win32api.error as e:
            self.logger.error(f"Error validating process access: {e}")
            return False
            
    def validate_syscall(self, syscall_info: Dict) -> bool:
        """Validate if the system call is allowed"""
        if not syscall_info:
            return False
            
        syscall_name = syscall_info.get('name', '')
        
        # Check if syscall is blocked
        if syscall_name in self.config['blocked_syscalls']:
            self.logger.warning(f"Blocked syscall attempted: {syscall_name}")
            return False
            
        # Validate based on monitoring rules
        if 'file_access' in syscall_name.lower() and not self.config['monitoring_rules']['file_access']:
            return False
        if 'network' in syscall_name.lower() and not self.config['monitoring_rules']['network_access']:
            return False
        if 'process' in syscall_name.lower() and not self.config['monitoring_rules']['process_creation']:
            return False
        if 'reg' in syscall_name.lower() and not self.config['monitoring_rules']['registry_access']:
            return False
            
        return True
        
    def check_thresholds(self, process_info: Dict) -> Optional[str]:
        """Check if process metrics exceed defined thresholds"""
        if not process_info:
            return None
            
        alerts = []
        
        if process_info.get('cpu_percent', 0) > self.config['alert_thresholds']['cpu_usage']:
            alerts.append("High CPU usage")
            
        if process_info.get('memory_percent', 0) > self.config['alert_thresholds']['memory_usage']:
            alerts.append("High memory usage")
            
        return '; '.join(alerts) if alerts else None
