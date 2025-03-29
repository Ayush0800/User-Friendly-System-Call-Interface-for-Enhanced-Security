"""Default configuration for the System Call Interface"""

DEFAULT_SECURITY_CONFIG = {
    "allowed_users": ["Administrator", "admin"],
    "blocked_syscalls": [],
    "monitoring_rules": {
        "file_access": True,
        "network_access": True,
        "process_creation": True,
        "registry_access": True
    },
    "alert_thresholds": {
        "cpu_usage": 90,
        "memory_usage": 90,
        "syscalls_per_second": 1000
    }
}
