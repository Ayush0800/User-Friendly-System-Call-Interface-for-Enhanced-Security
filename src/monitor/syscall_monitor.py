import win32api
import win32con
import win32security
import win32process
import win32event
import win32file
import winerror
import psutil
import logging
import traceback
from typing import Dict, List, Optional
from datetime import datetime
import win32gui
import win32con
import ctypes
from ctypes import wintypes, WINFUNCTYPE
import queue
import win32file
import win32con
import win32api
import win32event
import os
import threading
import time
import winreg
import socket
import struct

# Windows API constants
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
WH_CBT = 5
FILE_LIST_DIRECTORY = 0x0001

# Network related constants
AF_INET = 2
PROCESS_ALL_ACCESS = 0x1F0FFF

# Kernel32 functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

# Define callback function type
HOOKPROC = WINFUNCTYPE(
    wintypes.LPARAM,
    ctypes.c_int,
    wintypes.WPARAM,
    wintypes.LPARAM
)

# System call categories
SYSCALL_CATEGORIES = {
    'PROCESS_CONTROL': [
        'process_create',
        'process_terminate',
        'thread_create',
        'thread_terminate',
        'cpu_usage',
        'memory_usage',
        'thread_operation'
    ],
    'FILE_MANAGEMENT': [
        'file_read',
        'file_write',
        'file_open',
        'file_close',
        'file_create',
        'file_delete',
        'file_change',
        'file_rename',
        'file_copy',
        'file_move',
        'file_save',
        'file_access',
        'file_edit',
        'directory_create',
        'directory_delete',
        'directory_list',
        'handle_operation',
        'file_ops',
    ],
    'DEVICE_MANAGEMENT': [
        'device_open',
        'device_close',
        'device_read',
        'device_write',
        'device_control',
    ],
    'INFORMATION_MAINTENANCE': [],
    'COMMUNICATION': [
        'socket_create',
        'socket_connect',
        'socket_bind',
        'socket_listen',
        'socket_accept',
        'socket_send',
        'socket_receive'
    ]
}

def get_syscall_category(syscall_name: str) -> str:
    """Get the category of a system call"""
    print(f"Checking category for syscall: {syscall_name}")  # Debug print
    for category, syscalls in SYSCALL_CATEGORIES.items():
        if any(syscall in syscall_name.lower() for syscall in syscalls):
            print(f"Found category '{category}' for syscall: {syscall_name}")  # Debug print
            return category
    print(f"No category found for syscall: {syscall_name}")  # Debug print
    return 'UNKNOWN'

class SyscallMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.monitored_processes: Dict[int, Dict] = {}
        self.is_monitoring = False
        self.syscall_queue = queue.Queue()
        self.hooks = []
        self.file_threads = []
        self.hook_refs = []
        
    def _monitor_network_activity(self, pid: int, proc_name: str):
    # """Continuously monitor network activity for a specific process"""
        while self.is_monitoring:
            try:
                proc = psutil.Process(pid)
                connections = proc.connections()
                for conn in connections:
                    if conn.status:  # Only log active connections
                        syscall_info = {
                            'time': datetime.now(),
                            'process': proc_name,
                            'pid': pid,
                            'syscall': 'network_activity',
                            'category': 'COMMUNICATION',
                            'status': 'Active',
                            'details': {
                                'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                                'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                                'status': conn.status
                            }
                        }
                        self.syscall_queue.put(syscall_info)  
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            time.sleep(2) 


    def _monitor_file_operations(self, pid: int, proc_name: str):
    # """Monitor file read/write events for a process"""
        try:
            proc = psutil.Process(pid)
            for file in proc.open_files():
                try:
                    operation = "unknown"
                    if "r" in file.mode:
                        operation = "file_read"
                    elif "w" in file.mode:
                        operation = "file_write"
                    else:
                        operation="file_ops"

                    syscall_info = {
                        'time': datetime.now(),
                        'process': proc_name,
                        'pid': pid,
                        'syscall': f'file_{operation}',
                        'category': 'FILE_MANAGEMENT',
                        'status': 'Completed'
                    }
                    self.syscall_queue.put(syscall_info)  # ✅ Add to queue for UI update
                except Exception as e:
                    logging.error(f"Error accessing file mode: {str(e)}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


    def _start_process_monitoring(self):
        """Monitor process-related activities"""
        def monitor_process():
            while self.is_monitoring:
                try:
                    for pid in list(self.monitored_processes.keys()):
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                            print(f"Monitoring process: {proc_name} (PID: {pid})")  # Debug print

                            # Monitor file operations
                            self._monitor_file_operations(pid, proc_name)

                            # Basic CPU usage monitoring
                            cpu_percent = proc.cpu_percent()
                            syscall_info = {
                                'time': datetime.now(),
                                'process': proc_name,
                                'pid': pid,
                                'syscall': 'cpu_usage',
                                'category': 'PROCESS_CONTROL',
                                'status': 'Success',
                                'details': {'cpu_percent': cpu_percent}
                            }
                            print(f"Adding CPU usage syscall to queue: {syscall_info}")  # Debug print
                            self.syscall_queue.put(syscall_info)

                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            print(f"Error monitoring process {pid}: {e}")
                            continue

                except Exception as e:
                    print(f"Error in process monitoring: {e}")

                time.sleep(1)  # Check every second

        self.process_thread = threading.Thread(target=monitor_process)
        self.process_thread.daemon = True
        self.process_thread.start()

    def _start_registry_monitoring(self):
        """Monitor registry operations"""
        def monitor_registry():
            while self.is_monitoring:
                try:
                    for pid in list(self.monitored_processes.keys()):
                        try:
                            proc = psutil.Process(pid)
                            # Monitor registry keys
                            handles = self.get_process_handles(pid)
                            for handle in handles:
                                if handle.get('type') == 'registry':
                                    syscall_info = {
                                        'time': datetime.now(),
                                        'process': proc.name(),
                                        'pid': pid,
                                        'syscall': 'registry_access',
                                        'category': get_syscall_category('registry_access'),
                                        'status': 'Success',
                                        'details': {
                                            'path': handle.get('path', 'Unknown'),
                                            'access': handle.get('access', 'Unknown')
                                        }
                                    }
                                    print(f"Adding registry access syscall to queue: {syscall_info}")  # Debug print
                                    self.syscall_queue.put(syscall_info)
                                    
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            self.logger.warning(f"Access denied or process no longer exists (PID {pid}): {str(e)}")
                            continue
                            
                except Exception as e:
                    self.logger.error(f"Error in registry monitoring: {str(e)}\n{traceback.format_exc()}")
                    
                time.sleep(1)  # Check every second
                
        thread = threading.Thread(target=monitor_registry, daemon=True)
        thread.start()
        self.file_threads.append(thread)
        
    def _start_file_monitoring(self):
        """Monitor file system operations"""
        try:
            paths_to_monitor = [
                os.path.expandvars(r"%USERPROFILE%\Documents"),
                os.path.expandvars(r"%USERPROFILE%\Desktop"),
                os.path.expandvars(r"%USERPROFILE%\Downloads"),
                os.path.expandvars(r"%TEMP%"),
                os.path.expandvars(r"%APPDATA%"),
                os.path.expandvars(r"%LOCALAPPDATA%")
            ]
            
            for path in paths_to_monitor:
                if os.path.exists(path):
                    thread = threading.Thread(
                        target=self._monitor_directory,
                        args=(path,),
                        daemon=True
                    )
                    thread.start()
                    self.file_threads.append(thread)
                    
        except Exception as e:
            self.logger.error(f"Error starting file monitoring: {e}")
            
    def _monitor_directory(self, path: str):
        try:
            handle = win32file.CreateFile(
                path,
                FILE_LIST_DIRECTORY,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OVERLAPPED,
                None
            )
            
            buffer = ctypes.create_string_buffer(8192)
            overlapped = win32file.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, 0, 0, None)
            
            while self.is_monitoring:
                try:
                    win32file.ReadDirectoryChangesW(
                        handle,
                        buffer,
                        True,
                        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                        # win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                        # win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                        # win32con.FILE_NOTIFY_CHANGE_SIZE |
                        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE ,
                        # win32con.FILE_NOTIFY_CHANGE_SECURITY,
                        overlapped
                    )
                    
                    result = win32event.WaitForSingleObject(overlapped.hEvent, 1000)
                    if result == win32event.WAIT_OBJECT_0:
                        bytes_returned = win32file.GetOverlappedResult(handle, overlapped, True)
                        if bytes_returned > 0:
                            self._process_file_changes(buffer, bytes_returned, path)
                            
                except Exception as e:
                    if self.is_monitoring:
                        self.logger.error(f"Error monitoring directory {path}: {e}")
                    break
                    
            win32api.CloseHandle(handle)
            
        except Exception as e:
            self.logger.error(f"Error setting up directory monitor for {path}: {e}")
            
    def _process_file_changes(self, buffer, bytes_returned: int, base_path: str):
        try:
            changes = win32file.FILE_NOTIFY_INFORMATION(buffer, bytes_returned)
            for action, filename in changes:
                try:
                    full_path = os.path.join(base_path, filename)
                    action_name = {
                        1: "file_create",
                        2: "file_delete",
                        3: "file_write",  # ✅ Log file writes
                        4: "file_read",   # ✅ Log file reads (approximation)
                        5: "file_rename"
                    }.get(action, "file_ops")  # Default fallback
                
                    syscall_info = {
                        'time': datetime.now(),
                        'process': "Unknown",  # Fix this by linking to monitored processes
                        'pid': "Unknown",
                        'syscall': action_name,
                        'category': get_syscall_category(action_name),
                        'status': 'Detected'
                    }

                    print(f"Adding file operation syscall to queue: {syscall_info}")  # Debug print
                    self.syscall_queue.put(syscall_info)

                except Exception as e:
                    self.logger.error(f"Error processing file change: {e}")
        except Exception as e:
            self.logger.error(f"Error processing file changes: {e}")

    def get_process_handles(self, pid):
        """Get process handles using psutil's connections() method as an alternative."""
        try:
            proc = psutil.Process(pid)
            handles = []
            
            # Get network connections as a proxy for handle activity
            for conn in proc.connections():
                handle_info = {
                    'type': 'Socket',
                    'local_addr': conn.laddr,
                    'remote_addr': conn.raddr if conn.raddr else None,
                    'status': conn.status
                }
                handles.append(handle_info)
                
            # Get open files
            for file in proc.open_files():
                handle_info = {
                    'type': 'File',
                    'path': file.path,
                    'mode': file.mode if hasattr(file, 'mode') else 'unknown'
                }
                handles.append(handle_info)
                
            return handles
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return []

    def _start_security_monitoring(self):
        """Monitor security-related operations"""
        def monitor_security():
            while self.is_monitoring:
                try:
                    for pid in self.monitored_processes:
                        try:
                            proc = psutil.Process(pid)
                            
                            # Check open handles
                            handles = self.get_process_handles(pid)
                            for handle in handles:
                                if isinstance(handle,dict):
                                    syscall_info = {
                                        'time': datetime.now(),
                                        'process_name': proc.name(),
                                        'pid': pid,
                                        'syscall': 'handle_operation',
                                        'category': get_syscall_category('handle_operation'),
                                        'status': 'open'
                                }
                                if syscall_info['syscall']['name'] == 'handle_operation':
                                    operation_type = syscall_info['syscall']
                                    operation_msg = f"File {operation_type}d: {os.path.basename(handle.get('path', 'Unknown'))}"  # Use only the file name
                                else:
                                    operation_msg = syscall_info['syscall']['name']  # Default to syscall name
                                print(f"Adding handle operation syscall to queue: {operation_msg}")  # Debug print
                                self.syscall_queue.put(syscall_info)
                            
                            # Check threads
                            for thread in proc.threads():
                                syscall_info = {
                                    'time': datetime.now(),
                                    'process_name': proc.name(),
                                    'pid': pid,
                                    'syscall': 'thread_operation',
                                    'category': get_syscall_category('thread_operation'),
                                    'status': 'active'
                                }
                                print(f"Adding thread operation syscall to queue: {syscall_info}")  # Debug print
                                self.syscall_queue.put(syscall_info)
                            
                            # Check DLL modules
                            for module in proc.memory_maps():
                                if module.path.lower().endswith('.dll'):
                                    syscall_info = {
                                        'time': datetime.now(),
                                        'process_name': proc.name(),
                                        'pid': pid,
                                        'syscall': 'dll_load',
                                        'category': get_syscall_category('dll_load'),
                                        'status': 'loaded'
                                    }
                                    print(f"Adding DLL load syscall to queue: {syscall_info}")  # Debug print
                                    self.syscall_queue.put(syscall_info)
                                    
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
                except Exception as e:
                    self.logger.error(f"Error in security monitoring: {e}")
                    
                time.sleep(5)  # Check every 5 seconds
                
        threading.Thread(target=monitor_security, daemon=True).start()
        
    def stop_monitoring(self):
        try:
            self.is_monitoring = False
            
            # Stop file monitoring threads
            for thread in self.file_threads:
                thread.join(timeout=1.0)
            self.file_threads.clear()
            
            self.monitored_processes.clear()
            self.logger.info("Stopped monitoring all processes")
            
        except Exception as e:
            self.logger.error(f"Error in stop_monitoring: {e}\n{traceback.format_exc()}")
            
    def _get_foreground_process_id(self) -> int:
        try:
            hwnd = user32.GetForegroundWindow()
            return win32process.GetWindowThreadProcessId(hwnd)[1]
        except Exception as e:
            self.logger.error(f"Error getting foreground process: {e}")
            return None

    def get_process_info(self, pid: int) -> Optional[Dict]:
        """Get process information and any pending syscalls"""
        try:
            if not self.is_monitoring or pid not in self.monitored_processes:
                return None
                
            # Get process info
            process = psutil.Process(pid)
            info = {
                'time': datetime.now(),
                'process_name': process.name(),
                'pid': pid,
                'syscall': 'memory_usage', 
                'category': get_syscall_category('memory_usage'), 
                'status': 'active'
            }
            
            # Check for pending syscalls
            try:
                while not self.syscall_queue.empty():
                    syscall = self.syscall_queue.get_nowait()
                    if syscall['pid'] == pid:
                        info.update(syscall)
                        break
            except queue.Empty:
                pass
                
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception as e:
            self.logger.error(f"Error getting process info: {e}\n{traceback.format_exc()}")
            return None

    def start_monitoring(self, processes: Dict[int, Dict]):
        try:
            self.monitored_processes = processes
            self.is_monitoring = True
            self.logger.info(f"Started monitoring {len(processes)} processes")
            
            # Start file system monitoring
            self._start_file_monitoring()
            
            # Start registry monitoring
            self._start_registry_monitoring()
            
            # Start process monitoring
            self._start_process_monitoring()
            
            # Start security monitoring
            self._start_security_monitoring()
            
        except Exception as e:
            self.logger.error(f"Error in start_monitoring: {e}\n{traceback.format_exc()}")
            self.stop_monitoring()
            raise
