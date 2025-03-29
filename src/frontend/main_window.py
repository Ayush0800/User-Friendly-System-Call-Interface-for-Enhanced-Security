from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLabel, QHBoxLayout, QStatusBar, QListWidget,
    QListWidgetItem, QSplitter, QDialog, QDialogButtonBox, QMessageBox,
    QToolBar, QFrame, QLineEdit, QFormLayout, QHeaderView, QStyle,
    QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, QEvent
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
import psutil
from typing import Dict, Any
from datetime import datetime
from collections import defaultdict
import logging
import os
import sys
import traceback
import queue
import win32security
import win32api
import win32con
from .monitoring_reason_dialog import MonitoringReasonDialog
from queue import Queue, Empty

# Add parent directory to Python path to fix imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.auth import AuthManager
from monitor.syscall_monitor import SyscallMonitor
from security.security_validator import SecurityValidator

# Configure logging
logger = logging.getLogger(__name__)

class LoginDialog(QDialog):
    def __init__(self, auth_manager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.setStyleSheet("""
            QDialog {
                background-color: #f0f0f0;
            }
            QLabel {
                color: #2c3e50;
                font-size: 14px;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                background-color: white;
                selection-background-color: #3498db;
            }
            QLineEdit:focus {
                border: 2px solid #3498db;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton[type="cancel"] {
                background-color: #e74c3c;
            }
            QPushButton[type="cancel"]:hover {
                background-color: #c0392b;
            }
            QFrame#login_frame {
                background-color: white;
                border-radius: 8px;
                padding: 20px;
            }
            QLabel#title_label {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                padding-bottom: 20px;
            }
        """)
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("System Call Interface - Login")
        self.setFixedSize(400, 300)
        
        # Main layout
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Create a frame for the login form
        login_frame = QFrame()
        login_frame.setObjectName("login_frame")
        frame_layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("Login")
        title_label.setObjectName("title_label")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        frame_layout.addWidget(title_label)
        
        # Form layout
        form_layout = QFormLayout()
        form_layout.setSpacing(15)
        
        # Username field
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        form_layout.addRow("Username:", self.username_input)
        
        # Password field
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Password:", self.password_input)
        
        frame_layout.addLayout(form_layout)
        frame_layout.addSpacing(20)
        
        # Buttons
        button_box = QDialogButtonBox()
        ok_button = QPushButton("Login")
        cancel_button = QPushButton("Cancel")
        cancel_button.setProperty("type", "cancel")
        
        button_box.addButton(ok_button, QDialogButtonBox.ButtonRole.AcceptRole)
        button_box.addButton(cancel_button, QDialogButtonBox.ButtonRole.RejectRole)
        
        button_box.accepted.connect(self.validate_login)
        button_box.rejected.connect(self.reject)
        
        frame_layout.addWidget(button_box)
        login_frame.setLayout(frame_layout)
        layout.addWidget(login_frame)
        
        self.setLayout(layout)
        
        # Set focus to username field
        self.username_input.setFocus()
        
    def validate_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if self.auth_manager.authenticate(username, password):
            self.accept()
        else:
            QMessageBox.warning(
                self,
                "Login Failed",
                "Invalid username or password.",
                QMessageBox.StandardButton.Ok
            )

class ProcessSelectionDialog(QDialog):
    def __init__(self, processes, parent=None):
        super().__init__(parent)
        # Store processes list
        self._processes = processes
        
        # Basic window setup
        self.setWindowTitle("Select Processes to Monitor")
        self.setModal(True)
        self.setMinimumSize(500, 600)
        
        # Create main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Create search box
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:", self)
        self.search_box = QLineEdit(self)
        self.search_box.setPlaceholderText("Type to search processes...")
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_box)
        layout.addLayout(search_layout)
        
        # Create process list
        self.process_list = QListWidget(self)
        self.process_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        layout.addWidget(self.process_list)
        
        # Add buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Cancel,
            self
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        # Populate process list
        self.populate_processes()
        
        # Connect search box
        self.search_box.textChanged.connect(self._filter_processes)
        
        # Set focus to search box
        self.search_box.setFocus()
        
    def populate_processes(self):
        """Populate the process list"""
        self.process_list.clear()
        for proc in self._processes:
            item = QListWidgetItem(
                f"{proc['name']} (PID: {proc['pid']}) - {proc['username']}"
            )
            item.setData(Qt.ItemDataRole.UserRole, proc)
            self.process_list.addItem(item)
            
    def _filter_processes(self, text):
        """Filter processes based on search text"""
        search_text = text.lower()
        for i in range(self.process_list.count()):
            item = self.process_list.item(i)
            item.setHidden(search_text not in item.text().lower())
            
    def get_selected_processes(self):
        """Get list of selected processes"""
        return [
            item.data(Qt.ItemDataRole.UserRole)
            for item in self.process_list.selectedItems()
        ]

class SystemCallInterface(QMainWindow):
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.auth_manager = AuthManager()
        self.syscall_monitor = SyscallMonitor()
        self.security_validator = SecurityValidator()
        
        # Initialize state
        self.selected_processes = {}
        self.monitoring_active = False
        self.syscall_stats = defaultdict(int)
        
        # Set up UI
        self.setWindowTitle("System Call Interface")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QToolBar {
                background-color: #2c3e50;
                border: none;
                padding: 8px;
                spacing: 10px;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
            QTableWidget {
                background-color: white;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                gridline-color: #ecf0f1;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QHeaderView::section {
                background-color: #34495e;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QLabel {
                color: #2c3e50;
                font-size: 14px;
            }
            QLabel[heading="true"] {
                font-size: 16px;
                font-weight: bold;
                padding: 10px 0;
            }
            QStatusBar {
                background-color: #2c3e50;
                color: white;
            }
            QSplitter::handle {
                background-color: #bdc3c7;
            }
            QFrame[dashboard="true"] {
                background-color: white;
                border: 1px solid #bdc3c7;
                border-radius: 4px;
                padding: 10px;
                margin: 5px;
            }
        """)
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Create toolbar
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        
        # Add buttons with icons
        self.select_proc_button = QPushButton("Select Processes")
        self.start_button = QPushButton("Start Monitoring")
        self.stop_button = QPushButton("Stop Monitoring")
        self.clear_button = QPushButton("Clear Data")
        self.save_button = QPushButton("Save Logs")
        
        # Add icons to buttons
        style = self.style()
        self.select_proc_button.setIcon(style.standardIcon(QStyle.SP_FileDialogContentsView))
        self.start_button.setIcon(style.standardIcon(QStyle.SP_MediaPlay))
        self.stop_button.setIcon(style.standardIcon(QStyle.SP_MediaStop))
        self.clear_button.setIcon(style.standardIcon(QStyle.SP_DialogResetButton))
        self.save_button.setIcon(style.standardIcon(QStyle.SP_DialogSaveButton))
        
        toolbar.addWidget(self.select_proc_button)
        toolbar.addWidget(self.start_button)
        toolbar.addWidget(self.stop_button)
        toolbar.addWidget(self.clear_button)
        toolbar.addWidget(self.save_button)
        
        # Create main splitter
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)
        
        # Process table section
        process_widget = QWidget()
        process_widget.setProperty("dashboard", True)
        process_layout = QVBoxLayout(process_widget)
        process_label = QLabel("Monitored Processes")
        process_label.setProperty("heading", True)
        process_layout.addWidget(process_label)
        
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(["PID", "Process Name", "Status", "CPU %"])
        self.process_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.process_table.setAlternatingRowColors(True)
        process_layout.addWidget(self.process_table)
        splitter.addWidget(process_widget)
        
        # System call section
        syscall_widget = QWidget()
        syscall_widget.setProperty("dashboard", True)
        syscall_layout = QVBoxLayout(syscall_widget)
        syscall_label = QLabel("System Calls")
        syscall_label.setProperty("heading", True)
        syscall_layout.addWidget(syscall_label)
        
        self.syscall_table = QTableWidget()
        self.syscall_table.setColumnCount(6)  # Changed from 5 to 6 columns
        self.syscall_table.setHorizontalHeaderLabels(["Time", "Process", "PID", "System Call", "Type", "Status"])
        self.syscall_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.syscall_table.setAlternatingRowColors(True)
        syscall_layout.addWidget(self.syscall_table)
        splitter.addWidget(syscall_widget)
        
        # Statistics section
        stats_widget = QWidget()
        stats_widget.setProperty("dashboard", True)
        stats_layout = QVBoxLayout(stats_widget)
        stats_label = QLabel("System Call Statistics")
        stats_label.setProperty("heading", True)
        stats_layout.addWidget(stats_label)
        
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(2)
        self.stats_table.setHorizontalHeaderLabels(["System Call", "Count"])
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.stats_table.setAlternatingRowColors(True)
        stats_layout.addWidget(self.stats_table)
        splitter.addWidget(stats_widget)
        
        # Set splitter sizes
        splitter.setSizes([200, 400, 200])
        
        # Status bar
        self.status_bar = QStatusBar()
        self.monitoring_label = QLabel()
        self.monitoring_label.setStyleSheet("color: white; padding: 5px;")
        self.status_bar.addPermanentWidget(self.monitoring_label)
        self.setStatusBar(self.status_bar)
        
        # Connect signals
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.select_proc_button.clicked.connect(self.show_process_selection)
        self.clear_button.clicked.connect(self.clear_data)
        self.save_button.clicked.connect(self.save_logs)
        
        # Set up update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_tables)
        
        # Initial UI state
        self.update_ui_state()
        
        # Show login dialog
        self.show_login_dialog()
        
    def authenticate_user(self):
        """Show login dialog and authenticate user"""
        dialog = LoginDialog(self.auth_manager, self)
        if dialog.exec():
            username = dialog.username_input.text().strip()
            self.logger.info(f"User {username} logged in successfully")
            return True
        return False
        
    def show_login_dialog(self):
        if not self.authenticate_user():
            self.logger.error("Authentication failed")
            self.close()
            return
        
    def show_process_selection(self):
        """Show process selection dialog"""
        try:
            # Get list of running processes
            processes = []
            # Stop monitoring temporarily while selecting processes
            if self.monitoring_active:
                self.stop_monitoring()
                
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'username'])
                    processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
            # Create and show process selection dialog
            dialog = ProcessSelectionDialog(processes, self)
            dialog.setModal(True)  # Ensure modal behavior
            
            # Show dialog and handle result
            if dialog.exec() == QDialog.DialogCode.Accepted:
                selected = dialog.get_selected_processes()
                self.selected_processes = {
                    proc['pid']: proc
                    for proc in selected
                }
                self.update_process_table()
                self.update_ui_state()
                
        except Exception as e:
            self.logger.error(f"Error showing process selection: {e}\n{traceback.format_exc()}")
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to show process selection: {str(e)}"
            )
            
    def update_process_table(self):
        """Update the process table with latest information"""
        try:
            self.process_table.setRowCount(len(self.selected_processes))
            for i, proc in enumerate(self.selected_processes.values()):
                try:
                    process = psutil.Process(proc['pid'])
                    with process.oneshot():
                        status = "Monitoring" if self.monitoring_active else "Idle"
                        cpu = process.cpu_percent()
                        memory = process.memory_percent()
                        
                        self.process_table.setItem(i, 0, QTableWidgetItem(str(proc['pid'])))
                        self.process_table.setItem(i, 1, QTableWidgetItem(proc['name']))
                        self.process_table.setItem(i, 2, QTableWidgetItem(status))
                        self.process_table.setItem(i, 3, QTableWidgetItem(f"{cpu:.1f}%"))
                        
                        # Color code CPU usage
                        if cpu > 80:
                            self.process_table.item(i, 3).setBackground(QColor(255, 200, 200))
                        elif cpu > 50:
                            self.process_table.item(i, 3).setBackground(QColor(255, 255, 200))
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    self.process_table.setItem(i, 0, QTableWidgetItem(str(proc['pid'])))
                    self.process_table.setItem(i, 1, QTableWidgetItem(proc['name']))
                    self.process_table.setItem(i, 2, QTableWidgetItem("Terminated"))
                    self.process_table.setItem(i, 3, QTableWidgetItem("N/A"))
                    
        except Exception as e:
            self.logger.error(f"Error updating process table: {e}")
            
    def start_monitoring(self):
        """Start monitoring selected processes"""
        try:
            if not self.selected_processes:
                QMessageBox.warning(
                    self,
                    "No Processes Selected",
                    "Please select at least one process to monitor."
                )
                return

            reason_dialog = MonitoringReasonDialog(self)
            if reason_dialog.exec() != QDialog.DialogCode.Accepted:
                return

            monitoring_reason = reason_dialog.get_reason()
            if not monitoring_reason:
                QMessageBox.warning(
                    self,
                    "Monitoring Reason Required",
                    "Please provide a reason for monitoring."
                )
                return

            # Try to start monitoring
            try:
                self.syscall_monitor.start_monitoring(self.selected_processes)
                self.monitoring_active = True
                self.update_ui_state()
                self.status_bar.showMessage(f"Monitoring started: {monitoring_reason}")
                
                # Start the update timer with faster refresh
                self.update_timer.start(100)  # Update every 100ms
                
            except Exception as e:
                self.logger.error(f"Failed to start monitoring: {e}")
                QMessageBox.critical(
                    self,
                    "Monitoring Error",
                    f"Failed to start monitoring: {str(e)}\n\nPlease check the logs for details."
                )
                self.monitoring_active = False
                self.update_ui_state()
                
        except Exception as e:
            self.logger.error(f"Error in start_monitoring: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"An unexpected error occurred: {str(e)}"
            )
            
    def stop_monitoring(self):
        """Stop monitoring processes"""
        try:
            self.update_timer.stop()
            self.syscall_monitor.stop_monitoring()
            self.monitoring_active = False
            self.update_ui_state()
            self.status_bar.showMessage("Monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to stop monitoring: {str(e)}"
            )
            
    def update_ui_state(self):
        """Update UI elements based on current state"""
        self.stop_button.setEnabled(self.monitoring_active)
        self.start_button.setEnabled(not self.monitoring_active and bool(self.selected_processes))
        self.select_proc_button.setEnabled(not self.monitoring_active)
        
        if self.monitoring_active:
            self.monitoring_label.setText("Monitoring Active")
            self.monitoring_label.setStyleSheet("color: #2ecc71; font-weight: bold; padding: 5px;")
        else:
            self.monitoring_label.setText("Monitoring Inactive")
            self.monitoring_label.setStyleSheet("color: #e74c3c; font-weight: bold; padding: 5px;")
            
    def update_tables(self):
        """Update all tables"""
        self._process_syscall_queue()
        self.update_process_table()
        self.update_syscall_table()
        self.update_stats_table()
        
    def update_syscall_table(self):
        """Update the syscall table with latest data"""
        try:
            if not self.monitoring_active:
                return
                
            while not self.syscall_monitor.syscall_queue.empty():
                try:
                    syscall_info = self.syscall_monitor.syscall_queue.get_nowait()
                    pid = syscall_info.get("pid", "Unknown")

                    if pid in self.selected_processes or syscall_info.get("syscall") in ["file_read" , "file_write"]:  # Ensure it's a monitored process
                        self._add_syscall_to_table(syscall_info)
                except queue.Empty:
                    break
                except Exception as e:
                    self.logger.error(f"Error updating syscall info for PID {pid}: {e}")
                    
            # Update process information
            self.update_process_table()
                    
        except Exception as e:
            self.logger.error(f"Error in update_syscall_table: {e}")
            self.stop_monitoring()
            QMessageBox.critical(
                self,
                "Error",
                "Failed to update syscall information. Monitoring has been stopped."
            )
            
    def _add_syscall_to_table(self, syscall_info):
        """Add a syscall entry to the syscall table with improved formatting"""
        try:
            row = self.syscall_table.rowCount()
            # Limit the number of displayed entries to the last 100
            if row >= 100:
                self.syscall_table.removeRow(0)  # Remove the oldest entry
            self.syscall_table.insertRow(row)
            
            # Ensure time is formatted as a string
            formatted_time = syscall_info["time"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(syscall_info["time"], datetime) else str(syscall_info["time"])
            time_item = QTableWidgetItem(formatted_time)
            process_item = QTableWidgetItem(syscall_info.get("process", "Unknown"))
            pid_item = QTableWidgetItem(str(syscall_info.get("pid", "N/A")))
            syscall_item = QTableWidgetItem(str(syscall_info.get("syscall", "thread_operation")))
            type_item = QTableWidgetItem(syscall_info.get("category","COMMUNICATION" ))
            status_item = QTableWidgetItem(syscall_info.get("status", "Unknown"))
            
            # Set colors based on status
            if syscall_info.get("status") == "Success":
                status_item.setForeground(QColor("#27ae60"))
            else:
                status_item.setForeground(QColor("#c0392b"))
                
            # Set colors based on system call type
            type_colors = {
                "PROCESS_CONTROL": "#3498db",  # Blue
                "FILE_MANAGEMENT": "#27ae60",  # Green
                "DEVICE_MANAGEMENT": "#f1c40f", # Yellow
                "INFORMATION_MAINTENANCE": "#9b59b6", # Purple
                "COMMUNICATION": "#e67e22",  # Orange
                "UNKNOWN": "#95a5a6"  # Gray
            }
            
            if type_item.text() in type_colors:
                type_item.setForeground(QColor(type_colors[type_item.text()]))
                
            self.syscall_table.setItem(row, 0, time_item)
            self.syscall_table.setItem(row, 1, process_item)
            self.syscall_table.setItem(row, 2, pid_item)
            self.syscall_table.setItem(row, 3, syscall_item)
            self.syscall_table.setItem(row, 4, type_item)
            self.syscall_table.setItem(row, 5, status_item)
            
            # Update statistics
            syscall_name = str(syscall_info.get("syscall", "Unknown"))
            self.syscall_stats[syscall_name] += 1
            
        except Exception as e:
            logging.error(f"Error updating syscall info for PID: {str(e)}")

    def _process_syscall_queue(self):
        """Process syscalls from the queue"""
        try:
            while True:  # Process all available syscalls
                try:
                    syscall_info = self.syscall_monitor.syscall_queue.get_nowait()
                    print(f"Processing syscall: {syscall_info}")  # Debug print
                    
                    if syscall_info:
                        self._add_syscall_to_table(syscall_info)
                        print(f"Added syscall to table: {syscall_info}")  # Debug print
                        
                except queue.Empty:
                    break
                    
        except Exception as e:
            print(f"Error processing syscall queue: {e}")
            self.logger.error(f"Error processing syscall queue: {e}")

    def update_stats_table(self):
        """Update the statistics table"""
        self.stats_table.setRowCount(0)
        
        # Create a mapping for more descriptive names
        syscall_descriptions = {
            'File Open': 'File Opens (Read/Write)',
            'File Created': 'New Files Created',
            'File Updated': 'Files Modified',
            'File Deleted': 'Files Deleted',
            'Network 2': 'TCP Network Connections',
            'Network 1': 'UDP Network Connections',
            'Registry access': 'Registry Key Access',
            'Registry write': 'Registry Key Modifications',
            'memory_usage': 'Memory Usage Events',
            'memory_map': 'Memory Mapping Operations',
            'handle_operation': 'Handle Operations',
            'thread_operation': 'Thread Operations',
            'dll_load': 'DLL Loading Events'
        }
        
        # Sort by count in descending order
        sorted_stats = sorted(self.syscall_stats.items(), key=lambda x: x[1], reverse=True)
        
        for syscall, count in sorted_stats:
            row = self.stats_table.rowCount()
            self.stats_table.insertRow(row)
            
            # Use more descriptive name if available
            display_name = syscall_descriptions.get(syscall, syscall)
            
            # Create items
            name_item = QTableWidgetItem(display_name)
            count_item = QTableWidgetItem(str(count))
            
            # Right-align the count
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            
            # Add tooltip with description
            if syscall.startswith('Network'):
                name_item.setToolTip("Network connections made by the process")
            elif syscall.startswith('File'):
                name_item.setToolTip("File system operations by the process")
            elif syscall.startswith('Registry'):
                name_item.setToolTip("Windows Registry operations")
            elif syscall == 'memory_usage':
                name_item.setToolTip("Process memory consumption events (>100MB)")
            elif syscall == 'memory_map':
                name_item.setToolTip("Memory mapping operations (shared memory, file mapping)")
            elif syscall == 'handle_operation':
                name_item.setToolTip("File, registry, and other handle operations")
            elif syscall == 'thread_operation':
                name_item.setToolTip("Thread creation and state changes")
            elif syscall == 'dll_load':
                name_item.setToolTip("Dynamic-link library loading events")
                
            self.stats_table.setItem(row, 0, name_item)
            self.stats_table.setItem(row, 1, count_item)
            
    def clear_data(self):
        """Clear all tables, statistics, and chart data"""
        self.syscall_table.setRowCount(0)
        self.stats_table.setRowCount(0)
        self.syscall_stats.clear()
        
        self.update_stats_table()
        
    def save_logs(self):
        """Save system call logs to a file"""
        try:
            filename = QFileDialog.getSaveFileName(
                self,
                "Save System Call Logs",
                "",
                "Text Files (*.txt);;All Files (*.*)"
            )[0]
            
            if filename:
                with open(filename, 'w') as f:
                    # Write header
                    f.write("Time\tProcess\tPID\tSystem Call\tType\tStatus\n")
                    
                    # Write each row
                    for row in range(self.syscall_table.rowCount()):
                        time = self.syscall_table.item(row, 0).text()
                        process = self.syscall_table.item(row, 1).text()
                        pid = self.syscall_table.item(row, 2).text()
                        syscall = self.syscall_table.item(row, 3).text()
                        type = self.syscall_table.item(row, 4).text()
                        status = self.syscall_table.item(row, 5).text()
                        
                        f.write(f"{time}\t{process}\t{pid}\t{syscall}\t{type}\t{status}\n")
                        
                self.status_bar.showMessage("Logs saved successfully", 3000)
                
        except Exception as e:
            logging.error(f"Error saving logs: {str(e)}")
            QMessageBox.warning(self, "Error", "Failed to save logs")
            
    def closeEvent(self, event):
        if self.monitoring_active:
            reply = QMessageBox.question(
                self,
                "Confirm Exit",
                "Monitoring is still active. Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
                
        self.stop_monitoring()
        event.accept()
