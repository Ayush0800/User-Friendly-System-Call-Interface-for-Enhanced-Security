import sys
import os
import logging
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import QTimer
import platform
import signal
import ctypes
import traceback

# Configure logging to both file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'syscall_monitor.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add the src directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frontend.main_window import SystemCallInterface

def show_error_message(message):
    """Show error message in a dialog box"""
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Critical)
    msg.setText("Application Error")
    msg.setInformativeText(message)
    msg.setWindowTitle("Error")
    msg.exec()

def is_admin():
    """Check if the application is running with administrator privileges on Windows"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logger.error(f"Error checking admin privileges: {e}")
        return False

def check_admin():
    """Check if the application is running with administrator privileges"""
    logger.debug("Checking administrator privileges")
    if not is_admin():
        logger.error("Application must be run with administrator privileges")
        print("Error: This application requires administrator privileges.")
        print("Please right-click and select 'Run as administrator'.")
        sys.exit(1)
    logger.debug("Administrator privileges confirmed")

def main():
    try:
        # Check for administrator privileges
        check_admin()
        
        logger.debug("Initializing QApplication")
        app = QApplication(sys.argv)
        
        # Ensure clean shutdown
        app.aboutToQuit.connect(app.deleteLater)
        
        try:
            logger.debug("Creating main window")
            window = SystemCallInterface()
            
            logger.debug("Showing main window")
            window.show()
            
            logger.debug("Entering Qt event loop")
            return app.exec_()
            
        except Exception as window_error:
            error_msg = f"Error initializing application: {str(window_error)}\n\n{traceback.format_exc()}"
            logger.error(error_msg)
            show_error_message(error_msg)
            return 1
            
    except Exception as e:
        error_msg = f"Fatal error: {str(e)}\n\n{traceback.format_exc()}"
        logger.error(error_msg)
        show_error_message(error_msg)
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logger.error(f"Uncaught exception: {e}\n{traceback.format_exc()}")
        show_error_message(f"Uncaught exception: {str(e)}")
        sys.exit(1)
