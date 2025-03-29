# User-Friendly System Call Interface for Enhanced Security

## Introduction
This project provides a user-friendly graphical interface to monitor and control system calls for enhanced security. It helps track system activities, detect suspicious behaviors, and enforce security policies by requiring administrative privileges to run.

## Features
- **System Call Monitoring**: Logs and displays system calls made by running processes.
- **User-Friendly Interface**: Built using PyQt5 for an intuitive GUI.
- **Security Enforcement**: Ensures the application runs with administrator privileges.
- **Logging**: Stores logs in `syscall_monitor.log` for debugging and analysis.
- **Customizable Configuration**: Supports security settings and monitoring customization.

## Requirements
Before running the project, install the necessary dependencies:
```sh
pip install -r requirements.txt
```

## Installation & Setup
1. Clone the repository:
   ```sh
   git clone https://github.com/Ayush0800/User-Friendly-System-Call-Interface-for-Enhanced-Security.git
   ```
2. Navigate to the project directory:
   ```sh
   cd User-Friendly-System-Call-Interface-for-Enhanced-Security
   ```
3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Running the Application
Since the application requires administrator privileges, follow these steps:
### Windows
1. Open a terminal as Administrator.
2. Navigate to the project directory.
3. Run:
   ```sh
   python src/main.py
   ```

## File Structure
```
├── requirements.txt        # Dependencies
├── run_as_admin.bat        # Windows batch file for running as admin
├── setup_admin.py          # Script for admin privilege setup
├── security_config.json    # Security configuration settings
├── src/
│   ├── config/
│   │   ├── __init__.py
│   │   ├── default_config.py
│   ├── frontend/
│   │   ├── __init__.py
│   │   ├── main_window.py  # GUI implementation
│   │   ├── monitoring_reason_dialog.py
│   ├── main.py             # Entry point of the application
│   ├── monitor/
│   │   ├── __init__.py
│   │   ├── syscall_monitor.py  # System call monitoring logic
│   ├── security/
│   │   ├── __init__.py
│   │   ├── auth.py          # Authentication and security checks
│   │   ├── security_validator.py  # Security enforcement
```

## Logging
Logs are stored in `syscall_monitor.log` located in the project directory. It captures system calls, errors, and warnings for debugging.

## Troubleshooting
### Issue: "Error: This application requires administrator privileges."
- Ensure you're running the script in an Administrator terminal.
- Use `run_as_admin.bat` to execute the script.

### Issue: "ModuleNotFoundError: No module named 'PyQt5'"
- Run `pip install PyQt5` to install the missing module.

## Contributing
Feel free to contribute by submitting issues or pull requests.



