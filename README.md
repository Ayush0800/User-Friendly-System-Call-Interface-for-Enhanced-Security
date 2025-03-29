# User-Friendly System Call Interface for Enhanced Security

## Introduction
This project provides a user-friendly graphical interface to monitor and control system calls for enhanced security. It helps track system activities, detect suspicious behaviors, and enforce security policies by requiring administrative privileges to run.

## Features
- **System Call Monitoring:** Logs and displays system calls made by running processes.
- **User-Friendly Interface:** Built using PyQt5 for an intuitive GUI.
- **Security Enforcement:** Ensures the application runs with administrator privileges.
- **Logging:** Stores logs in `syscall_monitor.log` for debugging and analysis.
- **Customizable Configuration:** Supports security settings and monitoring customization.

## Requirements
Before running the project, install the necessary dependencies:
```sh
pip install -r requirements.txt
```

## Installation & Setup
### Clone the repository:
```sh
git clone https://github.com/Ayush0800/User-Friendly-System-Call-Interface-for-Enhanced-Security.git
```

### Navigate to the project directory:
```sh
cd User-Friendly-System-Call-Interface-for-Enhanced-Security
```

### Install dependencies:
```sh
pip install -r requirements.txt
```

## Running the Application
Since the application requires administrator privileges, follow these steps:

### Windows
#### Run the script as Administrator:
- Use `run_as_admin.bat` to launch the application with admin privileges.
- Alternatively, open a terminal as Administrator and navigate to the project directory.
- Then run:
```sh
python src/main.py
```

### Login Credentials:
- **Username:** admin
- **Password:** admin123

## Login Interface
Below is the login screen users will see when launching the application:
![Login](https://github.com/user-attachments/assets/73f5f40c-8e40-41f8-8508-9b8dca102a9a)


## System Call Monitoring Dashboard
Once logged in, users can monitor system calls in real-time through the dashboard:
![Dashboard](https://github.com/user-attachments/assets/ff51bee7-cbec-4dd2-9062-24841677b6e8)

## File Structure
```bash
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

## License
MIT License

## Author
**Ayush Kumar**

