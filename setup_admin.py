from src.security.auth import AuthManager

def setup_admin():
    auth_manager = AuthManager()
    username = "admin"
    password = "admin123"  # You should change this after first login
    
    success = auth_manager.create_user(username, password, is_admin=True)
    if success:
        print(f"Admin account created successfully!")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print("\nPlease change your password after first login.")
    else:
        print("Admin account already exists.")

if __name__ == "__main__":
    setup_admin()
