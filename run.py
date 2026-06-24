import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Add current directory to path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app import create_app

app = create_app()

if __name__ == '__main__':
    print("Starting Secure Password Lifecycle Management System...")
    app.run(host='127.0.0.1', port=5000, debug=True)
