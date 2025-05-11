import os
import sys
from app import app

if __name__ == '__main__':
    # Ensure we're in the correct directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Run the Flask application directly
    app.run(host='127.0.0.1', port=5001, debug=False) 