import os
from flask import Flask, request, jsonify
from clerk_backend_api import Clerk
from dotenv import load_dotenv
import requests

load_dotenv()
app = Flask(__name__)
CLERK_TEST_KEY = os.environ.get("CLERK_TEST_KEY")
clerk = Clerk(CLERK_TEST_KEY)


def authenticate_user():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "No authorization token provided"}), 401

    try:
        # Verify the session token with Clerk
        session = clerk.sessions.verify_token(token.split()[1])
        # Add user_id to the request context
        request.user_id = session['sub']
        return None
    except Exception as e:
        return jsonify({"error": "Invalid authorization token"}), 401


# Routes
@app.route('/api/user', methods=['GET'])
def get_user():
    """Get information about the authenticated user"""
    # Authenticate the user
    error_response = authenticate_user()
    if error_response:
        return error_response

    # In a real app, you'd fetch user data from a database
    return jsonify({"user_id": request.user_id})


if __name__ == '__main__':
    app.run(debug=True)
