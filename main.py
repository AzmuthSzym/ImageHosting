import os
from datetime import datetime
from flask import Flask, request, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv
from google.cloud import storage

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Database setup
client = MongoClient("mongodb://localhost:27017/")
db = client['image_hosting']
users = db['users']
images = db['images']
api_keys = db['api_keys']

GCP_KEY = os.environ.get("GCP_FILE")
storage_client = storage.Client.from_service_account_json(GCP_KEY)


class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = str(user_data['email'])
        self.api_key = str(user_data['api_key'])


@login_manager.user_loader
def load_user(user_id):
    user_data = users.find_one({'_id': user_id})
    return User(user_data) if user_data else None


# Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if users.find_one({'email': email}):
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user_data = {
        'email': email,
        'password': hashed_password,
        'api_key': 'TO BE DONE'
    }
    users.insert_one(user_data)
    return jsonify({'message': 'User registered successfully'})


# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user_data = users.find_one({'email': data.get('email')})

    if user_data and bcrypt.check_password_hash(user_data['password'], data.get('password')):
        user = User(user_data)
        login_user(user)
        token = user.get_id()  # Get the user's session token
        return jsonify({'message': 'Logged in successfully', 'token': token})

    return jsonify({'message': 'Invalid credentials'}), 401


# Upload
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    if not allowed_file(file.filename):
        return jsonify({'message': 'File type not allowed'}), 400

    filename = generate_unique_filename(file.filename)
    bucket_name = 'my-image-hosting-100'
    folder_name = 'ImageHosting'
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(f'{folder_name}/{filename}')

    generation_match_precondition = 0
    blob.upload_from_file(file)
    url = blob.public_url

    # Save the file metadata in MongoDB
    image_data = {
        'filename': filename,
        'user_id': current_user.id,
        'url': url,
        'timestamp': datetime.now()
    }
    images.insert_one(image_data)

    return jsonify({'message': 'File uploaded successfully', 'url': url})


@app.route('/upload2', methods=['POST'])
def upload2():
    token = request.headers.get('Authorization')
    if token and token.startswith('Bearer '):
        token = token.split(' ')[1]
        user = load_user(token)
        if user:
            login_user(user)
            # Your existing upload logic here
            return jsonify({'message': 'File uploaded successfully'})

    return jsonify({'message': 'Unauthorized'}), 401


# Protected test
@app.route('/protected')
@login_required
def protected():
    return jsonify({'message': f'Hello {current_user.email}'})


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_unique_filename(filename):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    _, extension = os.path.splitext(filename)
    return f"{timestamp}{extension}"


if __name__ == '__main__':
    app.run(debug=True)
