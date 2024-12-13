import os
import secrets
from datetime import datetime
from bson import ObjectId
from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
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
    try:
        user_data = users.find_one({'_id': ObjectId(user_id)})
        return User(user_data) if user_data else None
    except:
        return None


@app.route('/')
def index():
    return render_template('landing.html')


# Registration
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    email = request.form.get('email')
    password = request.form.get('password')

    if users.find_one({'email': email}):
        return jsonify({'error': 'User already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user_data = {
        'email': email,
        'password': hashed_password,
        'api_key': None
    }
    users.insert_one(user_data)
    return jsonify({'message': 'User registered successfully'})


# Login
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    user_data = users.find_one({'email': data.get('email')})

    if user_data and bcrypt.check_password_hash(user_data['password'], data.get('password')):
        user = User(user_data)
        login_user(user)
        return redirect(url_for('dashboard'))
        # return jsonify({'message': 'Logged in successfully', 'token': token})

    return render_template('login.html', error="Invalid credentials")
    # return jsonify({'message': 'Invalid credentials'}), 401


# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


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
        'timestamp': datetime.now(),
        'access_type': "private"
    }
    images.insert_one(image_data)

    return jsonify({'message': 'File uploaded successfully', 'url': url})


@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    # print("Dashboard accessed")
    # print("Is authenticated:", current_user.is_authenticated)
    # print("Current user:", current_user)
    user_images = images.find({'user_id': current_user.id})
    return render_template('dashboard.html', images=user_images)


@app.route('/generate-api-key', methods=['POST'])
@login_required
def generate_api_key():
    new_key = update_user_api_key(current_user.id)
    if new_key:
        flash('API key generated successfully')
    else:
        flash('Error generating API key')
    return redirect(url_for('dashboard'))


@app.route('/regenerate-api-key', methods=['POST'])
@login_required
def regenerate_api_key():
    new_key = update_user_api_key(current_user.id)
    if new_key:
        flash('API key regenerated successfully')
    else:
        flash('Error regenerating API key')
    return redirect(url_for('dashboard'))


@app.route('/delete-image/<image_id>', methods=['POST'])
@login_required
def delete_image(image_id):
    try:
        image = images.find_one({
            '_id': ObjectId(image_id),
            'user_id': current_user.id
        })
        if image:
            filename = image.get('url')
            bucket_name = 'my-image-hosting-100'
            folder_name = 'ImageHosting'
            bucket = storage_client.get_bucket(bucket_name)
            blob = bucket.blob(f'{folder_name}/{filename[65:]}')

            generation_match_precondition = 0
            blob.delete()
            flash('Image deleted successfully')
            images.delete_one({
                '_id': ObjectId(image_id)
            })
    except Exception as e:
        flash('Error deleting image', 'error')
    return redirect(url_for('dashboard'))


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


def is_key_unique(api_key):
    # Check if this key exists in database
    existing_user = users.find_one({'api_key': api_key})
    return existing_user is None


def generate_unique_api_key():
    while True:
        new_key = secrets.token_hex(32)
        if is_key_unique(new_key):
            return new_key


def update_user_api_key(user_id):
    new_key = generate_unique_api_key()

    result = users.update_one(
        {'_id': ObjectId(user_id)},  # Find user by ID
        {'$set': {'api_key': new_key}}  # Set new API key
    )
    if result.modified_count > 0:
        return new_key
    return None


if __name__ == '__main__':
    app.run(debug=True)
