
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, timedelta
import uuid
import bcrypt
import stripe
import os

# Flask app setup
app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-skilltrek')
jwt = JWTManager(app)

# Stripe setup (use your own secret key here)
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY', 'sk_test_YOUR_SECRET_KEY')

# In-memory mock database
users = []
opportunities = []
applications = []
messages = []
interviews = []
resumes = []
sponsorships = []

def generate_id(): return str(uuid.uuid4())
def hash_password(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def check_password(pw, hashed): return bcrypt.checkpw(pw.encode(), hashed.encode())
def find_user_by_id(uid): return next((u for u in users if u['id'] == uid), None)

# User signup
@app.route('/auth/signup', methods=['POST'])
def signup():
    data = request.json
    if any(u['email'] == data['email'] for u in users):
        return jsonify({"error": "Email already registered"}), 400
    new_user = {
        "id": generate_id(),
        "name": data['name'],
        "email": data['email'],
        "password": hash_password(data['password']),
        "role": data['role'],
        "skills": data.get('skills', []),
        "location": data.get('location', ''),
        "bio": data.get('bio', ''),
        "joined": datetime.utcnow().isoformat()
    }
    users.append(new_user)
    return jsonify(new_user), 201

# User login
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    user = next((u for u in users if u['email'] == data['email']), None)
    if not user or not check_password(data['password'], user['password']):
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_access_token(identity=user['id'], expires_delta=timedelta(days=7))
    return jsonify({"token": token, "user": user}), 200

# Post job (sponsor only)
@app.route('/opportunity', methods=['POST'])
@jwt_required()
def post_opportunity():
    uid = get_jwt_identity()
    data = request.json
    job = {
        "id": generate_id(),
        "sponsor_id": uid,
        "title": data['title'],
        "description": data['description'],
        "skills_required": data['skills_required'],
        "location": data['location'],
        "start_date": data.get('start_date'),
        "end_date": data.get('end_date'),
        "perks": data.get('perks', [])
    }
    opportunities.append(job)
    return jsonify(job), 201

# Resume upload (traveler only)
@app.route('/resume', methods=['POST'])
@jwt_required()
def upload_resume():
    uid = get_jwt_identity()
    data = request.json
    resumes.append({
        "user_id": uid,
        "resume_url": data['url'],
        "uploaded": datetime.utcnow().isoformat()
    })
    return jsonify({"message": "Resume uploaded"}), 200

# Schedule interview (sponsor only)
@app.route('/interview', methods=['POST'])
@jwt_required()
def schedule_interview():
    uid = get_jwt_identity()
    data = request.json
    interviews.append({
        "id": generate_id(),
        "sponsor_id": uid,
        "traveler_id": data['traveler_id'],
        "datetime": data['datetime'],
        "link": data.get('link')
    })
    return jsonify({"message": "Interview scheduled"}), 200

# Send message (both roles)
@app.route('/chat/send', methods=['POST'])
@jwt_required()
def send_message():
    uid = get_jwt_identity()
    data = request.json
    messages.append({
        "id": generate_id(),
        "sender_id": uid,
        "receiver_id": data['receiver_id'],
        "message": data['message'],
        "timestamp": datetime.utcnow().isoformat()
    })
    return jsonify({"message": "Message sent"}), 200

# Get matches
@app.route('/match', methods=['GET'])
@jwt_required()
def get_matches():
    uid = get_jwt_identity()
    user = find_user_by_id(uid)
    if user['role'] == 'traveler':
        match_jobs = [job for job in opportunities if set(user['skills']) & set(job['skills_required'])]
        return jsonify(match_jobs), 200
    elif user['role'] == 'sponsor':
        matched_travelers = [u for u in users if u['role'] == 'traveler']
        return jsonify(matched_travelers), 200
    return jsonify([]), 403

# Stripe checkout session (confirm match or subscribe)
@app.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout():
    uid = get_jwt_identity()
    data = request.json
    mode = data.get('mode')
    if mode == 'confirm':
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': 'SkillTrek Match Confirmation'},
                    'unit_amount': 9900
                },
                'quantity': 1
            }],
            mode='payment',
            success_url='https://skilltrek.com/success',
            cancel_url='https://skilltrek.com/cancel',
            metadata={'user_id': uid, 'type': 'confirm'}
        )
    elif mode == 'subscription':
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'recurring': {'interval': 'month'},
                    'product_data': {'name': 'SkillTrek Pro Subscription'},
                    'unit_amount': 2900
                },
                'quantity': 1
            }],
            mode='subscription',
            success_url='https://skilltrek.com/success',
            cancel_url='https://skilltrek.com/cancel',
            metadata={'user_id': uid, 'type': 'subscription'}
        )
    else:
        return jsonify({'error': 'Invalid mode'}), 400

    return jsonify({'url': session.url})

# Stripe webhook (optional)
@app.route('/stripe/webhook', methods=['POST'])
def stripe_webhook():
    event = request.json
    sponsorships.append({"event": event, "timestamp": datetime.utcnow().isoformat()})
    return jsonify({'status': 'received'})

# Server start
if __name__ == '__main__':
    app.run(debug=True)
