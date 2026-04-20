import firebase_admin
from firebase_admin import credentials, firestore
from firebase_admin.firestore import SERVER_TIMESTAMP
import bcrypt
import os
from datetime import datetime, timedelta

# Initialize Firebase Admin SDK
def initialize_firebase():
    """Initialize Firebase Admin SDK with credentials"""
    try:
        # Check if Firebase is already initialized
        firebase_admin.get_app()
        return True
    except ValueError:
        # Firebase not initialized, so initialize it
        # Look for firebase-adminsdk.json in the current directory
        cred_path = os.path.join(os.path.dirname(__file__), 'firebase-adminsdk.json')
        if os.path.exists(cred_path):
            try:
                cred = credentials.Certificate(cred_path)
                firebase_admin.initialize_app(cred)
                return True
            except Exception as e:
                print(f"Failed to initialize Firebase with credentials file: {e}")
                return False
        else:
            # If no credentials file, try to initialize without credentials
            # This will only work if running on Google Cloud Platform
            try:
                firebase_admin.initialize_app()
                return True
            except Exception as e:
                print(f"Failed to initialize Firebase without credentials: {e}")
                print("Firebase will not be available. Some features may not work.")
                return False

# Try to initialize Firebase when module is imported
firebase_initialized = initialize_firebase()

# Firestore database instance - only create if Firebase was initialized
firestore_db = None
if firebase_initialized:
    try:
        firestore_db = firestore.client()
    except Exception as e:
        pass  # Silent fail - will handle gracefully in routes

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(hashed_password, password):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_user_by_username(username):
    """Get user data by username"""
    if not firestore_db:
        print("Firebase not initialized - cannot get user by username")
        return None, None

    try:
        users_ref = firestore_db.collection('users')
        query = users_ref.where('username', '==', username).limit(1)
        docs = query.stream()

        for doc in docs:
            return doc.to_dict(), doc.id

        return None, None
    except Exception as e:
        print(f"Error getting user by username: {e}")
        return None, None

def create_user_session(user_id, device_info=None):
    """Create a new user session"""
    if not firestore_db:
        print("Firebase not initialized - cannot create user session")
        return None

    try:
        session_data = {
            'user_id': user_id,
            'created_at': SERVER_TIMESTAMP,
            'last_activity': SERVER_TIMESTAMP,
            'is_active': True,
            'device_info': device_info or {},
            'flow_count': 0,
            'risk_counts': {
                'low': 0,
                'medium': 0,
                'high': 0,
                'very_high': 0
            }
        }

        doc_ref = firestore_db.collection('user_sessions').document()
        doc_ref.set(session_data)

        return doc_ref.id
    except Exception as e:
        print(f"Error creating user session: {e}")
        return None

def save_malicious_flow(user_id, session_id, flow_data):
    """Save malicious flow data to Firestore"""
    if not firestore_db:
        print("Firebase not initialized - cannot save malicious flow")
        return None

    try:
        flow_doc = {
            'user_id': user_id,
            'session_id': session_id,
            'flow_data': flow_data,
            'timestamp': SERVER_TIMESTAMP,
            'risk_level': flow_data.get('risk_level', 'unknown'),
            'classification': flow_data.get('classification', 'unknown')
        }

        doc_ref = firestore_db.collection('malicious_flows').document()
        doc_ref.set(flow_doc)

        # Update session counters
        risk_level = flow_data.get('risk_level', 'low')
        if risk_level in ['low', 'medium', 'high', 'very_high']:
            increment_high_risk_count(session_id, risk_level)

        return doc_ref.id
    except Exception as e:
        print(f"Error saving malicious flow: {e}")
        return None

def increment_high_risk_count(session_id, risk_level):
    """Increment the risk count for a session"""
    if not firestore_db:
        print("Firebase not initialized - cannot increment risk count")
        return

    try:
        session_ref = firestore_db.collection('user_sessions').document(session_id)
        session_doc = session_ref.get()

        if session_doc.exists:
            current_counts = session_doc.to_dict().get('risk_counts', {
                'low': 0, 'medium': 0, 'high': 0, 'very_high': 0
            })

            if risk_level in current_counts:
                current_counts[risk_level] += 1

            session_ref.update({
                'risk_counts': current_counts,
                'last_activity': SERVER_TIMESTAMP
            })
    except Exception as e:
        print(f"Error incrementing risk count: {e}")

def update_global_stats():
    """Update global statistics"""
    if not firestore_db:
        print("Firebase not initialized - cannot update global stats")
        return

    try:
        # Get current stats
        stats_ref = firestore_db.collection('global_stats').document('current')
        stats_doc = stats_ref.get()

        current_stats = stats_doc.to_dict() if stats_doc.exists else {
            'total_users': 0,
            'total_sessions': 0,
            'total_flows': 0,
            'total_malicious_flows': 0,
            'last_updated': SERVER_TIMESTAMP
        }

        # Count users
        users_count = firestore_db.collection('users').count().get()
        current_stats['total_users'] = users_count[0].value if users_count else 0

        # Count sessions
        sessions_count = firestore_db.collection('user_sessions').count().get()
        current_stats['total_sessions'] = sessions_count[0].value if sessions_count else 0

        # Count flows
        flows_count = firestore_db.collection('malicious_flows').count().get()
        current_stats['total_malicious_flows'] = flows_count[0].value if flows_count else 0

        # Update timestamp
        current_stats['last_updated'] = SERVER_TIMESTAMP

        # Save updated stats
        stats_ref.set(current_stats, merge=True)

    except Exception as e:
        print(f"Error updating global stats: {e}")