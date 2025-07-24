#!/usr/bin/env python3

import os
import json
import secrets
import sqlite3
import hashlib
import requests
import re
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from functools import wraps

app = Flask(__name__)

# Configuration
ACME_DNS_URL = "http://acme-dns:8080"
DATABASE_PATH = "/data/registrations.db"
MASTER_KEY = os.getenv("MASTER_API_KEY", "")

if not MASTER_KEY:
    raise ValueError("MASTER_API_KEY environment variable is required")

def get_db():
    """Get database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database with required tables"""
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT UNIQUE NOT NULL,
            key_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            organization TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            usage_count INTEGER DEFAULT 0,
            last_used_at TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key_id TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            domain_hint TEXT,
            client_ip TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (api_key_id) REFERENCES api_keys (key_id)
        );
        
        CREATE INDEX IF NOT EXISTS idx_api_keys_key_id ON api_keys(key_id);
        CREATE INDEX IF NOT EXISTS idx_registrations_api_key ON registrations(api_key_id);
    ''')
    db.commit()

def hash_key(key):
    """Hash an API key for storage"""
    return hashlib.sha256(key.encode()).hexdigest()

def escape_like_pattern(pattern):
    """Escape special characters in LIKE patterns to prevent injection"""
    # Escape SQLite LIKE special characters
    return pattern.replace('%', '\\%').replace('_', '\\_').replace('\\', '\\\\')

def validate_domain(domain):
    """Validate domain name format"""
    if not domain or len(domain) > 253:
        return False
    
    # Basic domain regex - allows valid domain characters
    domain_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$'
    )
    return bool(domain_pattern.match(domain))

def validate_email(email):
    """Basic email validation"""
    if not email:
        return True  # Email is optional
    
    if len(email) > 254:
        return False
    
    # Basic email pattern
    email_pattern = re.compile(r'^[^@]+@[^@]+\.[^@]+$')
    return bool(email_pattern.match(email))

def sanitize_string(value, max_length=255):
    """Sanitize string input"""
    if not value:
        return ""
    
    # Strip whitespace and limit length
    sanitized = str(value).strip()[:max_length]
    
    # Remove control characters
    sanitized = ''.join(char for char in sanitized if ord(char) >= 32 or char in '\t\n\r')
    
    return sanitized

def generate_api_key():
    """Generate a new API key"""
    return f"acmedns_{secrets.token_urlsafe(32)}"

def require_master_key(f):
    """Decorator to require master key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid authorization header"}), 401
        
        provided_key = auth_header[7:]  # Remove 'Bearer ' prefix
        if not secrets.compare_digest(provided_key, MASTER_KEY):
            return jsonify({"error": "Invalid credentials"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def require_api_key(f):
    """Decorator to require valid API key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({"error": "Missing API key"}), 401
        
        db = get_db()
        key_hash = hash_key(api_key)
        
        # Check if key exists and is valid
        key_record = db.execute('''
            SELECT key_id, name, expires_at, is_active 
            FROM api_keys 
            WHERE key_hash = ? AND is_active = 1
        ''', (key_hash,)).fetchone()
        
        if not key_record:
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Check expiration
        if key_record['expires_at']:
            try:
                expires_at = datetime.fromisoformat(key_record['expires_at'])
                if datetime.utcnow() > expires_at:
                    return jsonify({"error": "Invalid credentials"}), 401
            except ValueError:
                return jsonify({"error": "Invalid credentials"}), 401
        
        # Update usage statistics
        db.execute('''
            UPDATE api_keys 
            SET usage_count = usage_count + 1, last_used_at = CURRENT_TIMESTAMP
            WHERE key_id = ?
        ''', (key_record['key_id'],))
        db.commit()
        
        # Store key info in request context
        g.api_key_id = key_record['key_id']
        g.api_key_name = key_record['name']
        
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def initialize():
    """Initialize database before each request (with check to avoid multiple inits)"""
    if not hasattr(g, '_database_initialized'):
        init_db()
        g._database_initialized = True

@app.teardown_appcontext
def close_db_connection(exception):
    """Close database connection after request"""
    close_db(exception)

# Master key endpoints (for internal management)

@app.route('/admin/keys', methods=['POST'])
@require_master_key
def create_api_key():
    """Create a new API key"""
    try:
        data = request.get_json() or {}
        
        # Sanitize and validate inputs
        name = sanitize_string(data.get('name', ''), 100)
        email = sanitize_string(data.get('email', ''), 254)
        organization = sanitize_string(data.get('organization', ''), 100)
        expires_days = data.get('expires_days')
        
        # Validation
        if not name:
            return jsonify({"error": "Name is required"}), 400
        
        if email and not validate_email(email):
            return jsonify({"error": "Invalid email format"}), 400
        
        if expires_days is not None:
            try:
                expires_days = int(expires_days)
                if expires_days <= 0 or expires_days > 3650:  # Max 10 years
                    return jsonify({"error": "Expiration days must be between 1 and 3650"}), 400
            except (ValueError, TypeError):
                return jsonify({"error": "Invalid expiration days"}), 400
    
    # Generate new key
    api_key = generate_api_key()
    key_id = f"key_{secrets.token_hex(8)}"
    key_hash = hash_key(api_key)
    
    # Calculate expiration
    expires_at = None
    if expires_days:
        expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()
    
    # Store in database
    db = get_db()
    try:
        db.execute('''
            INSERT INTO api_keys (key_id, key_hash, name, email, organization, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (key_id, key_hash, name, email, organization, expires_at))
        db.commit()
        
        app.logger.info(f"Created API key: {key_id} for {name} ({organization})")
        
        return jsonify({
            "key_id": key_id,
            "api_key": api_key,  # Only returned once!
            "name": name,
            "expires_at": expires_at,
            "message": "Store this API key securely - it will not be shown again"
        }), 201
        
    except sqlite3.IntegrityError:
        app.logger.error(f"Database integrity error creating API key for {name}")
        return jsonify({"error": "Key generation failed, please try again"}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error creating API key: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/admin/keys', methods=['GET'])
@require_master_key
def list_api_keys():
    """List all API keys (without the actual keys)"""
    db = get_db()
    keys = db.execute('''
        SELECT key_id, name, email, organization, created_at, expires_at, 
               is_active, usage_count, last_used_at
        FROM api_keys
        ORDER BY created_at DESC
    ''').fetchall()
    
    return jsonify([dict(key) for key in keys])

@app.route('/admin/keys/<key_id>', methods=['DELETE'])
@require_master_key
def revoke_api_key(key_id):
    """Revoke an API key"""
    db = get_db()
    result = db.execute('''
        UPDATE api_keys SET is_active = 0 WHERE key_id = ?
    ''', (key_id,))
    db.commit()
    
    if result.rowcount == 0:
        return jsonify({"error": "Key not found"}), 404
    
    app.logger.info(f"Revoked API key: {key_id}")
    return jsonify({"message": "API key revoked"})

@app.route('/admin/registrations', methods=['GET'])
@require_master_key
def list_registrations():
    """List all registrations"""
    db = get_db()
    registrations = db.execute('''
        SELECT r.*, k.name as key_name, k.organization
        FROM registrations r
        JOIN api_keys k ON r.api_key_id = k.key_id
        ORDER BY r.created_at DESC
        LIMIT 100
    ''').fetchall()
    
    return jsonify([dict(reg) for reg in registrations])

@app.route('/admin/registrations/<int:registration_id>', methods=['DELETE'])
@require_master_key
def revoke_registration(registration_id):
    """Revoke/delete a registration"""
    db = get_db()
    
    # First check if registration exists
    registration = db.execute('''
        SELECT r.*, k.name as key_name 
        FROM registrations r
        JOIN api_keys k ON r.api_key_id = k.key_id
        WHERE r.id = ?
    ''', (registration_id,)).fetchone()
    
    if not registration:
        return jsonify({"error": "Registration not found"}), 404
    
    # Delete the registration
    result = db.execute('DELETE FROM registrations WHERE id = ?', (registration_id,))
    db.commit()
    
    if result.rowcount == 0:
        return jsonify({"error": "Registration not found"}), 404
    
    app.logger.info(f"Revoked registration: id={registration_id}, key={registration['key_name']}, "
                  f"domain={registration['domain_hint']}, subdomain={registration['subdomain']}")
    
    return jsonify({"message": "Registration revoked successfully"})

@app.route('/admin/stats', methods=['GET'])
@require_master_key
def get_stats():
    """Get service statistics"""
    db = get_db()
    
    stats = {}
    
    # Total keys
    stats['total_keys'] = db.execute('SELECT COUNT(*) as count FROM api_keys').fetchone()['count']
    stats['active_keys'] = db.execute('SELECT COUNT(*) as count FROM api_keys WHERE is_active = 1').fetchone()['count']
    
    # Total registrations
    stats['total_registrations'] = db.execute('SELECT COUNT(*) as count FROM registrations').fetchone()['count']
    
    # Recent activity
    stats['registrations_last_24h'] = db.execute('''
        SELECT COUNT(*) as count FROM registrations 
        WHERE created_at > datetime('now', '-24 hours')
    ''').fetchone()['count']
    
    # Top users
    stats['top_users'] = [dict(row) for row in db.execute('''
        SELECT k.name, k.organization, COUNT(r.id) as registration_count
        FROM api_keys k
        LEFT JOIN registrations r ON k.key_id = r.api_key_id
        GROUP BY k.key_id
        ORDER BY registration_count DESC
        LIMIT 10
    ''').fetchall()]
    
    return jsonify(stats)

# Public endpoints (require API key)

@app.route('/register', methods=['POST'])
@require_api_key
def register():
    """Register a new domain with acme-dns"""
    try:
        data = request.get_json() or {}
        domain_hint = sanitize_string(data.get('domain', 'unknown'), 253)
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        # Validate domain if provided
        if domain_hint != 'unknown' and not validate_domain(domain_hint):
            return jsonify({"error": "Invalid domain format"}), 400
        
        # Forward to acme-dns with empty JSON body (acme-dns expects this)
        response = requests.post(f"{ACME_DNS_URL}/register", 
                               json={},  # acme-dns expects empty object
                               timeout=10)
        
        # Check for success (200 or 201 are both valid)
        if response.status_code in [200, 201]:
            registration_data = response.json()
            subdomain = registration_data.get('subdomain')
            
            # Store registration in database
            db = get_db()
            db.execute('''
                INSERT INTO registrations (api_key_id, subdomain, domain_hint, client_ip)
                VALUES (?, ?, ?, ?)
            ''', (g.api_key_id, subdomain, domain_hint, client_ip))
            db.commit()
            
            app.logger.info(f"Registration: key={g.api_key_name}, domain={domain_hint}, "
                          f"subdomain={subdomain}, ip={client_ip}")
            
            return jsonify(registration_data), 200
        else:
            app.logger.error(f"acme-dns registration failed: {response.status_code} - {response.text}")
            return jsonify({"error": "Registration failed"}), 500
            
    except requests.RequestException as e:
        app.logger.error(f"ACME DNS service error: {e}")
        return jsonify({"error": "External service unavailable"}), 503
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    try:
        # Check database
        db = get_db()
        db.execute('SELECT 1').fetchone()
        
        # Check acme-dns
        response = requests.get(f"{ACME_DNS_URL}/health", timeout=5)
        acme_dns_healthy = response.status_code == 200
        
        return jsonify({
            "status": "healthy",
            "database": "ok",
            "acme_dns": "ok" if acme_dns_healthy else "error"
        }), 200
        
    except Exception as e:
        app.logger.error(f"Health check error: {e}")
        return jsonify({
            "status": "unhealthy",
            "error": "Service check failed"
        }), 500

@app.route('/info', methods=['GET'])
@require_api_key
def get_key_info():
    """Get information about the current API key"""
    db = get_db()
    key_info = db.execute('''
        SELECT name, email, organization, created_at, expires_at, usage_count, last_used_at
        FROM api_keys WHERE key_id = ?
    ''', (g.api_key_id,)).fetchone()
    
    if not key_info:
        return jsonify({"error": "Key not found"}), 404
    
    # Get registration count
    reg_count = db.execute('''
        SELECT COUNT(*) as count FROM registrations WHERE api_key_id = ?
    ''', (g.api_key_id,)).fetchone()['count']
    
    result = dict(key_info)
    result['registration_count'] = reg_count
    
    return jsonify(result)

@app.route('/lookup', methods=['POST'])
@require_api_key
def lookup_config():
    """Look up ACME DNS configuration for a domain"""
    try:
        data = request.get_json() or {}
        domain = sanitize_string(data.get('domain', ''))
        
        if not domain:
            return jsonify({"error": "Domain is required"}), 400
        
        if not validate_domain(domain):
            return jsonify({"error": "Invalid domain format"}), 400
    
    db = get_db()
    
    # Find registrations for this API key and domain
    escaped_domain = escape_like_pattern(domain)
    registrations = db.execute('''
        SELECT r.*, k.name as key_name
        FROM registrations r
        JOIN api_keys k ON r.api_key_id = k.key_id
        WHERE r.api_key_id = ? AND (r.domain_hint = ? OR r.domain_hint LIKE ? ESCAPE '\\')
        ORDER BY r.created_at DESC
    ''', (g.api_key_id, domain, f'%{escaped_domain}%')).fetchall()
    
    if not registrations:
        return jsonify({
            "error": "No registrations found for this domain",
            "domain": domain,
            "suggestion": "You may need to register this domain first using the /register endpoint"
        }), 404
    
    # Get the most recent registration
    latest_reg = registrations[0]
    
    # Return configuration information
    config = {
        "domain": domain,
        "acme_dns_server": "acmedns.realworld.net.au",
        "subdomain": latest_reg['subdomain'],
        "cname_record": {
            "name": f"_acme-challenge.{domain}",
            "value": f"{latest_reg['subdomain']}.acmedns.realworld.net.au",
            "type": "CNAME"
        },
        "registration_info": {
            "registered_at": latest_reg['created_at'],
            "key_name": latest_reg['key_name'],
            "total_registrations": len(registrations)
        },
        "instructions": {
            "step1": f"Add this CNAME record to your DNS: _acme-challenge.{domain} CNAME {latest_reg['subdomain']}.acmedns.realworld.net.au",
            "step2": "Configure your ACME client to use DNS-01 challenge with acme-dns",
            "step3": "Use the subdomain and your API key for certificate requests"
        }
    }
    
        app.logger.info(f"Config lookup: key={g.api_key_name}, domain={domain}, subdomain={latest_reg['subdomain']}")
        
        return jsonify(config)
    
    except Exception as e:
        app.logger.error(f"Error in lookup_config: {e}")
        return jsonify({"error": "Internal server error"}), 500

# Application factory pattern for WSGI deployment
# Use gunicorn to run this application in production
