import os
import time
import uuid
import json
import threading
import socket
import ipaddress
from datetime import datetime, timedelta
from typing import Optional

from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import requests
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///ssrf_canary.db')
ALERT_WEBHOOK = os.getenv('ALERT_WEBHOOK')
ALERT_EMAIL = os.getenv('ALERT_EMAIL')
SMTP_HOST = os.getenv('SMTP_HOST')
SMTP_PORT = int(os.getenv('SMTP_PORT', '25'))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')
APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = int(os.getenv('APP_PORT', '8443'))
BASE_URL = os.getenv('BASE_URL', 'https://canary.example.com')
TOKEN_EXPIRY_DEFAULT = int(os.getenv('TOKEN_EXPIRY_SECONDS', str(60 * 60 * 24 * 7)))
RATE_LIMIT_MAX = int(os.getenv('RATE_LIMIT_MAX', '20'))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', '60'))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Token(db.Model):
    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    owner = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    meta = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'token': self.token,
            'owner': self.owner,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'active': self.active,
            'meta': json.loads(self.meta) if self.meta else None,
        }

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    method = db.Column(db.String(16))
    path = db.Column(db.Text)
    headers = db.Column(db.Text)
    body_preview = db.Column(db.Text)
    remote_addr = db.Column(db.String(64))
    remote_host = db.Column(db.String(256), nullable=True)
    suspicious = db.Column(db.Boolean, default=False)
    raw = db.Column(db.Text)

    def to_dict(self):
        try:
            headers = json.loads(self.headers) if self.headers else {}
        except Exception:
            headers = {}
        return {
            'id': self.id,
            'token': self.token,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'method': self.method,
            'path': self.path,
            'headers': headers,
            'body_preview': self.body_preview,
            'remote_addr': self.remote_addr,
            'remote_host': self.remote_host,
            'suspicious': self.suspicious,
        }

METADATA_IPS = {'169.254.169.254', '169.254.170.2', '100.100.100.200'}
PRIV_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]

rate_counters = {}
rate_lock = threading.Lock()


def init_db() -> None:
    with app.app_context():
        db.create_all()


def gen_token() -> str:
    for _ in range(5):
        candidate = uuid.uuid4().hex
        if not Token.query.filter_by(token=candidate).first():
            return candidate
    return uuid.uuid4().hex


def is_private_ip_str(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except Exception:
        return False
    for net in PRIV_RANGES:
        if ip in net:
            return True
    return False


def enrich_remote_host(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def record_and_check_rate(token: str) -> bool:
    now = time.time()
    with rate_lock:
        arr = rate_counters.setdefault(token, [])
        window_start = now - RATE_LIMIT_WINDOW
        i = 0
        while i < len(arr) and arr[i] < window_start:
            i += 1
        if i:
            del arr[:i]
        arr.append(now)
        return len(arr) <= RATE_LIMIT_MAX


def send_email(subject: str, body: str, to_addr: Optional[str] = None) -> bool:
    if not SMTP_HOST or not to_addr:
        return False
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = SMTP_USER or 'canary@example.com'
        msg['To'] = to_addr
        msg.set_content(body)
        s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        if SMTP_USER and SMTP_PASS:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
        s.quit()
        return True
    except Exception:
        return False


def send_webhook(payload: dict) -> bool:
    if not ALERT_WEBHOOK:
        return False
    try:
        r = requests.post(ALERT_WEBHOOK, json=payload, timeout=5)
        return r.status_code >= 200 and r.status_code < 300
    except Exception:
        return False


def alert_async(payload: dict) -> None:
    def worker(p: dict):
        try:
            send_webhook(p)
        except Exception:
            pass
        try:
            if ALERT_EMAIL:
                send_email('SSRF Canary hit', json.dumps(p, indent=2), ALERT_EMAIL)
        except Exception:
            pass
    t = threading.Thread(target=worker, args=(payload,))
    t.daemon = True
    t.start()

@app.route('/create_token', methods=['POST'])
def create_token_api():
    data = request.get_json(silent=True) or {}
    owner = data.get('owner') or request.args.get('owner') or 'default'
    expires_in_raw = data.get('expires_in') if 'expires_in' in data else request.args.get('expires_in')
    try:
        expires_in = int(expires_in_raw) if expires_in_raw is not None else TOKEN_EXPIRY_DEFAULT
    except Exception:
        expires_in = TOKEN_EXPIRY_DEFAULT
    token = gen_token()
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None
    tkn = Token(token=token, owner=owner, expires_at=expires_at, meta=json.dumps({'created_via': 'api'}))
    db.session.add(tkn)
    db.session.commit()
    url = f"{BASE_URL}/c/{token}"
    return jsonify({'token': token, 'url': url, 'expires_at': expires_at.isoformat() if expires_at else None})

@app.route('/tokens', methods=['GET'])
def list_tokens():
    tokens = Token.query.order_by(Token.created_at.desc()).limit(200).all()
    return jsonify({'count': len(tokens), 'tokens': [t.to_dict() for t in tokens]})

@app.route('/tokens/<token>/deactivate', methods=['POST'])
def deactivate_token(token):
    t = Token.query.filter_by(token=token).first()
    if not t:
        abort(404)
    t.active = False
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/c/<token>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
def canary(token):
    ok_rate = record_and_check_rate(token)
    t = Token.query.filter_by(token=token).first()
    try:
        body = request.get_data()[:4096]
        body_preview = body.decode('utf-8', 'replace') if body else ''
    except Exception:
        body_preview = ''
    xff = request.headers.get('X-Forwarded-For')
    remote_addr = None
    if xff:
        remote_addr = xff.split(',')[0].strip()
    if not remote_addr:
        remote_addr = request.remote_addr
    suspicious = False
    if remote_addr:
        if is_private_ip_str(remote_addr) or remote_addr in METADATA_IPS:
            suspicious = True
    host_hdr = request.headers.get('Host', '')
    try:
        host_part = host_hdr.split(':')[0] if host_hdr else ''
        if host_part:
            try:
                if is_private_ip_str(host_part):
                    suspicious = True
            except Exception:
                pass
    except Exception:
        pass
    ev = Event(
        token=token,
        method=request.method,
        path=request.full_path,
        headers=json.dumps(dict(request.headers)),
        body_preview=body_preview[:2000],
        remote_addr=remote_addr,
        remote_host=enrich_remote_host(remote_addr) if remote_addr else None,
        suspicious=suspicious or (not ok_rate),
        raw=json.dumps({
            'method': request.method,
            'path': request.path,
            'args': request.args.to_dict(),
            'headers': dict(request.headers),
            'body_preview': body_preview,
            'remote_addr': remote_addr,
            'timestamp': datetime.utcnow().isoformat(),
        }),
    )
    db.session.add(ev)
    db.session.commit()
    payload = {
        'token': token,
        'token_exists': bool(t),
        'token_owner': t.owner if t else None,
        'timestamp': ev.timestamp.isoformat(),
        'method': ev.method,
        'path': ev.path,
        'remote_addr': ev.remote_addr,
        'remote_host': ev.remote_host,
        'suspicious': ev.suspicious,
        'headers': json.loads(ev.headers or '{}'),
        'body_preview': ev.body_preview,
        'rate_ok': ok_rate,
    }
    alert_async(payload)
    return ('OK', 200)

@app.route('/events', methods=['GET'])
def list_events():
    try:
        page = int(request.args.get('page', '1'))
        per = int(request.args.get('per', '50'))
    except Exception:
        page, per = 1, 50
    q = Event.query.order_by(Event.timestamp.desc())
    total = q.count()
    items = q.offset((page - 1) * per).limit(per).all()
    return jsonify({'total': total, 'page': page, 'per': per, 'events': [e.to_dict() for e in items]})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    init_db()
    app.run(host=APP_HOST, port=APP_PORT)

