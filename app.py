# app.py
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import Flask, request, Response, abort, jsonify, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
import requests

# -------- CONFIG --------
DB_PATH = os.environ.get("DB_PATH", "sqlite:///data.db")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "superadminsecret")  # change in prod
API_DEFAULT_PASSWORD_EXPIRES_DAYS = 7

ALLOWED_HOSTS = {"teraboxdl.site", "www.teraboxdl.site"}
CHUNK_SIZE = 64 * 1024

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------- MODELS --------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(128), unique=True, index=True, nullable=False)  # external id provided by client
    is_premium = db.Column(db.Boolean, default=False)
    cooldown_until = db.Column(db.DateTime, nullable=True)
    downloads_count = db.Column(db.Integer, default=0)
    api_calls = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ApiPassword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(256), unique=True, index=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.String(128), nullable=True)  # admin who created

class AdminLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_action = db.Column(db.String(512))
    admin_by = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DownloadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(128), nullable=True)
    source_url = db.Column(db.String(2000))
    status_code = db.Column(db.Integer)
    bytes_sent = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------- DB INIT (call once) --------
@app.before_first_request
def create_tables():
    db.create_all()

# -------- Helpers --------
def is_allowed_url(url):
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        return host in ALLOWED_HOSTS
    except Exception:
        return False

def get_user_or_create(userid):
    u = User.query.filter_by(userid=userid).first()
    if not u:
        u = User(userid=userid)
        db.session.add(u)
        db.session.commit()
    return u

def check_api_password(pw):
    now = datetime.utcnow()
    ap = ApiPassword.query.filter_by(password=pw).filter(
        (ApiPassword.expires_at == None) | (ApiPassword.expires_at > now)
    ).first()
    return ap

def parse_time_string(s):
    # expected format 2025-11-10-12-00
    try:
        return datetime.strptime(s, "%Y-%m-%d-%H-%M")
    except Exception:
        return None

def log_admin(action, admin_by):
    entry = AdminLog(admin_action=action, admin_by=admin_by)
    db.session.add(entry)
    db.session.commit()

# -------- Admin route: create new api password
# URL pattern: /admin/pas/{admin_password}/{new_password}&{time}
# Example: /admin/pas/admin123/test&2025-11-10-12-00
@app.route("/admin/pas/<admin_password>/<path:payload>")
def admin_create_password(admin_password, payload):
    # WARNING: passing admin_password in URL is insecure. Use env or other secure channel.
    if admin_password != ADMIN_SECRET:
        return jsonify({"ok": False, "error": "invalid admin password"}), 401

    # payload expected: newpass&YYYY-MM-DD-HH-MM
    # support optional time; if missing, use default expiry
    parts = payload.split("&", 1)
    new_password = parts[0]
    timepart = parts[1] if len(parts) > 1 else None

    expires_at = None
    if timepart:
        parsed = parse_time_string(timepart)
        if parsed is None:
            return jsonify({"ok": False, "error": "invalid time format; use YYYY-MM-DD-HH-MM"}), 400
        expires_at = parsed
    else:
        expires_at = datetime.utcnow() + timedelta(days=API_DEFAULT_PASSWORD_EXPIRES_DAYS)

    # create ApiPassword
    ap = ApiPassword(password=new_password, expires_at=expires_at, created_by=admin_password)
    db.session.add(ap)
    db.session.commit()

    log_admin(f"Created api password '{new_password}' expires {expires_at.isoformat()}", admin_by=admin_password)

    return jsonify({"ok": True, "password": new_password, "expires_at": expires_at.isoformat()})

# -------- Admin: other endpoints (examples) ----------
@app.route("/admin/stats/<admin_password>")
def admin_stats(admin_password):
    if admin_password != ADMIN_SECRET:
        return jsonify({"ok": False, "error": "invalid admin password"}), 401

    total_users = User.query.count()
    total_api_pw = ApiPassword.query.count()
    total_downloads = DownloadLog.query.count()
    logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(50).all()
    recent = [{"action": l.admin_action, "by": l.admin_by, "at": l.created_at.isoformat()} for l in logs]
    return jsonify({
        "ok": True,
        "total_users": total_users,
        "total_api_passwords": total_api_pw,
        "total_download_logs": total_downloads,
        "recent_admin_actions": recent
    })

# -------- Download proxy route
# Example:
# /TeraBox/Download/Api/v1/safensecure/fast/Team-X-Og/{password}/?dl={source_url}&userid={userid}&filename=...
@app.route("/TeraBox/Download/Api/v1/safensecure/fast/Team-X-Og/<password>/")
def proxy_download(password):
    source = request.args.get("dl", type=str)
    if not source:
        return abort(400, "Missing dl parameter")

    if not is_allowed_url(source):
        return abort(400, "URL not allowed")

    # validate api password
    ap = check_api_password(password)
    if not ap:
        return abort(401, "Invalid or expired API password")

    # user identification (client must pass a userid param or header)
    userid = request.args.get("userid") or request.headers.get("X-User-Id")
    if not userid:
        return abort(400, "Missing userid (pass userid query param or X-User-Id header)")

    user = get_user_or_create(userid)

    # Check cooldown
    now = datetime.utcnow()
    if user.cooldown_until and user.cooldown_until > now and not user.is_premium:
        wait_seconds = int((user.cooldown_until - now).total_seconds())
        return jsonify({"ok": False, "error": "On cooldown", "wait_seconds": wait_seconds}), 429

    # simple rate/limit logic
    # Example limits:
    DAILY_API_CALL_LIMIT = 100 if not user.is_premium else 10000
    DAILY_DOWNLOAD_LIMIT = 5 if not user.is_premium else 1000
    # Reset daily counters at midnight UTC (simple implementation uses created_at day)
    # For simplicity: we won't auto-reset counters here; a cron or daily job could reset counts.
    # But we'll limit via a naive count per run (you can extend)

    # Count API calls increment
    user.api_calls = user.api_calls + 1
    # use downloads_count for number of files downloaded
    if user.downloads_count >= DAILY_DOWNLOAD_LIMIT and not user.is_premium:
        return jsonify({"ok": False, "error": "Daily download limit reached"}), 429

    # Proceed to stream from upstream
    try:
        upstream = requests.get(source, stream=True, timeout=20)
    except requests.exceptions.RequestException as e:
        db.session.add(DownloadLog(userid=userid, source_url=source, status_code=0, bytes_sent=0))
        db.session.commit()
        return abort(502, f"Upstream error: {e}")

    if upstream.status_code >= 400:
        db.session.add(DownloadLog(userid=userid, source_url=source, status_code=upstream.status_code, bytes_sent=0))
        db.session.commit()
        return abort(502, f"Upstream returned {upstream.status_code}")

    # filename resolution
    filename = request.args.get("filename")
    if not filename:
        cd = upstream.headers.get("Content-Disposition")
        if cd and "filename=" in cd:
            try:
                filename = re.findall('filename="?([^";]+)"?', cd)[0]
            except Exception:
                filename = None
    if not filename:
        filename = source.rstrip("/").split("/")[-1] or "download"

    content_type = upstream.headers.get("Content-Type", "application/octet-stream")
    headers = {
        "Content-Type": content_type,
        "Content-Disposition": f'attachment; filename="{filename}"'
    }

    # update user stats
    user.downloads_count = user.downloads_count + 1

    # enforce cooldown after download: e.g., non-premium must wait 30 seconds between downloads
    if not user.is_premium:
        user.cooldown_until = datetime.utcnow() + timedelta(seconds=30)

    db.session.commit()

    # stream generator
    def generate():
        total = 0
        try:
            for chunk in upstream.iter_content(CHUNK_SIZE):
                if chunk:
                    total += len(chunk)
                    yield chunk
        finally:
            # log after streaming
            db.session.add(DownloadLog(userid=userid, source_url=source, status_code=upstream.status_code, bytes_sent=total))
            db.session.commit()
            upstream.close()

    return Response(stream_with_context(generate()), headers=headers)

# -------- Simple endpoint to toggle premium (admin)
@app.route("/admin/toggle_premium/<admin_password>/<userid>/<state>")
def admin_toggle_premium(admin_password, userid, state):
    if admin_password != ADMIN_SECRET:
        return jsonify({"ok": False, "error": "invalid admin password"}), 401
    user = get_user_or_create(userid)
    user.is_premium = True if state.lower() in ("1","true","yes") else False
    db.session.commit()
    log_admin(f"Set premium={user.is_premium} for {userid}", admin_by=admin_password)
    return jsonify({"ok": True, "userid": userid, "is_premium": user.is_premium})

# -------- Admin logs listing
@app.route("/admin/logs/<admin_password>")
def admin_logs(admin_password):
    if admin_password != ADMIN_SECRET:
        return jsonify({"ok": False, "error": "invalid admin password"}), 401
    logs = AdminLog.query.order_by(AdminLog.created_at.desc()).limit(200).all()
    return jsonify([{"action": l.admin_action, "by": l.admin_by, "at": l.created_at.isoformat()} for l in logs])

# -------- run
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
