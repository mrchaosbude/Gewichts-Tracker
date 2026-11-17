"""Flask-App, Konfiguration und Erweiterungen (db, csrf, limiter, login_manager, api_bp)."""

import datetime
import os
import secrets

from env_config import load_env_file
from flask import Blueprint, Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix


# Werte aus .env laden (z.B. von update.py erzeugter SECRET_KEY); echte Umgebungsvariablen haben Vorrang
load_env_file()


def _utcnow():
    """Current UTC time as naive datetime (compatible with SQLite which strips tzinfo)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


# Projektverzeichnis (enthält templates/, static/, instance/). Name 'app' und Pfade bleiben wie
# früher, als alles in app.py lag: gleiche Datenbank, gleicher Instanz- und Upload-Ordner.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask('app', root_path=PROJECT_ROOT, instance_path=os.path.join(PROJECT_ROOT, 'instance'))


# Hinter einem Reverse Proxy (nginx, Caddy ...): Anzahl der vertrauenswürdigen Proxys angeben,
# damit Rate-Limit und HTTPS-Erkennung die echte Client-Adresse sehen.
try:
    _trusted_proxies = max(0, int(os.environ.get('GEWICHTS_TRACKER_TRUSTED_PROXIES', '0') or 0))
except ValueError:
    _trusted_proxies = 0
if _trusted_proxies:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=_trusted_proxies, x_proto=_trusted_proxies, x_host=_trusted_proxies)


# Content-Security-Policy. Inline-Skripte sind noch erlaubt (die Templates nutzen sie),
# aber fremde Skript-Quellen, Formularziele, Plugins und <base>-Umleitungen sind gesperrt.
_CDN_SCRIPTS = 'https://cdn.jsdelivr.net https://code.jquery.com'
_CDN_STYLES = 'https://stackpath.bootstrapcdn.com'
DEFAULT_CSP = (
    "default-src 'self'; "
    f"script-src 'self' 'unsafe-inline' {_CDN_SCRIPTS}; "
    f"style-src 'self' 'unsafe-inline' {_CDN_STYLES}; "
    "img-src 'self' data: blob:; "
    f"font-src 'self' data: {_CDN_STYLES}; "
    f"connect-src 'self' {_CDN_SCRIPTS} {_CDN_STYLES}; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
)


# Leerer Wert schaltet den Header ab, ein eigener Wert ersetzt ihn.
CONTENT_SECURITY_POLICY = os.environ.get('GEWICHTS_TRACKER_CSP', DEFAULT_CSP).strip()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('GEWICHTS_TRACKER_DATABASE_URI', 'sqlite:///fitness.db')


# Cookie-Härtung. SESSION_COOKIE_SECURE=true setzen, sobald die App über HTTPS läuft.
_cookie_secure = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = _cookie_secure
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_SECURE'] = _cookie_secure
# "Angemeldet bleiben" gilt 30 Tage statt der Flask-Login-Vorgabe von 365.
try:
    _remember_days = max(1, int(os.environ.get('GEWICHTS_TRACKER_REMEMBER_DAYS', '30')))
except ValueError:
    _remember_days = 30
app.config['REMEMBER_COOKIE_DURATION'] = datetime.timedelta(days=_remember_days)
# Optional: nur diese Hostnamen annehmen (Komma-getrennt, z.B. "fit.example.de,localhost").
# Anfragen mit anderem Host-Header werden mit 400 abgewiesen.
_allowed_hosts = [h.strip() for h in os.environ.get('GEWICHTS_TRACKER_ALLOWED_HOSTS', '').split(',') if h.strip()]
if _allowed_hosts:
    app.config['TRUSTED_HOSTS'] = _allowed_hosts


# reCAPTCHA-Konfiguration (ersetze die Schlüssel durch deine echten Werte)
app.config['RECAPTCHA_PUBLIC_KEY'] = 'dein_recaptcha_public_key'
app.config['RECAPTCHA_PRIVATE_KEY'] = 'dein_recaptcha_private_key'


# Zum Testen (ohne reCAPTCHA) kannst du es hier auf False setzen:
app.config['RECAPTCHA_ENABLED'] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[], storage_uri="memory://")


# Flask-Login konfigurieren
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
api_bp = Blueprint("api", __name__, url_prefix="/api")


# Upload-Konfiguration
# Fortschrittsfotos liegen bewusst NICHT unter static/, da dort alles ohne Login
# abrufbar ist. Ausgeliefert werden sie nur über progress_photo_file() an den Besitzer.
LEGACY_UPLOAD_FOLDER = os.path.join(PROJECT_ROOT, 'static', 'uploads', 'photos')
UPLOAD_FOLDER = (
    os.environ.get('GEWICHTS_TRACKER_UPLOAD_FOLDER')
    or os.path.join(app.instance_path, 'uploads', 'photos')
)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}
PHOTO_MIMETYPES = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'webp': 'image/webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_REQUEST_BYTES = 10 * 1024 * 1024  # 10 MB für alle normalen Anfragen (auch einzelne Fotos)
try:
    MAX_IMPORT_BYTES = max(10, int(os.environ.get('GEWICHTS_TRACKER_MAX_IMPORT_MB', '100'))) * 1024 * 1024
except ValueError:
    MAX_IMPORT_BYTES = 100 * 1024 * 1024
app.config['MAX_CONTENT_LENGTH'] = MAX_IMPORT_BYTES  # harte Obergrenze; nur der Daten-Import darf sie ausschöpfen
