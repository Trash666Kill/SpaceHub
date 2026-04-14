from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo, available_timezones
from sqlalchemy import update as sa_update
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import uuid, json, os, re, threading, secrets, smtplib, ssl

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False

# ── Status / role constants ───────────────────────────────────────────────────
ROOM_STATUSES  = {'active', 'maintenance', 'inactive'}
USER_STATUSES  = {'pending', 'approved', 'blocked'}
USER_ROLES     = {'admin', 'user'}
DEFAULT_TZ     = 'America/Sao_Paulo'

_JWT_DEFAULT_SECRET = 'dev-secret-change-in-production!!'  # 33 chars — only for dev

app = Flask(__name__)

# CORS: restrict to explicit origins when CORS_ORIGINS env var is set.
# In production, set CORS_ORIGINS to your frontend domain(s).
_cors_origins = os.environ.get('CORS_ORIGINS', '*')
CORS(app, origins=_cors_origins, expose_headers=["X-Establishment-Id"])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spacehub.db'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'check_same_thread': False}}

_jwt_secret = os.environ.get('JWT_SECRET', _JWT_DEFAULT_SECRET)
app.config['JWT_SECRET_KEY'] = _jwt_secret
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ── Models ────────────────────────────────────────────────────────────────────

class Establishment(db.Model):
    __tablename__ = 'establishments'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(120), nullable=False)
    address = db.Column(db.String(255), nullable=True, default='')
    status = db.Column(db.String(12), default='active')  # active | inactive
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'address': self.address or '',
            'status': self.status,
            'created_at': self.created_at.isoformat(),
        }


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(100), nullable=True, default='')
    is_super_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self, establishment_id=None):
        """Serialize user. If establishment_id is provided, includes role/status
        from that specific membership."""
        base = {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'department': self.department or '',
            'is_super_admin': self.is_super_admin,
            'created_at': self.created_at.isoformat(),
        }
        if establishment_id is not None:
            m = UserEstablishment.query.filter_by(
                user_id=self.id, establishment_id=establishment_id
            ).first()
            if m:
                base['role'] = m.role
                base['status'] = m.status
        return base

    def memberships_dict(self):
        """Return list of establishments this user belongs to, with role/status."""
        rows = (
            db.session.query(UserEstablishment, Establishment)
            .join(Establishment, Establishment.id == UserEstablishment.establishment_id)
            .filter(UserEstablishment.user_id == self.id)
            .filter(Establishment.status == 'active')
            .all()
        )
        return [
            {
                'establishment_id': est.id,
                'establishment_name': est.name,
                'role': m.role,
                'status': m.status,
            }
            for m, est in rows
        ]


class UserEstablishment(db.Model):
    __tablename__ = 'user_establishments'
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), primary_key=True)
    establishment_id = db.Column(db.Integer, db.ForeignKey('establishments.id'), primary_key=True)
    role = db.Column(db.String(10), default='user', nullable=False)       # admin | user
    status = db.Column(db.String(12), default='pending', nullable=False)  # pending | approved | blocked
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='memberships')
    establishment = db.relationship('Establishment', backref='memberships')


class Invitation(db.Model):
    __tablename__ = 'invitations'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    establishment_id = db.Column(db.Integer, db.ForeignKey('establishments.id'),
                                 nullable=False, index=True)
    token = db.Column(db.String(36), unique=True, nullable=False,
                      default=lambda: str(uuid.uuid4()))
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    revoked_at = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False)

    establishment = db.relationship('Establishment', backref='invitations')

    def to_dict(self):
        return {
            'id': self.id,
            'establishment_id': self.establishment_id,
            'token': self.token,
            'created_at': self.created_at.isoformat(),
            'revoked_at': self.revoked_at.isoformat() if self.revoked_at else None,
            'active': self.active,
        }


class Setting(db.Model):
    __tablename__ = 'settings'
    # Composite PK: (establishment_id, key). establishment_id is required —
    # all settings are scoped per establishment.
    establishment_id = db.Column(db.Integer, db.ForeignKey('establishments.id'),
                                 primary_key=True)
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)


class GlobalSetting(db.Model):
    __tablename__ = 'global_settings'
    # Key/value store for system-level settings (e.g. super-admin SMTP).
    # Not scoped to any establishment.
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)


class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    establishment_id = db.Column(db.Integer, db.ForeignKey('establishments.id'),
                                 nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    resources = db.Column(db.Text, default='[]')
    status = db.Column(db.String(12), default='active')

    establishment = db.relationship('Establishment', backref='rooms')

    def to_dict(self):
        return {
            'id': self.id,
            'establishment_id': self.establishment_id,
            'name': self.name,
            'capacity': self.capacity,
            'resources': json.loads(self.resources),
            'status': self.status,
        }


class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    establishment_id = db.Column(db.Integer, db.ForeignKey('establishments.id'),
                                 nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    date = db.Column(db.String(10), nullable=False, index=True)
    start_time = db.Column(db.String(5), nullable=False)
    end_time = db.Column(db.String(5), nullable=False)
    description = db.Column(db.String(200), nullable=True, default='')
    reminder_sent = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    user = db.relationship('User', backref='bookings')
    room = db.relationship('Room', backref='bookings')
    establishment = db.relationship('Establishment', backref='bookings')

    def to_dict(self):
        return {
            'id': self.id,
            'establishment_id': self.establishment_id,
            'user_id': self.user_id,
            'user_name': self.user.name if self.user else None,
            'room_id': self.room_id,
            'room_name': self.room.name if self.room else None,
            'date': self.date,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'description': self.description or '',
            'created_at': self.created_at.isoformat(),
        }


# ── Email Defaults (per-establishment templates seeded on creation) ──────────

EMAIL_DEFAULTS = {
    'email_reg_subject': '🔔 Novo cadastro aguardando aprovação — SpaceHub',
    'email_reg_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#1a73e8">Novo cadastro aguardando aprovação</h2>'
        '<p>Um novo usuário se cadastrou em <strong>{{estabelecimento}}</strong> e aguarda sua aprovação:</p>'
        '<table style="width:100%;border-collapse:collapse;margin:16px 0">'
        '<tr><td style="padding:8px;font-weight:600;color:#555;width:120px">Nome</td><td style="padding:8px">{{nome}}</td></tr>'
        '<tr style="background:#f5f5f5"><td style="padding:8px;font-weight:600;color:#555">E-mail</td><td style="padding:8px">{{email}}</td></tr>'
        '<tr><td style="padding:8px;font-weight:600;color:#555">Setor</td><td style="padding:8px">{{setor}}</td></tr>'
        '<tr style="background:#f5f5f5"><td style="padding:8px;font-weight:600;color:#555">Data</td><td style="padding:8px">{{data}}</td></tr>'
        '</table>'
        '<p>Acesse o painel de administração para aprovar ou rejeitar este cadastro.</p>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
    'email_approved_subject': '✅ Sua conta em {{estabelecimento}} foi aprovada!',
    'email_approved_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#34a853">✅ Sua conta foi aprovada!</h2>'
        '<p>Olá, <strong>{{nome}}</strong>!</p>'
        '<p>Boas notícias! Seu acesso ao estabelecimento <strong>{{estabelecimento}}</strong> no SpaceHub foi aprovado por um administrador.</p>'
        '<p>Você já pode fazer login e realizar reservas de salas.</p>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
    'email_blocked_subject': '⚠️ Seu acesso a {{estabelecimento}} foi bloqueado',
    'email_blocked_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#ea4335">Acesso bloqueado</h2>'
        '<p>Olá, <strong>{{nome}}</strong>.</p>'
        '<p>Seu acesso ao estabelecimento <strong>{{estabelecimento}}</strong> no SpaceHub foi bloqueado por um administrador.</p>'
        '<p>Entre em contato com o administrador do estabelecimento para mais informações.</p>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
    'email_reminder_subject': '⏰ Lembrete: sua reserva começa em 15 minutos — SpaceHub',
    'email_reminder_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#1a73e8">⏰ Sua reserva começa em breve!</h2>'
        '<p>Olá, <strong>{{nome}}</strong>!</p>'
        '<p>Sua reserva em <strong>{{estabelecimento}}</strong> começa em <strong>15 minutos</strong>:</p>'
        '<table style="width:100%;border-collapse:collapse;margin:16px 0">'
        '<tr><td style="padding:8px;font-weight:600;color:#555;width:120px">Sala</td><td style="padding:8px">{{sala}}</td></tr>'
        '<tr style="background:#f5f5f5"><td style="padding:8px;font-weight:600;color:#555">Data</td><td style="padding:8px">{{data_reserva}}</td></tr>'
        '<tr><td style="padding:8px;font-weight:600;color:#555">Horário</td><td style="padding:8px">{{inicio}} – {{fim}}</td></tr>'
        '<tr style="background:#f5f5f5"><td style="padding:8px;font-weight:600;color:#555">Descrição</td><td style="padding:8px">{{descricao}}</td></tr>'
        '</table>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
    'email_cancelled_subject': '❌ Reserva cancelada — {{estabelecimento}}',
    'email_cancelled_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#ea4335">Reserva cancelada</h2>'
        '<p>Olá, <strong>{{nome}}</strong>.</p>'
        '<p>Sua reserva em <strong>{{estabelecimento}}</strong> foi cancelada porque o estabelecimento foi desativado:</p>'
        '<table style="width:100%;border-collapse:collapse;margin:16px 0">'
        '<tr><td style="padding:8px;font-weight:600;color:#555;width:120px">Sala</td><td style="padding:8px">{{sala}}</td></tr>'
        '<tr style="background:#f5f5f5"><td style="padding:8px;font-weight:600;color:#555">Data</td><td style="padding:8px">{{data_reserva}}</td></tr>'
        '<tr><td style="padding:8px;font-weight:600;color:#555">Horário</td><td style="padding:8px">{{inicio}} – {{fim}}</td></tr>'
        '</table>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
    'email_booking_confirmed_subject': '📅 Reserva confirmada — {{estabelecimento}}',
    'email_booking_confirmed_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#34a853">📅 Reserva confirmada!</h2>'
        '<p>Olá, <strong>{{nome}}</strong>!</p>'
        '<p>Sua reserva em <strong>{{estabelecimento}}</strong> foi registrada com sucesso:</p>'
        '<table style="width:100%;border-collapse:collapse;margin:16px 0">'
        '<tr><td style="padding:8px;font-weight:600;color:#555;width:120px">Sala</td><td style="padding:8px">{{sala}}</td></tr>'
        '<tr style="background:#f5f5f5"><td style="padding:8px;font-weight:600;color:#555">Data</td><td style="padding:8px">{{data_reserva}}</td></tr>'
        '<tr><td style="padding:8px;font-weight:600;color:#555">Horário</td><td style="padding:8px">{{inicio}} – {{fim}}</td></tr>'
        '<tr style="background:#f5f5f5"><td style="padding:8px;font-weight:600;color:#555">Descrição</td><td style="padding:8px">{{descricao}}</td></tr>'
        '</table>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
}

SETTING_DEFAULTS = {
    'allowed_domains': '[]',
    'mail_server': 'smtp.gmail.com',
    'mail_port': '587',
    'mail_username': '',
    'mail_password': '',
    'mail_from_name': 'SpaceHub',
    'timezone': DEFAULT_TZ,
}

# Global SMTP keys managed exclusively by super admins
GLOBAL_SMTP_KEYS = ('mail_server', 'mail_port', 'mail_username', 'mail_password', 'mail_from_name')
GLOBAL_SMTP_DEFAULTS = {
    'mail_server': 'smtp.gmail.com',
    'mail_port': '587',
    'mail_username': '',
    'mail_password': '',
    'mail_from_name': 'SpaceHub',
}


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    establishment_id = db.Column(db.Integer, db.ForeignKey('establishments.id'),
                                 nullable=True, index=True)
    actor_id   = db.Column(db.String(36), nullable=True)   # who performed the action
    actor_name = db.Column(db.String(120), nullable=True)
    action     = db.Column(db.String(80), nullable=False)   # e.g. 'user.approved'
    target     = db.Column(db.String(200), nullable=True)   # human-readable target
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'establishment_id': self.establishment_id,
            'actor_name': self.actor_name,
            'action': self.action,
            'target': self.target,
            'created_at': self.created_at.isoformat(),
        }


class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id    = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    token      = db.Column(db.String(64), unique=True, nullable=False,
                           default=lambda: secrets.token_urlsafe(48))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', backref='reset_tokens')


def seed_establishment_settings(establishment_id):
    """Create default settings + email templates for a new establishment."""
    for key, value in SETTING_DEFAULTS.items():
        if not Setting.query.filter_by(establishment_id=establishment_id, key=key).first():
            db.session.add(Setting(establishment_id=establishment_id, key=key, value=value))
    for key, value in EMAIL_DEFAULTS.items():
        if not Setting.query.filter_by(establishment_id=establishment_id, key=key).first():
            db.session.add(Setting(establishment_id=establishment_id, key=key, value=value))
    db.session.commit()


# ── Timezone & Audit Helpers ─────────────────────────────────────────────────

def _get_establishment_tz(est_id):
    """Return ZoneInfo for an establishment, falling back to DEFAULT_TZ."""
    tz_name = _get_setting(est_id, 'timezone', DEFAULT_TZ) or DEFAULT_TZ
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return ZoneInfo(DEFAULT_TZ)


def _get_establishment_now(est_id):
    """Return current datetime in the establishment's configured timezone."""
    return datetime.now(_get_establishment_tz(est_id))


def _audit(action, target=None, establishment_id=None, actor=None):
    """Write an audit log entry. Call before db.session.commit()."""
    try:
        entry = AuditLog(
            establishment_id=establishment_id,
            actor_id=actor.id if actor else None,
            actor_name=actor.name if actor else 'system',
            action=action,
            target=target,
        )
        db.session.add(entry)
    except Exception as e:
        app.logger.error(f'Audit log error: {e}')


# ── Password Validation ───────────────────────────────────────────────────────

_PASSWORD_RE = re.compile(
    r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/\\]).{8,}$'
)


def _validate_password(password):
    """Return (ok, error_message). Requires 8+ chars, upper, lower, digit, special."""
    if len(password) < 8:
        return False, 'A senha deve ter no mínimo 8 caracteres'
    if not _PASSWORD_RE.match(password):
        return False, ('A senha deve conter pelo menos: 1 maiúscula, 1 minúscula, '
                       '1 número e 1 caractere especial (!@#$%^&*…)')
    return True, None


# ── Context & Auth Helpers ────────────────────────────────────────────────────

def current_user():
    return db.session.get(User, get_jwt_identity())


def get_membership(user, establishment_id):
    """Return the UserEstablishment row for (user, est), or None."""
    if not user or establishment_id is None:
        return None
    return UserEstablishment.query.filter_by(
        user_id=user.id, establishment_id=establishment_id
    ).first()


def resolve_establishment_context():
    """Read X-Establishment-Id header, validate, and store in flask.g.
    Returns (establishment, error_response). If error_response is not None,
    the caller should return it immediately."""
    header = request.headers.get('X-Establishment-Id')
    if not header:
        return None, (jsonify({'error': 'Header X-Establishment-Id é obrigatório'}), 400)
    try:
        est_id = int(header)
    except (ValueError, TypeError):
        return None, (jsonify({'error': 'X-Establishment-Id inválido'}), 400)
    est = db.session.get(Establishment, est_id)
    if not est:
        return None, (jsonify({'error': 'Estabelecimento não encontrado'}), 404)
    if est.status != 'active':
        return None, (jsonify({'error': 'Estabelecimento inativo'}), 403)
    g.establishment = est
    return est, None


def super_admin_required(fn):
    """Requires a logged-in super admin. No establishment context needed."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_super_admin:
            return jsonify({'error': 'Super admin access required'}), 403
        g.user = u
        return fn(*args, **kwargs)
    return wrapper


def establishment_member_required(fn):
    """Requires: logged in + valid establishment context + user is a member
    (or super admin) with status 'approved'."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return jsonify({'error': 'Usuário não encontrado'}), 401
        est, err = resolve_establishment_context()
        if err:
            return err
        g.user = u
        if u.is_super_admin:
            g.membership = None  # super admin has implicit access
            g.is_admin = True
            return fn(*args, **kwargs)
        m = get_membership(u, est.id)
        if not m:
            return jsonify({'error': 'Você não pertence a este estabelecimento'}), 403
        if m.status != 'approved':
            return jsonify({'error': 'Seu acesso a este estabelecimento não está aprovado'}), 403
        g.membership = m
        g.is_admin = (m.role == 'admin')
        return fn(*args, **kwargs)
    return wrapper


def establishment_admin_required(fn):
    """Requires: logged in + valid establishment context + user is admin of that
    establishment (or super admin)."""
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return jsonify({'error': 'Usuário não encontrado'}), 401
        est, err = resolve_establishment_context()
        if err:
            return err
        g.user = u
        if u.is_super_admin:
            g.membership = None
            g.is_admin = True
            return fn(*args, **kwargs)
        m = get_membership(u, est.id)
        if not m or m.status != 'approved' or m.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        g.membership = m
        g.is_admin = True
        return fn(*args, **kwargs)
    return wrapper


def check_conflict(room_id, date, start_time, end_time, exclude_id=None):
    q = Booking.query.filter_by(room_id=room_id, date=date)
    if exclude_id:
        q = q.filter(Booking.id != exclude_id)
    return any(start_time < b.end_time and end_time > b.start_time for b in q.all())


# ── Health ────────────────────────────────────────────────────────────────────

@app.get('/api/health')
def health():
    return jsonify({'status': 'ok'})


# ── Setup (first-run: creates the first super admin) ─────────────────────────

SAFE_EMAIL_RE = re.compile(r'^[A-Za-z0-9.@_\-+]+$')


@app.get('/api/auth/setup-status')
def setup_status():
    """Returns whether the system still needs its first super admin."""
    needs_setup = not User.query.filter_by(is_super_admin=True).first()
    return jsonify({'needs_setup': needs_setup})


@app.post('/api/auth/setup')
def setup():
    """Creates the first super administrator. Only works when no super admin exists."""
    if User.query.filter_by(is_super_admin=True).first():
        return jsonify({'error': 'Configuração inicial já foi realizada'}), 403
    d = request.get_json() or {}
    name = str(d.get('name', '')).strip()
    email = str(d.get('email', '')).lower().strip()
    password = str(d.get('password', ''))
    if not name or not email or not password:
        return jsonify({'error': 'Nome, e-mail e senha são obrigatórios'}), 400
    if not SAFE_EMAIL_RE.match(email):
        return jsonify({'error': 'E-mail não pode conter acentos ou caracteres especiais'}), 400
    pwd_ok, pwd_err = _validate_password(password)
    if not pwd_ok:
        return jsonify({'error': pwd_err}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'E-mail já cadastrado'}), 409
    sa = User(
        name=name, email=email,
        password_hash=generate_password_hash(password),
        is_super_admin=True, department='',
    )
    db.session.add(sa)
    db.session.commit()
    token = create_access_token(identity=sa.id)
    return jsonify({
        'message': 'Super administrador criado com sucesso',
        'token': token,
        'user': sa.to_dict(),
        'memberships': sa.memberships_dict(),
    }), 201


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post('/api/auth/login')
def login():
    d = request.get_json() or {}
    email = str(d.get('email', '')).lower().strip()
    password = str(d.get('password', ''))
    u = User.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash, password):
        return jsonify({'error': 'Credenciais inválidas'}), 401

    # Super admins bypass membership checks
    if u.is_super_admin:
        return jsonify({
            'token': create_access_token(identity=u.id),
            'user': u.to_dict(),
            'memberships': u.memberships_dict(),
        })

    # Regular users must have at least one approved membership
    memberships = u.memberships_dict()
    approved = [m for m in memberships if m['status'] == 'approved']
    pending = [m for m in memberships if m['status'] == 'pending']
    blocked = [m for m in memberships if m['status'] == 'blocked']

    if not memberships:
        return jsonify({'error': 'Você não pertence a nenhum estabelecimento'}), 403
    if not approved:
        if pending:
            return jsonify({'error': 'Seu cadastro aguarda aprovação do administrador'}), 403
        if blocked:
            return jsonify({'error': 'Seu acesso foi bloqueado. Contate o administrador'}), 403
        return jsonify({'error': 'Nenhum acesso aprovado'}), 403

    return jsonify({
        'token': create_access_token(identity=u.id),
        'user': u.to_dict(),
        'memberships': approved,
    })


@app.get('/api/auth/me')
@jwt_required()
def me():
    u = current_user()
    if not u:
        return jsonify({'error': 'Not found'}), 404
    if u.is_super_admin:
        memberships = u.memberships_dict()
    else:
        memberships = [m for m in u.memberships_dict() if m['status'] == 'approved']
    return jsonify({'user': u.to_dict(), 'memberships': memberships})


# ── Super Admin: Establishments ──────────────────────────────────────────────

@app.get('/api/super/establishments')
@super_admin_required
def super_list_establishments():
    ests = Establishment.query.order_by(Establishment.created_at.desc()).all()
    return jsonify([e.to_dict() for e in ests])


@app.post('/api/super/establishments')
@super_admin_required
def super_create_establishment():
    d = request.get_json() or {}
    name = str(d.get('name', '')).strip()
    if not name:
        return jsonify({'error': 'Nome é obrigatório'}), 400
    address = str(d.get('address', '')).strip()
    est = Establishment(name=name, address=address, status='active')
    db.session.add(est)
    db.session.commit()
    seed_establishment_settings(est.id)
    return jsonify(est.to_dict()), 201


@app.patch('/api/super/establishments/<int:eid>')
@super_admin_required
def super_update_establishment(eid):
    est = db.session.get(Establishment, eid)
    if not est:
        return jsonify({'error': 'Estabelecimento não encontrado'}), 404
    d = request.get_json() or {}
    if 'name' in d:
        name = str(d['name']).strip()
        if not name:
            return jsonify({'error': 'Nome não pode ser vazio'}), 400
        est.name = name
    if 'address' in d:
        est.address = str(d['address']).strip()
    if 'status' in d:
        new_status = str(d['status']).strip().lower()
        if new_status not in ('active', 'inactive'):
            return jsonify({'error': 'Status inválido'}), 400
        # Transition active -> inactive: cancel future bookings
        if est.status == 'active' and new_status == 'inactive':
            _cancel_future_bookings_on_deactivate(est)
        est.status = new_status
    db.session.commit()
    return jsonify(est.to_dict())


@app.delete('/api/super/establishments/<int:eid>')
@super_admin_required
def super_delete_establishment(eid):
    est = db.session.get(Establishment, eid)
    if not est:
        return jsonify({'error': 'Estabelecimento não encontrado'}), 404
    try:
        # Cascade: bookings, rooms, memberships, invitations, settings
        Booking.query.filter_by(establishment_id=eid).delete()
        Room.query.filter_by(establishment_id=eid).delete()
        UserEstablishment.query.filter_by(establishment_id=eid).delete()
        Invitation.query.filter_by(establishment_id=eid).delete()
        AuditLog.query.filter_by(establishment_id=eid).delete()
        Setting.query.filter_by(establishment_id=eid).delete()
        db.session.delete(est)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting establishment #{eid}: {e}')
        return jsonify({'error': 'Erro interno ao remover estabelecimento'}), 500
    return jsonify({'message': 'Estabelecimento removido'})


def _cancel_future_bookings_on_deactivate(est):
    """When an establishment is deactivated, cancel all future bookings and
    notify each affected user, using the establishment's own SMTP + templates."""
    now_local = _get_establishment_now(est.id)
    today = now_local.strftime('%Y-%m-%d')
    now_time = now_local.strftime('%H:%M')
    future = Booking.query.filter(
        Booking.establishment_id == est.id,
    ).filter(
        (Booking.date > today) |
        ((Booking.date == today) & (Booking.start_time > now_time))
    ).all()
    # Send cancellation emails BEFORE deletion so we still have all the data
    for b in future:
        if b.user:
            _email_booking_cancelled(est, b.user, b)
    for b in future:
        db.session.delete(b)
    app.logger.info(f'Cancelled {len(future)} future booking(s) on deactivation of est #{est.id}')


# ── Super Admin: Users & Memberships ─────────────────────────────────────────

@app.get('/api/super/users')
@super_admin_required
def super_list_users():
    """List all users globally, with their memberships."""
    users = User.query.order_by(User.created_at.desc()).all()
    result = []
    for u in users:
        d = u.to_dict()
        d['memberships'] = u.memberships_dict()
        result.append(d)
    return jsonify(result)


@app.post('/api/super/users/<string:uid>/super-admin')
@super_admin_required
def super_toggle_super_admin(uid):
    """Promote or demote a user's super admin flag."""
    u = db.session.get(User, uid)
    if not u:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    d = request.get_json() or {}
    if 'is_super_admin' not in d:
        return jsonify({'error': 'Campo is_super_admin obrigatório'}), 400
    new_val = bool(d['is_super_admin'])
    # Prevent demoting the last super admin
    if not new_val and u.is_super_admin:
        remaining = User.query.filter(
            User.is_super_admin == True, User.id != u.id
        ).count()
        if remaining == 0:
            return jsonify({'error': 'Não é possível remover o último super admin'}), 400
    u.is_super_admin = new_val
    db.session.commit()
    return jsonify(u.to_dict())


@app.post('/api/super/users')
@super_admin_required
def super_create_user():
    """Create a new super admin user."""
    d = request.get_json() or {}
    name = str(d.get('name', '')).strip()
    email = str(d.get('email', '')).lower().strip()
    password = str(d.get('password', ''))
    if not name or not email or not password:
        return jsonify({'error': 'Nome, e-mail e senha são obrigatórios'}), 400
    if not SAFE_EMAIL_RE.match(email):
        return jsonify({'error': 'E-mail inválido'}), 400
    pwd_ok, pwd_err = _validate_password(password)
    if not pwd_ok:
        return jsonify({'error': pwd_err}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'E-mail já cadastrado'}), 409
    u = User(
        name=name, email=email,
        password_hash=generate_password_hash(password),
        is_super_admin=True, department='',
    )
    db.session.add(u)
    db.session.commit()
    return jsonify(u.to_dict()), 201


@app.patch('/api/super/users/<string:uid>')
@super_admin_required
def super_update_user(uid):
    """Edit a super admin user's name, email or password."""
    u = db.session.get(User, uid)
    if not u:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    d = request.get_json() or {}
    if 'name' in d:
        name = str(d['name']).strip()
        if not name:
            return jsonify({'error': 'Nome não pode ser vazio'}), 400
        u.name = name
    if 'email' in d:
        email = str(d['email']).lower().strip()
        if not SAFE_EMAIL_RE.match(email):
            return jsonify({'error': 'E-mail inválido'}), 400
        conflict = User.query.filter_by(email=email).first()
        if conflict and conflict.id != uid:
            return jsonify({'error': 'E-mail já cadastrado'}), 409
        u.email = email
    if 'password' in d:
        password = str(d['password'])
        pwd_ok, pwd_err = _validate_password(password)
        if not pwd_ok:
            return jsonify({'error': pwd_err}), 400
        u.password_hash = generate_password_hash(password)
    db.session.commit()
    return jsonify(u.to_dict())


@app.delete('/api/super/users/<string:uid>')
@super_admin_required
def super_delete_user(uid):
    """Delete a super admin user. Cannot delete self or the last super admin."""
    current_id = get_jwt_identity()
    if uid == current_id:
        return jsonify({'error': 'Você não pode excluir sua própria conta'}), 400
    u = db.session.get(User, uid)
    if not u:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    if u.is_super_admin:
        remaining = User.query.filter(
            User.is_super_admin == True, User.id != uid
        ).count()
        if remaining == 0:
            return jsonify({'error': 'Não é possível excluir o último super admin'}), 400
    # Remove memberships and bookings before deleting
    UserEstablishment.query.filter_by(user_id=uid).delete()
    Booking.query.filter_by(user_id=uid).delete()
    db.session.delete(u)
    db.session.commit()
    return jsonify({'ok': True})


@app.post('/api/super/establishments/<int:eid>/memberships')
@super_admin_required
def super_create_membership(eid):
    """Super admin attaches an existing user to an establishment as admin or user.
    Useful for bootstrapping the first admin of a newly created establishment."""
    est = db.session.get(Establishment, eid)
    if not est:
        return jsonify({'error': 'Estabelecimento não encontrado'}), 404
    d = request.get_json() or {}
    user_id = str(d.get('user_id', '')).strip()
    role = str(d.get('role', 'user')).strip().lower()
    status = str(d.get('status', 'approved')).strip().lower()
    if role not in ('admin', 'user'):
        return jsonify({'error': 'Role inválido'}), 400
    if status not in ('pending', 'approved', 'blocked'):
        return jsonify({'error': 'Status inválido'}), 400
    u = db.session.get(User, user_id)
    if not u:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    existing = get_membership(u, eid)
    if existing:
        return jsonify({'error': 'Usuário já pertence a este estabelecimento'}), 409
    m = UserEstablishment(
        user_id=u.id, establishment_id=eid, role=role, status=status
    )
    db.session.add(m)
    db.session.commit()
    return jsonify({
        'establishment_id': eid,
        'user_id': u.id,
        'role': m.role,
        'status': m.status,
    }), 201


# ── Super Admin: Global SMTP ──────────────────────────────────────────────────

@app.get('/api/super/smtp')
@super_admin_required
def get_global_smtp():
    """Return global SMTP settings (password masked) for super admins."""
    result = {}
    for k in GLOBAL_SMTP_KEYS:
        if k == 'mail_password':
            result['mail_password_set'] = bool(_get_global_setting(k, ''))
        else:
            result[k] = _get_global_setting(k, GLOBAL_SMTP_DEFAULTS.get(k, ''))
    return jsonify(result)


@app.post('/api/super/smtp')
@super_admin_required
def update_global_smtp():
    """Save global SMTP settings. Only super admins can call this."""
    d = request.get_json() or {}
    for k in GLOBAL_SMTP_KEYS:
        if k not in d:
            continue
        if k == 'mail_password' and d[k] == '':
            continue  # empty string means "leave unchanged"
        _set_global_setting(k, str(d[k]) if d[k] is not None else '')
    db.session.commit()
    return jsonify({'message': 'Configurações de SMTP global salvas'})


@app.post('/api/super/smtp/test-email')
@super_admin_required
def test_global_smtp():
    """Send a test email using the global super-admin SMTP."""
    cfg = _get_global_mail_config()
    if not cfg:
        return jsonify({'error': 'Configurações de SMTP global não definidas'}), 400
    u = g.user
    _send_global_email_async(
        '✅ Teste de SMTP global — SpaceHub',
        [u.email],
        f'<p>Olá, <strong>{u.name}</strong>! O SMTP global do SpaceHub está funcionando.</p>',
    )
    return jsonify({'message': f'E-mail de teste enviado para {u.email}'})


# ── Rooms (scoped to current establishment) ──────────────────────────────────

@app.get('/api/rooms')
@establishment_member_required
def list_rooms():
    rooms = Room.query.filter_by(establishment_id=g.establishment.id).all()
    return jsonify([r.to_dict() for r in rooms])


@app.post('/api/rooms')
@establishment_admin_required
def create_room():
    d = request.get_json() or {}
    if not all(k in d for k in ('name', 'capacity')):
        return jsonify({'error': 'Nome e capacidade são obrigatórios'}), 400
    try:
        capacity = int(d['capacity'])
    except (ValueError, TypeError):
        return jsonify({'error': 'Capacidade inválida'}), 400
    status = str(d.get('status', 'active')).strip().lower()
    if status not in ROOM_STATUSES:
        return jsonify({'error': f'Status inválido. Valores permitidos: {", ".join(ROOM_STATUSES)}'}), 400
    name = str(d['name']).strip()
    if not name:
        return jsonify({'error': 'Nome não pode ser vazio'}), 400
    r = Room(
        establishment_id=g.establishment.id,
        name=name,
        capacity=capacity,
        resources=json.dumps(d.get('resources', [])),
        status=status,
    )
    db.session.add(r)
    _audit(action='room.created', target=name, establishment_id=g.establishment.id, actor=g.user)
    db.session.commit()
    return jsonify(r.to_dict()), 201


@app.patch('/api/rooms/<int:rid>')
@establishment_admin_required
def update_room(rid):
    r = Room.query.filter_by(id=rid, establishment_id=g.establishment.id).first()
    if not r:
        return jsonify({'error': 'Sala não encontrada'}), 404
    d = request.get_json() or {}
    if 'name' in d:
        name = str(d['name']).strip()
        if not name:
            return jsonify({'error': 'Nome não pode ser vazio'}), 400
        r.name = name
    if 'status' in d:
        new_status = str(d['status']).strip().lower()
        if new_status not in ROOM_STATUSES:
            return jsonify({'error': f'Status inválido. Valores permitidos: {", ".join(ROOM_STATUSES)}'}), 400
        r.status = new_status
    if 'capacity' in d:
        try:
            r.capacity = int(d['capacity'])
        except (ValueError, TypeError):
            return jsonify({'error': 'Capacidade inválida'}), 400
    if 'resources' in d:
        r.resources = json.dumps(d['resources'])
    db.session.commit()
    return jsonify(r.to_dict())


@app.delete('/api/rooms/<int:rid>')
@establishment_admin_required
def delete_room(rid):
    r = Room.query.filter_by(id=rid, establishment_id=g.establishment.id).first()
    if not r:
        return jsonify({'error': 'Sala não encontrada'}), 404
    try:
        Booking.query.filter_by(room_id=rid).delete()
        _audit(action='room.deleted', target=r.name, establishment_id=g.establishment.id, actor=g.user)
        db.session.delete(r)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting room #{rid}: {e}')
        return jsonify({'error': 'Erro interno ao remover sala'}), 500
    return jsonify({'message': 'Sala removida'})


# ── Bookings (scoped to current establishment) ───────────────────────────────

@app.get('/api/bookings')
@establishment_member_required
def list_bookings():
    """List bookings in the current establishment.
    - Admins (or super admin) see all bookings of the establishment.
    - Regular users see only their own bookings in this establishment.
    - Expired bookings (end_time already passed in the establishment's timezone)
      are excluded automatically."""
    now_local = _get_establishment_now(g.establishment.id)
    today = now_local.strftime('%Y-%m-%d')
    now_time = now_local.strftime('%H:%M')

    q = Booking.query.filter_by(establishment_id=g.establishment.id)
    if not g.is_admin:
        q = q.filter_by(user_id=g.user.id)
    # Exclude bookings whose end_time has already passed
    q = q.filter(
        db.or_(
            Booking.date > today,
            db.and_(Booking.date == today, Booking.end_time > now_time),
        )
    )
    bs = q.order_by(Booking.date, Booking.start_time).all()
    return jsonify([b.to_dict() for b in bs])


@app.get('/api/bookings/room/<int:rid>')
@establishment_member_required
def room_bookings(rid):
    room = Room.query.filter_by(id=rid, establishment_id=g.establishment.id).first()
    if not room:
        return jsonify({'error': 'Sala não encontrada'}), 404
    date = request.args.get('date')
    q = Booking.query.filter_by(room_id=rid)
    if date:
        q = q.filter_by(date=date)
    return jsonify([b.to_dict() for b in q.order_by(Booking.start_time).all()])


@app.post('/api/bookings')
@establishment_member_required
def create_booking():
    d = request.get_json() or {}
    if not all(k in d for k in ('room_id', 'date', 'start_time', 'end_time')):
        return jsonify({'error': 'Campos obrigatórios ausentes'}), 400
    # Room must belong to the current establishment
    r = Room.query.filter_by(id=d['room_id'], establishment_id=g.establishment.id).first()
    if not r:
        return jsonify({'error': 'Sala não encontrada neste estabelecimento'}), 404
    if r.status == 'maintenance':
        return jsonify({'error': 'Sala em manutenção'}), 400
    # Validate time format
    try:
        datetime.strptime(d['start_time'], '%H:%M')
        datetime.strptime(d['end_time'], '%H:%M')
    except ValueError:
        return jsonify({'error': 'Horário inválido (use HH:MM)'}), 400
    if d['start_time'] >= d['end_time']:
        return jsonify({'error': 'Horário inválido'}), 400
    # Reject past bookings — use establishment timezone
    now = _get_establishment_now(g.establishment.id)
    try:
        booking_date = datetime.strptime(d['date'], '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Data inválida'}), 400
    if booking_date < now.date():
        return jsonify({'error': 'Não é possível reservar em datas passadas'}), 400
    if booking_date == now.date():
        booking_start = datetime.strptime(d['start_time'], '%H:%M').time()
        if booking_start <= now.time():
            return jsonify({'error': 'Não é possível reservar horários que já passaram'}), 400
    if check_conflict(r.id, d['date'], d['start_time'], d['end_time']):
        return jsonify({'error': 'Horário já reservado para esta sala'}), 409
    b = Booking(
        establishment_id=g.establishment.id,
        user_id=g.user.id,
        room_id=r.id,
        date=d['date'],
        start_time=d['start_time'],
        end_time=d['end_time'],
        description=str(d.get('description', '')).strip()[:200],
    )
    db.session.add(b)
    db.session.commit()
    _email_booking_confirmed(g.establishment, g.user, b)
    return jsonify(b.to_dict()), 201


@app.delete('/api/bookings/<int:bid>')
@establishment_member_required
def cancel_booking(bid):
    b = Booking.query.filter_by(id=bid, establishment_id=g.establishment.id).first()
    if not b:
        return jsonify({'error': 'Reserva não encontrada'}), 404
    if not g.is_admin and b.user_id != g.user.id:
        return jsonify({'error': 'Não autorizado'}), 403
    db.session.delete(b)
    db.session.commit()
    return jsonify({'message': 'Reserva cancelada'})


# ── Establishment Admin: Users (memberships) ─────────────────────────────────

@app.get('/api/admin/users')
@establishment_admin_required
def admin_list_users():
    """List all users belonging to the current establishment.
    Super admins are excluded unless they also have an explicit membership."""
    rows = (
        db.session.query(User, UserEstablishment)
        .join(UserEstablishment, UserEstablishment.user_id == User.id)
        .filter(UserEstablishment.establishment_id == g.establishment.id)
        .order_by(User.created_at.desc())
        .all()
    )
    result = []
    for u, m in rows:
        d = u.to_dict()
        d['role'] = m.role
        d['status'] = m.status
        result.append(d)
    return jsonify(result)


@app.route('/api/admin/users/<string:uid>', methods=['PATCH', 'POST'])
@establishment_admin_required
def admin_update_user(uid):
    """Update a user's membership in the current establishment.
    Only role/status of the membership can be changed here. Password changes
    are intentionally NOT allowed from the establishment admin panel — passwords
    are global to the user."""
    m = UserEstablishment.query.filter_by(
        user_id=uid, establishment_id=g.establishment.id
    ).first()
    if not m:
        return jsonify({'error': 'Usuário não pertence a este estabelecimento'}), 404
    u = db.session.get(User, uid)
    if not u:
        return jsonify({'error': 'Usuário não encontrado'}), 404

    d = request.get_json() or {}
    old_status = m.status
    if 'status' in d:
        new_status = str(d['status']).strip().lower()
        if new_status not in ('pending', 'approved', 'blocked'):
            return jsonify({'error': 'Status inválido'}), 400
        m.status = new_status
    if 'role' in d:
        new_role = str(d['role']).strip().lower()
        if new_role not in ('admin', 'user'):
            return jsonify({'error': 'Role inválido'}), 400
        # Prevent demoting the last admin of an establishment
        if new_role == 'user' and m.role == 'admin':
            remaining_admins = UserEstablishment.query.filter_by(
                establishment_id=g.establishment.id, role='admin', status='approved'
            ).filter(UserEstablishment.user_id != uid).count()
            if remaining_admins == 0:
                return jsonify({'error': 'Não é possível remover o último admin deste estabelecimento'}), 400
        m.role = new_role

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error updating user membership: {e}')
        return jsonify({'error': 'Erro interno ao atualizar usuário'}), 500

    # Audit log
    _audit(
        action=f'user.{m.status}' if old_status != m.status else f'user.role_changed',
        target=f'{u.name} ({u.email})',
        establishment_id=g.establishment.id,
        actor=g.user,
    )
    try:
        db.session.commit()
    except Exception:
        pass  # audit entry is non-critical

    # Email notifications on status transitions
    new_status = m.status
    if old_status != new_status:
        if new_status == 'approved':
            _email_membership_approved(g.establishment, u)
        elif new_status == 'blocked':
            _email_membership_blocked(g.establishment, u)

    result = u.to_dict()
    result['role'] = m.role
    result['status'] = m.status
    return jsonify(result)


@app.delete('/api/admin/users/<string:uid>')
@establishment_admin_required
def admin_remove_user(uid):
    """Remove a user's membership in the current establishment (NOT the user itself).
    Also deletes that user's bookings within this establishment."""
    m = UserEstablishment.query.filter_by(
        user_id=uid, establishment_id=g.establishment.id
    ).first()
    if not m:
        return jsonify({'error': 'Usuário não pertence a este estabelecimento'}), 404
    # Prevent removing the last admin
    if m.role == 'admin':
        remaining_admins = UserEstablishment.query.filter_by(
            establishment_id=g.establishment.id, role='admin', status='approved'
        ).filter(UserEstablishment.user_id != uid).count()
        if remaining_admins == 0:
            return jsonify({'error': 'Não é possível remover o último admin deste estabelecimento'}), 400
    try:
        u_name = u.name if (u := db.session.get(User, uid)) else uid
        Booking.query.filter_by(
            establishment_id=g.establishment.id, user_id=uid
        ).delete()
        db.session.delete(m)
        _audit(
            action='user.removed',
            target=f'{u_name} ({uid})',
            establishment_id=g.establishment.id,
            actor=g.user,
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error removing user {uid} from establishment: {e}')
        return jsonify({'error': 'Erro interno ao remover usuário'}), 500
    return jsonify({'message': 'Usuário removido do estabelecimento'})


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get('/api/admin/audit-log')
@establishment_admin_required
def get_audit_log():
    """Return the last 200 audit entries for the current establishment."""
    entries = (
        AuditLog.query
        .filter_by(establishment_id=g.establishment.id)
        .order_by(AuditLog.created_at.desc())
        .limit(200)
        .all()
    )
    return jsonify([e.to_dict() for e in entries])


# ── Establishment Settings (SMTP, allowed domains) ───────────────────────────

# Keys that are safe to expose without admin (e.g. allowed_domains for signup UI
# hint). Everything else requires admin of the establishment.
PUBLIC_SETTING_KEYS = {'allowed_domains', 'timezone'}
# Sensitive keys never returned in plaintext
SENSITIVE_SETTING_KEYS = {'mail_password'}


def _get_setting(est_id, key, default=None):
    s = Setting.query.filter_by(establishment_id=est_id, key=key).first()
    return s.value if s else default


def _set_setting(est_id, key, value):
    s = Setting.query.filter_by(establishment_id=est_id, key=key).first()
    if s:
        s.value = value
    else:
        db.session.add(Setting(establishment_id=est_id, key=key, value=value))


def _get_global_setting(key, default=None):
    s = GlobalSetting.query.filter_by(key=key).first()
    return s.value if s else default


def _set_global_setting(key, value):
    s = GlobalSetting.query.filter_by(key=key).first()
    if s:
        s.value = value
    else:
        db.session.add(GlobalSetting(key=key, value=value))


def _get_global_mail_config():
    """Load super-admin global SMTP config. Returns dict or None if not configured."""
    cfg = {k: _get_global_setting(k, GLOBAL_SMTP_DEFAULTS.get(k, '')) for k in GLOBAL_SMTP_KEYS}
    if not cfg.get('mail_username') or not cfg.get('mail_password'):
        return None
    return cfg


@app.get('/api/settings')
@establishment_member_required
def get_settings():
    """Return non-sensitive, non-email-template settings for the current establishment.
    Admins see everything except passwords; regular users see only public keys."""
    rows = Setting.query.filter_by(establishment_id=g.establishment.id).all()
    result = {}
    for s in rows:
        if s.key in EMAIL_DEFAULTS:
            continue  # email templates have their own endpoint
        if s.key in SENSITIVE_SETTING_KEYS:
            # Never leak the password; indicate whether it's set
            result[s.key + '_set'] = bool(s.value)
            continue
        if g.is_admin or s.key in PUBLIC_SETTING_KEYS:
            result[s.key] = s.value
    return jsonify(result)


@app.post('/api/admin/settings')
@establishment_admin_required
def update_settings():
    d = request.get_json() or {}
    allowed_keys = set(SETTING_DEFAULTS.keys())
    for k, v in d.items():
        if k not in allowed_keys:
            continue  # silently ignore unknown keys (protects email templates)
        if k == 'mail_password' and v == '':
            continue  # empty string means "leave unchanged"
        if k == 'timezone':
            tz_val = str(v).strip()
            try:
                ZoneInfo(tz_val)  # validate
            except Exception:
                return jsonify({'error': f'Fuso horário inválido: {tz_val}'}), 400
            _set_setting(g.establishment.id, k, tz_val)
            continue
        _set_setting(g.establishment.id, k, str(v) if v is not None else '')
    db.session.commit()
    return jsonify({'message': 'Configurações salvas'})


@app.get('/api/timezones')
def list_timezones():
    """Return sorted list of available IANA timezone names."""
    tzs = sorted(available_timezones())
    return jsonify(tzs)


@app.post('/api/admin/settings/test-email')
@establishment_admin_required
def test_email():
    """Send a test email using the current establishment's SMTP."""
    cfg = _get_establishment_mail_config(g.establishment.id)
    if not cfg:
        return jsonify({'error': 'Configurações de e-mail não definidas'}), 400
    _send_email_async(
        g.establishment.id,
        f'✅ Teste de e-mail — {g.establishment.name}',
        [g.user.email],
        f'<p>Olá, <strong>{g.user.name}</strong>! As configurações de e-mail do '
        f'estabelecimento <strong>{g.establishment.name}</strong> estão funcionando.</p>',
    )
    return jsonify({'message': f'E-mail de teste enviado para {g.user.email}'})


# ── Email Templates (per establishment) ──────────────────────────────────────

@app.get('/api/admin/email-templates')
@establishment_admin_required
def get_email_templates():
    result = {}
    for k in EMAIL_DEFAULTS.keys():
        val = _get_setting(g.establishment.id, k)
        result[k] = val if val is not None else EMAIL_DEFAULTS[k]
    return jsonify(result)


@app.post('/api/admin/email-templates')
@establishment_admin_required
def save_email_templates():
    d = request.get_json() or {}
    for k in EMAIL_DEFAULTS.keys():
        if k in d:
            _set_setting(g.establishment.id, k, str(d[k]))
    db.session.commit()
    return jsonify({'message': 'Templates salvos'})


@app.post('/api/admin/email-templates/reset')
@establishment_admin_required
def reset_email_templates():
    d = request.get_json() or {}
    key = d.get('key') if isinstance(d, dict) else None
    keys = [key] if key and key in EMAIL_DEFAULTS else list(EMAIL_DEFAULTS.keys())
    for k in keys:
        _set_setting(g.establishment.id, k, EMAIL_DEFAULTS[k])
    db.session.commit()
    return jsonify({'message': 'Templates restaurados'})


# ── Invitations (one active link per establishment) ─────────────────────────

def _get_or_create_active_invitation(est_id, created_by_user_id):
    """Return the current active invitation for the establishment, creating one
    if none exists."""
    inv = Invitation.query.filter_by(
        establishment_id=est_id, active=True
    ).first()
    if inv:
        return inv
    inv = Invitation(
        establishment_id=est_id,
        created_by=created_by_user_id,
        active=True,
    )
    db.session.add(inv)
    db.session.commit()
    return inv


@app.get('/api/admin/invitation')
@establishment_admin_required
def get_invitation():
    """Return the current active invitation for the establishment,
    creating one lazily on first call."""
    inv = _get_or_create_active_invitation(g.establishment.id, g.user.id)
    return jsonify(inv.to_dict())


@app.post('/api/admin/invitation/regenerate')
@establishment_admin_required
def regenerate_invitation():
    """Revoke any current active invitation and create a new one."""
    current = Invitation.query.filter_by(
        establishment_id=g.establishment.id, active=True
    ).all()
    for c in current:
        c.active = False
        c.revoked_at = datetime.now(timezone.utc)
    new_inv = Invitation(
        establishment_id=g.establishment.id,
        created_by=g.user.id,
        active=True,
    )
    db.session.add(new_inv)
    db.session.commit()
    return jsonify(new_inv.to_dict())


@app.post('/api/admin/invitation/revoke')
@establishment_admin_required
def revoke_invitation():
    """Deactivate the current invitation without generating a new one."""
    current = Invitation.query.filter_by(
        establishment_id=g.establishment.id, active=True
    ).all()
    if not current:
        return jsonify({'message': 'Nenhum convite ativo'}), 200
    for c in current:
        c.active = False
        c.revoked_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({'message': 'Convite revogado'})


# ── Email System (per-establishment SMTP + templates) ───────────────────────

def _get_establishment_mail_config(est_id):
    """Load SMTP settings for a specific establishment. Returns dict or None."""
    keys = ['mail_server', 'mail_port', 'mail_username', 'mail_password', 'mail_from_name']
    rows = Setting.query.filter(
        Setting.establishment_id == est_id,
        Setting.key.in_(keys),
    ).all()
    cfg = {s.key: s.value for s in rows}
    if not cfg.get('mail_username') or not cfg.get('mail_password'):
        return None
    return cfg


def _send_email_async(est_id, subject, recipients, html_body):
    """Send e-mail in an isolated background thread using smtplib directly.

    Each call creates its own SMTP connection with the establishment's credentials —
    no shared global state, fully thread-safe even when multiple establishments send
    simultaneously.
    """
    if not recipients:
        return

    def _send():
        with app.app_context():
            cfg = _get_establishment_mail_config(est_id)
            if not cfg:
                app.logger.warning(f'No SMTP config for est #{est_id}; email dropped')
                return
            server    = cfg.get('mail_server') or 'smtp.gmail.com'
            port      = int(cfg.get('mail_port') or 587)
            username  = cfg['mail_username']
            password  = cfg['mail_password']
            from_name = cfg.get('mail_from_name') or 'SpaceHub'
            try:
                mime = MIMEMultipart('alternative')
                mime['Subject'] = subject
                mime['From']    = f'{from_name} <{username}>'
                mime['To']      = ', '.join(recipients)
                mime.attach(MIMEText(html_body, 'html', 'utf-8'))

                ctx = ssl.create_default_context()
                with smtplib.SMTP(server, port, timeout=15) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=ctx)
                    smtp.login(username, password)
                    smtp.sendmail(username, recipients, mime.as_string())
                app.logger.info(f'Email sent (est #{est_id}) to {recipients}: {subject}')
            except Exception as e:
                app.logger.error(f'Email error (est #{est_id}): {e}')

    threading.Thread(target=_send, daemon=True).start()


def _send_global_email_async(subject, recipients, html_body):
    """Send e-mail using the global super-admin SMTP config."""
    if not recipients:
        return

    def _send():
        with app.app_context():
            cfg = _get_global_mail_config()
            if not cfg:
                app.logger.warning('No global SMTP config; email dropped')
                return
            server    = cfg.get('mail_server') or 'smtp.gmail.com'
            port      = int(cfg.get('mail_port') or 587)
            username  = cfg['mail_username']
            password  = cfg['mail_password']
            from_name = cfg.get('mail_from_name') or 'SpaceHub'
            try:
                mime = MIMEMultipart('alternative')
                mime['Subject'] = subject
                mime['From']    = f'{from_name} <{username}>'
                mime['To']      = ', '.join(recipients)
                mime.attach(MIMEText(html_body, 'html', 'utf-8'))

                ctx = ssl.create_default_context()
                with smtplib.SMTP(server, port, timeout=15) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=ctx)
                    smtp.login(username, password)
                    smtp.sendmail(username, recipients, mime.as_string())
                app.logger.info(f'Global email sent to {recipients}: {subject}')
            except Exception as e:
                app.logger.error(f'Global email error: {e}')

    threading.Thread(target=_send, daemon=True).start()


def _get_template(est_id, key):
    """Return template value for (est, key), falling back to default."""
    val = _get_setting(est_id, key)
    return val if val is not None else EMAIL_DEFAULTS.get(key, '')


def _render(template, replacements):
    for k, v in replacements.items():
        template = template.replace(k, str(v) if v is not None else '')
    return template


def _user_replacements(user, establishment, registered_at=None):
    date = registered_at or user.created_at
    return {
        '{{nome}}': user.name,
        '{{email}}': user.email,
        '{{setor}}': user.department or '—',
        '{{data}}': date.strftime('%d/%m/%Y %H:%M') if date else '—',
        '{{estabelecimento}}': establishment.name,
    }


def _booking_replacements(user, booking, establishment):
    base = _user_replacements(user, establishment)
    try:
        formatted_date = datetime.strptime(booking.date, '%Y-%m-%d').strftime('%d/%m/%Y')
    except Exception:
        formatted_date = booking.date
    base.update({
        '{{sala}}': booking.room.name if booking.room else '—',
        '{{data_reserva}}': formatted_date,
        '{{inicio}}': booking.start_time,
        '{{fim}}': booking.end_time,
        '{{descricao}}': booking.description or '—',
    })
    return base


def _email_new_registration(establishment, new_user, registered_at=None):
    """Notify admins (and super admins) about a new pending registration."""
    admin_rows = (
        db.session.query(User)
        .join(UserEstablishment, UserEstablishment.user_id == User.id)
        .filter(
            UserEstablishment.establishment_id == establishment.id,
            UserEstablishment.role == 'admin',
            UserEstablishment.status == 'approved',
        )
        .all()
    )
    super_admin_rows = User.query.filter_by(is_super_admin=True).all()
    seen = {u.id for u in admin_rows}
    all_recipients = list(admin_rows) + [u for u in super_admin_rows if u.id not in seen]
    recipients = [u.email for u in all_recipients]
    if not recipients:
        return
    replacements = _user_replacements(new_user, establishment, registered_at=registered_at)
    subj = _render(_get_template(establishment.id, 'email_reg_subject'), replacements)
    body = _render(_get_template(establishment.id, 'email_reg_body'), replacements)
    _send_email_async(establishment.id, subj, recipients, body)


def _email_membership_approved(establishment, user):
    subj = _render(_get_template(establishment.id, 'email_approved_subject'),
                   _user_replacements(user, establishment))
    body = _render(_get_template(establishment.id, 'email_approved_body'),
                   _user_replacements(user, establishment))
    _send_email_async(establishment.id, subj, [user.email], body)


def _email_membership_blocked(establishment, user):
    subj = _render(_get_template(establishment.id, 'email_blocked_subject'),
                   _user_replacements(user, establishment))
    body = _render(_get_template(establishment.id, 'email_blocked_body'),
                   _user_replacements(user, establishment))
    _send_email_async(establishment.id, subj, [user.email], body)


def _email_booking_reminder(establishment, user, booking):
    subj = _render(_get_template(establishment.id, 'email_reminder_subject'),
                   _booking_replacements(user, booking, establishment))
    body = _render(_get_template(establishment.id, 'email_reminder_body'),
                   _booking_replacements(user, booking, establishment))
    _send_email_async(establishment.id, subj, [user.email], body)


def _email_booking_cancelled(establishment, user, booking):
    subj = _render(_get_template(establishment.id, 'email_cancelled_subject'),
                   _booking_replacements(user, booking, establishment))
    body = _render(_get_template(establishment.id, 'email_cancelled_body'),
                   _booking_replacements(user, booking, establishment))
    _send_email_async(establishment.id, subj, [user.email], body)


def _email_booking_confirmed(establishment, user, booking):
    subj = _render(_get_template(establishment.id, 'email_booking_confirmed_subject'),
                   _booking_replacements(user, booking, establishment))
    body = _render(_get_template(establishment.id, 'email_booking_confirmed_body'),
                   _booking_replacements(user, booking, establishment))
    _send_email_async(establishment.id, subj, [user.email], body)


# ── Reminder Scheduler ────────────────────────────────────────────────────────

def _send_booking_reminders():
    """Background job: find bookings starting in ~15 minutes and notify users.
    - Uses per-establishment timezone for time calculation.
    - Checks a ±2 min window around the 15-min mark to tolerate scheduler jitter.
    - Uses an atomic conditional UPDATE to prevent duplicate reminders under
      concurrent execution (max_instances=1 also helps, but belt-and-suspenders)."""
    with app.app_context():
        # Get all active establishments that have pending reminders
        active_est_ids = (
            db.session.query(Booking.establishment_id)
            .filter_by(reminder_sent=False)
            .distinct()
            .all()
        )
        for (est_id,) in active_est_ids:
            est = db.session.get(Establishment, est_id)
            if not est or est.status != 'active':
                continue
            # Calculate target window in this establishment's timezone
            now_local  = _get_establishment_now(est_id)
            lo = now_local + timedelta(minutes=13)
            hi = now_local + timedelta(minutes=17)
            lo_date, lo_time = lo.strftime('%Y-%m-%d'), lo.strftime('%H:%M')
            hi_date, hi_time = hi.strftime('%Y-%m-%d'), hi.strftime('%H:%M')

            # Build a window query (handle same-day only for simplicity;
            # bookings spanning midnight are an edge case not worth complicating)
            if lo_date == hi_date:
                candidates = Booking.query.filter(
                    Booking.establishment_id == est_id,
                    Booking.reminder_sent == False,
                    Booking.date == lo_date,
                    Booking.start_time >= lo_time,
                    Booking.start_time <= hi_time,
                ).all()
            else:
                # Rare window crossing midnight — include both sides
                candidates = Booking.query.filter(
                    Booking.establishment_id == est_id,
                    Booking.reminder_sent == False,
                    db.or_(
                        db.and_(Booking.date == lo_date, Booking.start_time >= lo_time),
                        db.and_(Booking.date == hi_date, Booking.start_time <= hi_time),
                    ),
                ).all()

            for b in candidates:
                if not b.user:
                    continue
                # Atomic claim: only send if we actually flip reminder_sent
                result = db.session.execute(
                    sa_update(Booking)
                    .where(Booking.id == b.id, Booking.reminder_sent == False)
                    .values(reminder_sent=True)
                )
                db.session.commit()
                if result.rowcount == 0:
                    continue  # another thread already handled it
                _email_booking_reminder(est, b.user, b)
                app.logger.info(f'Reminder sent for booking #{b.id} (est #{est_id})')


def _start_reminder_scheduler():
    if not APSCHEDULER_AVAILABLE:
        app.logger.warning('APScheduler not installed — booking reminders disabled.')
        return
    scheduler = BackgroundScheduler(timezone='UTC')
    scheduler.add_job(
        _send_booking_reminders,
        trigger='interval',
        seconds=60,
        max_instances=1,
        misfire_grace_time=30,
        id='booking_reminders',
    )
    scheduler.start()
    app.logger.info('Booking reminder scheduler started (interval: 60s).')


# ── Public: Invitation lookup & signup flow ──────────────────────────────────

def _resolve_invitation(token):
    """Return (invitation, establishment, error_response). Validates the token
    is active and the establishment is active."""
    if not token:
        return None, None, (jsonify({'error': 'Token obrigatório'}), 400)
    inv = Invitation.query.filter_by(token=token, active=True).first()
    if not inv:
        return None, None, (jsonify({'error': 'Link de convite inválido ou revogado'}), 404)
    est = db.session.get(Establishment, inv.establishment_id)
    if not est or est.status != 'active':
        return None, None, (jsonify({'error': 'Estabelecimento indisponível'}), 403)
    return inv, est, None


def _check_email_domain(email, establishment_id):
    """Validate email against the establishment's allowed_domains list.
    Returns (ok, error_message). Empty list means any domain is allowed."""
    raw = _get_setting(establishment_id, 'allowed_domains', '[]')
    try:
        domains = json.loads(raw) if raw else []
    except (json.JSONDecodeError, TypeError):
        domains = []
    domains = [d.strip().lower() for d in domains if d and d.strip()]
    if not domains:
        return True, None
    email_domain = email.split('@')[-1] if '@' in email else ''
    if email_domain not in domains:
        return False, 'Domínio de e-mail não permitido. Domínios aceitos: ' + ', '.join(domains)
    return True, None


@app.get('/api/invitation/<token>')
def public_invitation_info(token):
    """Public: returns basic info about the establishment behind an invitation token,
    so the signup page can show its name."""
    inv, est, err = _resolve_invitation(token)
    if err:
        return err
    return jsonify({
        'establishment_id': est.id,
        'establishment_name': est.name,
    })


@app.post('/api/invitation/<token>/check-email')
def public_invitation_check_email(token):
    """Public: given an email, tells the frontend which flow to use.
    - mode=new_user: email doesn't exist anywhere → show full signup form
    - mode=existing_user: email exists → ask user to log in and confirm joining
    Also validates the email against the establishment's allowed domains
    (rule (a): domain check applies to every new association).
    Returns 409 if the user already has any membership in this establishment."""
    inv, est, err = _resolve_invitation(token)
    if err:
        return err
    d = request.get_json() or {}
    email = str(d.get('email', '')).lower().strip()
    if not email:
        return jsonify({'error': 'E-mail é obrigatório'}), 400
    if not SAFE_EMAIL_RE.match(email):
        return jsonify({'error': 'E-mail não pode conter acentos ou caracteres especiais'}), 400
    ok, msg = _check_email_domain(email, est.id)
    if not ok:
        return jsonify({'error': msg}), 403

    existing = User.query.filter_by(email=email).first()
    if existing:
        # Check if already has a membership in this establishment
        m = get_membership(existing, est.id)
        if m:
            if m.status == 'approved':
                return jsonify({'error': 'Você já tem acesso a este estabelecimento'}), 409
            if m.status == 'pending':
                return jsonify({'error': 'Você já solicitou acesso a este estabelecimento. Aguarde a aprovação.'}), 409
            if m.status == 'blocked':
                return jsonify({'error': 'Seu acesso a este estabelecimento foi bloqueado.'}), 403
        return jsonify({
            'mode': 'existing_user',
            'user_name': existing.name,
            'establishment_name': est.name,
        })
    return jsonify({
        'mode': 'new_user',
        'establishment_name': est.name,
    })


@app.post('/api/invitation/<token>/register')
def public_invitation_register(token):
    """Public: register a brand-new user via invitation link.
    Creates the global user + a 'pending' membership in the establishment.
    Rejects if the email already exists — caller should use /join instead."""
    inv, est, err = _resolve_invitation(token)
    if err:
        return err
    d = request.get_json() or {}
    name = str(d.get('name', '')).strip()
    email = str(d.get('email', '')).lower().strip()
    password = str(d.get('password', ''))
    department = str(d.get('department', '')).strip()

    if not name or not email or not password or not department:
        return jsonify({'error': 'Nome, e-mail, senha e setor são obrigatórios'}), 400
    if not SAFE_EMAIL_RE.match(email):
        return jsonify({'error': 'E-mail não pode conter acentos ou caracteres especiais'}), 400
    pwd_ok, pwd_err = _validate_password(password)
    if not pwd_ok:
        return jsonify({'error': pwd_err}), 400
    ok, msg = _check_email_domain(email, est.id)
    if not ok:
        return jsonify({'error': msg}), 403
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'E-mail já cadastrado. Faça login para solicitar acesso a este estabelecimento.'}), 409

    u = User(
        name=name, email=email,
        password_hash=generate_password_hash(password),
        department=department,
    )
    db.session.add(u)
    db.session.flush()  # need u.id before creating membership
    m = UserEstablishment(
        user_id=u.id, establishment_id=est.id,
        role='user', status='pending',
    )
    db.session.add(m)
    db.session.commit()

    # Notify establishment admins about new pending registration
    _email_new_registration(est, u)

    return jsonify({
        'message': 'Cadastro recebido. Aguarde a aprovação do administrador.',
        'user': u.to_dict(),
        'establishment': {'id': est.id, 'name': est.name},
    }), 201


@app.post('/api/invitation/<token>/join')
@jwt_required()
def public_invitation_join(token):
    """Authenticated: an existing user requests to join another establishment
    via its invitation link. Creates a 'pending' membership."""
    inv, est, err = _resolve_invitation(token)
    if err:
        return err
    u = current_user()
    if not u:
        return jsonify({'error': 'Usuário não encontrado'}), 401

    # Domain rule applies to any new association, even when reusing a user
    ok, msg = _check_email_domain(u.email, est.id)
    if not ok:
        return jsonify({'error': msg}), 403

    existing = get_membership(u, est.id)
    if existing:
        if existing.status == 'approved':
            return jsonify({'error': 'Você já tem acesso a este estabelecimento'}), 409
        if existing.status == 'pending':
            return jsonify({'error': 'Você já solicitou acesso a este estabelecimento'}), 409
        if existing.status == 'blocked':
            return jsonify({'error': 'Seu acesso a este estabelecimento está bloqueado'}), 403

    m = UserEstablishment(
        user_id=u.id, establishment_id=est.id,
        role='user', status='pending',
    )
    db.session.add(m)
    db.session.commit()

    # Notify establishment admins about existing user requesting access
    _email_new_registration(est, u, registered_at=m.created_at)

    return jsonify({
        'message': 'Solicitação enviada. Aguarde a aprovação do administrador.',
        'establishment': {'id': est.id, 'name': est.name},
    }), 201


# ── Password Reset ────────────────────────────────────────────────────────────

@app.post('/api/auth/forgot-password')
def forgot_password():
    """Request a password reset. Always returns 200 to prevent email enumeration."""
    d = request.get_json() or {}
    email = str(d.get('email', '')).lower().strip()
    if not email:
        return jsonify({'message': 'Se o e-mail existir, você receberá as instruções.'}), 200

    u = User.query.filter_by(email=email).first()
    if not u:
        return jsonify({'message': 'Se o e-mail existir, você receberá as instruções.'}), 200

    # Invalidate previous tokens for this user
    PasswordResetToken.query.filter_by(user_id=u.id, used=False).update({'used': True})

    token = PasswordResetToken(
        user_id=u.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.session.add(token)
    db.session.commit()

    reset_body = (
        f'<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        f'<h2 style="color:#1a73e8">Redefinição de senha — SpaceHub</h2>'
        f'<p>Olá, <strong>{u.name}</strong>!</p>'
        f'<p>Recebemos uma solicitação para redefinir sua senha. '
        f'Use o código abaixo (válido por 1 hora):</p>'
        f'<div style="background:#f5f5f5;padding:16px;border-radius:8px;'
        f'text-align:center;font-size:24px;font-family:monospace;'
        f'letter-spacing:4px;margin:20px 0">{token.token}</div>'
        f'<p style="font-size:13px;color:#999">Se você não solicitou isso, ignore este e-mail.</p>'
        f'<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        f'<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        f'</div>'
    )

    sent = False
    if u.is_super_admin:
        # Super admins always use the global SMTP
        cfg = _get_global_mail_config()
        if cfg:
            _send_global_email_async('🔑 Redefinição de senha — SpaceHub', [u.email], reset_body)
            sent = True
    else:
        # Regular users: try any establishment SMTP they belong to
        memberships = UserEstablishment.query.filter_by(user_id=u.id, status='approved').all()
        for m in memberships:
            cfg = _get_establishment_mail_config(m.establishment_id)
            if cfg:
                _send_email_async(
                    m.establishment_id,
                    '🔑 Redefinição de senha — SpaceHub',
                    [u.email],
                    reset_body,
                )
                sent = True
                break

    if not sent:
        app.logger.warning(f'Password reset requested for {email} but no SMTP configured.')

    return jsonify({'message': 'Se o e-mail existir, você receberá as instruções.'}), 200


@app.post('/api/auth/reset-password')
def reset_password():
    """Validate reset token and set a new password."""
    d = request.get_json() or {}
    token_str = str(d.get('token', '')).strip()
    new_password = str(d.get('password', ''))

    if not token_str or not new_password:
        return jsonify({'error': 'Token e nova senha são obrigatórios'}), 400

    pwd_ok, pwd_err = _validate_password(new_password)
    if not pwd_ok:
        return jsonify({'error': pwd_err}), 400

    prt = PasswordResetToken.query.filter_by(token=token_str, used=False).first()
    if not prt:
        return jsonify({'error': 'Token inválido ou já utilizado'}), 400
    if prt.expires_at < datetime.now(timezone.utc):
        return jsonify({'error': 'Token expirado. Solicite um novo link.'}), 400

    prt.used = True
    prt.user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({'message': 'Senha redefinida com sucesso. Faça login.'}), 200


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get('/')
def serve_index():
    return send_file('index.html')


with app.app_context():
    db.create_all()
    # Warn loudly if running with the default JWT secret
    if _jwt_secret == _JWT_DEFAULT_SECRET:
        app.logger.warning(
            '\n' + '='*70 +
            '\n  AVISO DE SEGURANÇA: JWT_SECRET não configurado!\n'
            '  Defina a variável de ambiente JWT_SECRET com um valor seguro\n'
            '  antes de usar em produção. Exemplo:\n'
            '    export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")\n' +
            '='*70
        )
    _start_reminder_scheduler()

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', debug=debug_mode, port=5000)