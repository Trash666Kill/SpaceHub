from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid, json, os, re, threading

try:
    from flask_mail import Mail, Message
    MAIL_AVAILABLE = True
except ImportError:
    MAIL_AVAILABLE = False

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False

app = Flask(__name__)
CORS(app, origins="*")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spacehub.db'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'check_same_thread': False}}
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'dev-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

# Flask-Mail defaults (overridden at runtime via DB settings)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', '')

db = SQLAlchemy(app)
jwt = JWTManager(app)
mail = Mail(app) if MAIL_AVAILABLE else None

# ── Models ────────────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(100), nullable=True, default='')
    role = db.Column(db.String(10), default='user')
    status = db.Column(db.String(12), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'email': self.email,
                'department': self.department or '', 'role': self.role, 'status': self.status, 'created_at': self.created_at.isoformat()}

class Setting(db.Model):
    __tablename__ = 'settings'
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text)

class Room(db.Model):
    __tablename__ = 'rooms'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    resources = db.Column(db.Text, default='[]')
    status = db.Column(db.String(12), default='active')

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'capacity': self.capacity,
                'resources': json.loads(self.resources), 'status': self.status}

class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    date = db.Column(db.String(10), nullable=False, index=True)
    start_time = db.Column(db.String(5), nullable=False)
    end_time = db.Column(db.String(5), nullable=False)
    description = db.Column(db.String(200), nullable=True, default='')
    reminder_sent = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='bookings')
    room = db.relationship('Room', backref='bookings')

    def to_dict(self):
        return {'id': self.id, 'user_id': self.user_id, 'user_name': self.user.name if self.user else None,
                'room_id': self.room_id, 'room_name': self.room.name if self.room else None,
                'date': self.date, 'start_time': self.start_time, 'end_time': self.end_time,
                'description': self.description or '',
                'created_at': self.created_at.isoformat()}

# ── Email Defaults ────────────────────────────────────────────────────────────

EMAIL_DEFAULTS = {
    'email_reg_subject': '🔔 Novo cadastro aguardando aprovação — SpaceHub',
    'email_reg_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#1a73e8">Novo cadastro aguardando aprovação</h2>'
        '<p>Um novo usuário se cadastrou no <strong>SpaceHub</strong> e aguarda sua aprovação:</p>'
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
    'email_approved_subject': '✅ Sua conta no SpaceHub foi aprovada!',
    'email_approved_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#34a853">✅ Sua conta foi aprovada!</h2>'
        '<p>Olá, <strong>{{nome}}</strong>!</p>'
        '<p>Boas notícias! Sua conta no <strong>SpaceHub</strong> foi aprovada por um administrador.</p>'
        '<p>Você já pode fazer login e realizar reservas de salas.</p>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
    'email_blocked_subject': '⚠️ Sua conta no SpaceHub foi bloqueada',
    'email_blocked_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#ea4335">Conta bloqueada</h2>'
        '<p>Olá, <strong>{{nome}}</strong>.</p>'
        '<p>Sua conta no <strong>SpaceHub</strong> foi bloqueada por um administrador.</p>'
        '<p>Entre em contato com o administrador do sistema para mais informações.</p>'
        '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
        '<p style="font-size:12px;color:#999">SpaceHub — Sistema de Reserva de Salas</p>'
        '</div>'
    ),
    'email_reminder_subject': '⏰ Lembrete: sua reserva começa em 15 minutos — SpaceHub',
    'email_reminder_body': (
        '<div style="font-family:sans-serif;max-width:480px;margin:0 auto;color:#222">'
        '<h2 style="color:#1a73e8">⏰ Sua reserva começa em breve!</h2>'
        '<p>Olá, <strong>{{nome}}</strong>!</p>'
        '<p>Sua reserva começa em <strong>15 minutos</strong>:</p>'
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

# ── Helpers ───────────────────────────────────────────────────────────────────

def check_conflict(room_id, date, start_time, end_time, exclude_id=None):
    q = Booking.query.filter_by(room_id=room_id, date=date)
    if exclude_id: q = q.filter(Booking.id != exclude_id)
    return any(start_time < b.end_time and end_time > b.start_time for b in q.all())

def current_user():
    return db.session.get(User, get_jwt_identity())

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or u.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

# ── Email ─────────────────────────────────────────────────────────────────────

def _get_mail_settings():
    """Load SMTP settings from DB, return dict or None if not configured."""
    if not MAIL_AVAILABLE:
        return None
    keys = ['mail_server', 'mail_port', 'mail_username', 'mail_password', 'mail_from_name']
    rows = {s.key: s.value for s in Setting.query.filter(Setting.key.in_(keys)).all()}
    if not rows.get('mail_username') or not rows.get('mail_password'):
        return None
    return rows

def _apply_mail_config(cfg):
    app.config['MAIL_SERVER']   = cfg.get('mail_server') or 'smtp.gmail.com'
    app.config['MAIL_PORT']     = int(cfg.get('mail_port') or 587)
    app.config['MAIL_USERNAME'] = cfg['mail_username']
    app.config['MAIL_PASSWORD'] = cfg['mail_password']
    app.config['MAIL_DEFAULT_SENDER'] = (
        cfg.get('mail_from_name') or 'SpaceHub', cfg['mail_username']
    )
    mail.init_app(app)

def send_email_async(subject, recipients, html_body):
    """Send email in a background thread so requests are not blocked."""
    if not MAIL_AVAILABLE:
        return
    def _send():
        with app.app_context():
            cfg = _get_mail_settings()
            if not cfg:
                return
            _apply_mail_config(cfg)
            try:
                msg = Message(subject=subject, recipients=recipients, html=html_body)
                mail.send(msg)
            except Exception as e:
                app.logger.error(f'Email error: {e}')
    threading.Thread(target=_send, daemon=True).start()

def _render_template(template, user):
    """Replace {{variavel}} placeholders with user data."""
    replacements = {
        '{{nome}}': user.name,
        '{{email}}': user.email,
        '{{setor}}': user.department or '—',
        '{{data}}': user.created_at.strftime('%d/%m/%Y %H:%M'),
    }
    for k, v in replacements.items():
        template = template.replace(k, v)
    return template

def _render_booking_template(template, user, booking):
    """Replace {{variavel}} placeholders with user + booking data."""
    replacements = {
        '{{nome}}':        user.name,
        '{{email}}':       user.email,
        '{{setor}}':       user.department or '—',
        '{{data}}':        user.created_at.strftime('%d/%m/%Y %H:%M'),
        '{{sala}}':        booking.room.name if booking.room else '—',
        '{{data_reserva}}': datetime.strptime(booking.date, '%Y-%m-%d').strftime('%d/%m/%Y'),
        '{{inicio}}':      booking.start_time,
        '{{fim}}':         booking.end_time,
        '{{descricao}}':   booking.description or '—',
    }
    for k, v in replacements.items():
        template = template.replace(k, v)
    return template

def _email_new_registration(new_user):
    """Notify all admins about a new pending registration."""
    admins = User.query.filter_by(role='admin', status='approved').all()
    admin_emails = [a.email for a in admins]
    if not admin_emails:
        return
    subj_tpl = (db.session.get(Setting, 'email_reg_subject') or Setting(value=EMAIL_DEFAULTS['email_reg_subject'])).value
    body_tpl = (db.session.get(Setting, 'email_reg_body') or Setting(value=EMAIL_DEFAULTS['email_reg_body'])).value
    subject = _render_template(subj_tpl, new_user)
    body    = _render_template(body_tpl, new_user)
    send_email_async(subject, admin_emails, body)

def _email_account_approved(user):
    """Notify user their account was approved."""
    subj_tpl = (db.session.get(Setting, 'email_approved_subject') or Setting(value=EMAIL_DEFAULTS['email_approved_subject'])).value
    body_tpl = (db.session.get(Setting, 'email_approved_body') or Setting(value=EMAIL_DEFAULTS['email_approved_body'])).value
    subject = _render_template(subj_tpl, user)
    body    = _render_template(body_tpl, user)
    send_email_async(subject, [user.email], body)

def _email_account_blocked(user):
    """Notify user their account was blocked."""
    subj_tpl = (db.session.get(Setting, 'email_blocked_subject') or Setting(value=EMAIL_DEFAULTS['email_blocked_subject'])).value
    body_tpl = (db.session.get(Setting, 'email_blocked_body') or Setting(value=EMAIL_DEFAULTS['email_blocked_body'])).value
    subject = _render_template(subj_tpl, user)
    body    = _render_template(body_tpl, user)
    send_email_async(subject, [user.email], body)

# ── Reminder Scheduler ────────────────────────────────────────────────────────

def _send_booking_reminders():
    """Check for bookings starting in ~15 minutes and send reminder emails."""
    with app.app_context():
        now = datetime.now()
        target = now + timedelta(minutes=15)
        target_date = target.strftime('%Y-%m-%d')
        target_time = target.strftime('%H:%M')

        bookings = Booking.query.filter_by(
            date=target_date,
            start_time=target_time,
            reminder_sent=False
        ).all()

        for b in bookings:
            if not b.user:
                continue
            # Mark as sent BEFORE dispatching to prevent duplicates on concurrent runs
            b.reminder_sent = True
            db.session.commit()
            subj_tpl = (db.session.get(Setting, 'email_reminder_subject') or
                        Setting(value=EMAIL_DEFAULTS['email_reminder_subject'])).value
            body_tpl = (db.session.get(Setting, 'email_reminder_body') or
                        Setting(value=EMAIL_DEFAULTS['email_reminder_body'])).value
            subject = _render_booking_template(subj_tpl, b.user, b)
            body    = _render_booking_template(body_tpl, b.user, b)
            send_email_async(subject, [b.user.email], body)
            app.logger.info(f'Reminder sent to {b.user.email} for booking #{b.id} at {target_time}')

def _start_reminder_scheduler():
    """Start APScheduler to fire _send_booking_reminders every 60 seconds."""
    if not APSCHEDULER_AVAILABLE:
        app.logger.warning(
            'APScheduler not installed — booking reminders disabled. '
            'Run: pip install apscheduler==3.10.4'
        )
        return

    scheduler = BackgroundScheduler(timezone='America/Sao_Paulo')
    scheduler.add_job(
        _send_booking_reminders,
        trigger='interval',
        seconds=60,
        max_instances=1,        # never runs in parallel
        misfire_grace_time=30,  # still fires if delayed up to 30s
        id='booking_reminders',
    )
    scheduler.start()
    app.logger.info('Booking reminder scheduler started (interval: 60s).')

# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get('/')
def serve_index():
    return send_file('index.html')

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post('/api/auth/register')
def register():
    d = request.get_json()
    if not d or not all(k in d for k in ('name','email','password','department')):
        return jsonify({'error': 'Nome, e-mail, senha e setor são obrigatórios'}), 400
    if not d['department'].strip():
        return jsonify({'error': 'O campo Setor é obrigatório'}), 400
    email = d['email'].lower().strip()
    safe_email = re.compile(r'^[A-Za-z0-9.@_\-+]+$')
    if not safe_email.match(email):
        return jsonify({'error': 'E-mail não pode conter acentos ou caracteres especiais'}), 400
    # Domain restriction
    setting = db.session.get(Setting, 'allowed_domains')
    if setting and setting.value:
        try:
            domains = json.loads(setting.value)
        except (json.JSONDecodeError, TypeError):
            domains = []
        domains = [dom.strip().lower() for dom in domains if dom.strip()]
        if domains:
            email_domain = email.split('@')[-1] if '@' in email else ''
            if email_domain not in domains:
                return jsonify({'error': 'Domínio de e-mail não permitido. Domínios aceitos: ' + ', '.join(domains)}), 403
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409
    u = User(name=d['name'].strip(), email=email,
             department=d['department'].strip(),
             password_hash=generate_password_hash(d['password']))
    db.session.add(u); db.session.commit()
    _email_new_registration(u)
    return jsonify({'message': 'Cadastro recebido. Aguarde ativação por um administrador.', 'user': u.to_dict()}), 201

@app.post('/api/auth/login')
def login():
    d = request.get_json() or {}
    u = User.query.filter_by(email=d.get('email','').lower()).first()
    if not u or not check_password_hash(u.password_hash, d.get('password','')):
        return jsonify({'error': 'Credenciais inválidas'}), 401
    if u.status == 'pending': return jsonify({'error': 'Conta aguardando aprovação do administrador'}), 403
    if u.status == 'blocked': return jsonify({'error': 'Conta bloqueada. Contate o administrador'}), 403
    return jsonify({'token': create_access_token(identity=u.id), 'user': u.to_dict()})

@app.get('/api/auth/me')
@jwt_required()
def me():
    u = current_user()
    return jsonify(u.to_dict()) if u else (jsonify({'error': 'Not found'}), 404)

# ── Rooms ─────────────────────────────────────────────────────────────────────

@app.get('/api/rooms')
@jwt_required()
def list_rooms():
    return jsonify([r.to_dict() for r in Room.query.all()])

@app.post('/api/rooms')
@admin_required
def create_room():
    d = request.get_json() or {}
    if not all(k in d for k in ('name','capacity')):
        return jsonify({'error': 'name and capacity required'}), 400
    r = Room(name=d['name'], capacity=int(d['capacity']),
             resources=json.dumps(d.get('resources',[])), status=d.get('status','active'))
    db.session.add(r); db.session.commit()
    return jsonify(r.to_dict()), 201

@app.patch('/api/rooms/<int:rid>')
@admin_required
def update_room(rid):
    r = Room.query.get_or_404(rid); d = request.get_json() or {}
    for k in ('name','status'):
        if k in d: setattr(r, k, d[k])
    if 'capacity' in d: r.capacity = int(d['capacity'])
    if 'resources' in d: r.resources = json.dumps(d['resources'])
    db.session.commit(); return jsonify(r.to_dict())

@app.delete('/api/rooms/<int:rid>')
@admin_required
def delete_room(rid):
    r = Room.query.get_or_404(rid)
    try:
        Booking.query.filter_by(room_id=rid).delete()
        db.session.delete(r)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    return jsonify({'message': 'Sala removida'})

# ── Bookings ──────────────────────────────────────────────────────────────────

@app.get('/api/bookings')
@jwt_required()
def list_bookings():
    u = current_user()
    if u.role == 'admin':
        bs = Booking.query.order_by(Booking.date, Booking.start_time).all()
    else:
        bs = Booking.query.filter_by(user_id=u.id).order_by(Booking.date, Booking.start_time).all()
    return jsonify([b.to_dict() for b in bs])

@app.get('/api/bookings/room/<int:rid>')
@jwt_required()
def room_bookings(rid):
    date = request.args.get('date')
    q = Booking.query.filter_by(room_id=rid)
    if date: q = q.filter_by(date=date)
    return jsonify([b.to_dict() for b in q.order_by(Booking.start_time).all()])

@app.post('/api/bookings')
@jwt_required()
def create_booking():
    u = current_user()
    if u.status != 'approved': return jsonify({'error': 'Conta não aprovada'}), 403
    d = request.get_json() or {}
    if not all(k in d for k in ('room_id','date','start_time','end_time')):
        return jsonify({'error': 'Campos obrigatórios ausentes'}), 400
    r = db.session.get(Room, d['room_id'])
    if not r: return jsonify({'error': 'Sala não encontrada'}), 404
    if r.status == 'maintenance': return jsonify({'error': 'Sala em manutenção'}), 400
    if d['start_time'] >= d['end_time']: return jsonify({'error': 'Horário inválido'}), 400
    # Reject past bookings
    now = datetime.now()
    booking_date = datetime.strptime(d['date'], '%Y-%m-%d').date()
    if booking_date < now.date():
        return jsonify({'error': 'Não é possível reservar em datas passadas'}), 400
    if booking_date == now.date():
        booking_start = datetime.strptime(d['start_time'], '%H:%M').time()
        if booking_start <= now.time():
            return jsonify({'error': 'Não é possível reservar horários que já passaram'}), 400
    if check_conflict(d['room_id'], d['date'], d['start_time'], d['end_time']):
        return jsonify({'error': 'Horário já reservado para esta sala'}), 409
    b = Booking(user_id=u.id, room_id=d['room_id'], date=d['date'],
                start_time=d['start_time'], end_time=d['end_time'],
                description=d.get('description', '').strip()[:200])
    db.session.add(b); db.session.commit()
    return jsonify(b.to_dict()), 201

@app.delete('/api/bookings/<int:bid>')
@jwt_required()
def cancel_booking(bid):
    u = current_user(); b = Booking.query.get_or_404(bid)
    if u.role != 'admin' and b.user_id != u.id:
        return jsonify({'error': 'Não autorizado'}), 403
    db.session.delete(b); db.session.commit()
    return jsonify({'message': 'Reserva cancelada'})

# ── Settings ──────────────────────────────────────────────────────────────────

@app.get('/api/settings')
def get_settings():
    sets = Setting.query.all()
    return jsonify({s.key: s.value for s in sets})

@app.post('/api/admin/settings')
@admin_required
def update_settings():
    d = request.get_json() or {}
    for k, v in d.items():
        s = db.session.get(Setting, k)
        if s:
            s.value = v
        else:
            s = Setting(key=k, value=v)
            db.session.add(s)
    db.session.commit()
    return jsonify({'message': 'Configurações salvas'})

# ── Admin Users ───────────────────────────────────────────────────────────────

@app.post('/api/admin/settings/test-email')
@admin_required
def test_email():
    if not MAIL_AVAILABLE:
        return jsonify({'error': 'flask-mail não instalado. Execute: pip install flask-mail'}), 400
    u = current_user()
    cfg = _get_mail_settings()
    if not cfg:
        return jsonify({'error': 'Configurações de e-mail não definidas'}), 400
    _apply_mail_config(cfg)
    try:
        msg = Message(
            subject='✅ Teste de e-mail — SpaceHub',
            recipients=[u.email],
            html=f'<p>Olá, <strong>{u.name}</strong>! As configurações de e-mail do SpaceHub estão funcionando corretamente.</p>'
        )
        mail.send(msg)
        return jsonify({'message': f'E-mail de teste enviado para {u.email}'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.get('/api/admin/email-templates')
@admin_required
def get_email_templates():
    keys = list(EMAIL_DEFAULTS.keys())
    result = {}
    for k in keys:
        s = db.session.get(Setting, k)
        result[k] = s.value if s else EMAIL_DEFAULTS[k]
    return jsonify(result)

@app.post('/api/admin/email-templates')
@admin_required
def save_email_templates():
    d = request.get_json() or {}
    for k in EMAIL_DEFAULTS.keys():
        if k in d:
            s = db.session.get(Setting, k)
            if s:
                s.value = d[k]
            else:
                db.session.add(Setting(key=k, value=d[k]))
    db.session.commit()
    return jsonify({'message': 'Templates salvos'})

@app.post('/api/admin/email-templates/reset')
@admin_required
def reset_email_templates():
    key = request.get_json().get('key') if request.get_json() else None
    keys = [key] if key and key in EMAIL_DEFAULTS else list(EMAIL_DEFAULTS.keys())
    for k in keys:
        s = db.session.get(Setting, k)
        if s:
            s.value = EMAIL_DEFAULTS[k]
        else:
            db.session.add(Setting(key=k, value=EMAIL_DEFAULTS[k]))
    db.session.commit()
    return jsonify({'message': 'Templates restaurados'})


@app.get('/api/admin/users')
@admin_required
def admin_list_users():
    return jsonify([u.to_dict() for u in User.query.order_by(User.created_at.desc()).all()])

@app.route('/api/admin/users/<string:uid>', methods=['PATCH', 'POST'])
@admin_required
def admin_update_user(uid):
    u = User.query.get_or_404(uid)
    d = request.get_json() or {}
    old_status = u.status
    if 'status' in d:
        u.status = str(d['status']).strip()
    if 'role' in d:
        new_role = str(d['role']).strip().lower()
        if new_role in ['admin', 'user']:
            u.role = new_role
    if 'password' in d and str(d['password']).strip():
        u.password_hash = generate_password_hash(str(d['password']).strip())
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    # Send email notification based on status change
    new_status = u.status
    if old_status != new_status:
        if new_status == 'approved':
            _email_account_approved(u)
        elif new_status == 'blocked':
            _email_account_blocked(u)
    return jsonify(u.to_dict())

@app.delete('/api/admin/users/<string:uid>')
@admin_required
def admin_delete_user(uid):
    u = User.query.get_or_404(uid)
    try:
        Booking.query.filter_by(user_id=uid).delete()
        db.session.delete(u)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    return jsonify({'message': 'Usuário removido'})

# ── Setup (first-run) ────────────────────────────────────────────────────────

@app.get('/api/auth/setup-status')
def setup_status():
    """Returns whether the app still needs its first admin to be created."""
    needs_setup = not User.query.filter_by(role='admin').first()
    return jsonify({'needs_setup': needs_setup})

@app.post('/api/auth/setup')
def setup():
    """Creates the first administrator. Only works when no admin exists yet."""
    if User.query.filter_by(role='admin').first():
        return jsonify({'error': 'Configuração inicial já foi realizada'}), 403
    d = request.get_json() or {}
    name = str(d.get('name', '')).strip()
    email = str(d.get('email', '')).lower().strip()
    password = str(d.get('password', ''))
    if not name or not email or not password:
        return jsonify({'error': 'Nome, e-mail e senha são obrigatórios'}), 400
    safe_email = re.compile(r'^[A-Za-z0-9.@_\-+]+$')
    if not safe_email.match(email):
        return jsonify({'error': 'E-mail não pode conter acentos ou caracteres especiais'}), 400
    if len(password) < 8:
        return jsonify({'error': 'A senha deve ter no mínimo 8 caracteres'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'E-mail já cadastrado'}), 409
    admin = User(name=name, email=email,
                 password_hash=generate_password_hash(password),
                 role='admin', status='approved', department='')
    db.session.add(admin)
    db.session.commit()
    token = create_access_token(identity=admin.id)
    return jsonify({'message': 'Administrador criado com sucesso', 'token': token, 'user': admin.to_dict()}), 201

# ── Init ──────────────────────────────────────────────────────────────────────

def seed():
    if not db.session.get(Setting, 'allowed_domains'):
        db.session.add(Setting(key='allowed_domains', value=json.dumps([])))
    for key in ('mail_server', 'mail_port', 'mail_username', 'mail_password', 'mail_from_name'):
        if not db.session.get(Setting, key):
            defaults = {'mail_server': 'smtp.gmail.com', 'mail_port': '587', 'mail_from_name': 'SpaceHub'}
            db.session.add(Setting(key=key, value=defaults.get(key, '')))
    for key, value in EMAIL_DEFAULTS.items():
        if not db.session.get(Setting, key):
            db.session.add(Setting(key=key, value=value))
    db.session.commit()

with app.app_context():
    db.create_all()
    seed()
    _start_reminder_scheduler()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)