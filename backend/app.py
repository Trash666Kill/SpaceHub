from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid, json, os, re

app = Flask(__name__)
CORS(app, origins="*")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///spacehub.db'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'check_same_thread': False}}
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'dev-secret-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)

db = SQLAlchemy(app)
jwt = JWTManager(app)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='bookings')
    room = db.relationship('Room', backref='bookings')

    def to_dict(self):
        return {'id': self.id, 'user_id': self.user_id, 'user_name': self.user.name if self.user else None,
                'room_id': self.room_id, 'room_name': self.room.name if self.room else None,
                'date': self.date, 'start_time': self.start_time, 'end_time': self.end_time,
                'description': self.description or '',
                'created_at': self.created_at.isoformat()}

# ── Helpers ───────────────────────────────────────────────────────────────────

def check_conflict(room_id, date, start_time, end_time, exclude_id=None):
    q = Booking.query.filter_by(room_id=room_id, date=date)
    if exclude_id: q = q.filter(Booking.id != exclude_id)
    return any(start_time < b.end_time and end_time > b.start_time for b in q.all())

def current_user():
    return User.query.get(get_jwt_identity())

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
    setting = Setting.query.get('allowed_domains')
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
    r = Room.query.get(d['room_id'])
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
        s = Setting.query.get(k)
        if s:
            s.value = v
        else:
            s = Setting(key=k, value=v)
            db.session.add(s)
    db.session.commit()
    return jsonify({'message': 'Configurações salvas'})

# ── Admin Users ───────────────────────────────────────────────────────────────

@app.get('/api/admin/users')
@admin_required
def admin_list_users():
    return jsonify([u.to_dict() for u in User.query.order_by(User.created_at.desc()).all()])

@app.route('/api/admin/users/<string:uid>', methods=['PATCH', 'POST'])
@admin_required
def admin_update_user(uid):
    u = User.query.get_or_404(uid)
    d = request.get_json() or {}
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

# ── Init ──────────────────────────────────────────────────────────────────────

def seed():
    if not User.query.count():
        db.session.add(User(name='Administrador', email='admin@empresa.com',
                            password_hash=generate_password_hash('admin123'),
                            role='admin', status='approved'))
    if not Setting.query.get('allowed_domains'):
        db.session.add(Setting(key='allowed_domains', value=json.dumps(['sugisawa.com.br'])))
    db.session.commit()

with app.app_context():
    db.create_all()
    seed()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)