# SpaceHub — Sistema de Reserva de Salas

## Estrutura do Projeto

```
spacehub/
├── backend/
│   ├── app.py           ← API Flask (todas as rotas)
│   └── requirements.txt ← Dependências Python
└── frontend/
    └── index.html       ← SPA completo (sem build necessário)
```

## Como Rodar

### 1. Backend (Flask)

```bash
cd backend

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate          # Windows

# Instalar dependências
pip install -r requirements.txt

# Iniciar servidor
python app.py
# → Rodando em http://localhost:5000
```

### 2. Frontend

Abra `frontend/index.html` diretamente no navegador.

> **Nota:** Para o frontend se comunicar com o backend, ambos precisam estar rodando ao mesmo tempo. O frontend aponta para `http://localhost:5000`.

## Credenciais de Teste

| Papel         | Email               | Senha     |
|--------------|---------------------|-----------|
| Administrador | admin@empresa.com   | admin123  |

## Funcionalidades

### Usuário Comum
- Auto-cadastro (aguarda aprovação)
- Visualiza salas disponíveis em cards
- Reserva em 3 passos: data → horário → confirmação
- Cancela reservas futuras
- Perfil com lista de agendamentos

### Administrador
- Aprova / bloqueia usuários
- Cria e edita salas (nome, capacidade, recursos, status)
- Coloca sala em manutenção
- Visão master de todas as reservas por data

## API Endpoints

### Auth
- `POST /api/auth/register` — Cadastro
- `POST /api/auth/login` — Login → retorna JWT
- `GET  /api/auth/me` — Dados do usuário logado

### Salas
- `GET    /api/rooms` — Listar salas
- `POST   /api/rooms` — Criar (admin)
- `PATCH  /api/rooms/:id` — Editar (admin)
- `DELETE /api/rooms/:id` — Remover (admin)

### Reservas
- `GET    /api/bookings` — Minhas reservas (admin vê todas)
- `GET    /api/bookings/room/:id?date=YYYY-MM-DD` — Reservas de uma sala
- `POST   /api/bookings` — Criar reserva
- `DELETE /api/bookings/:id` — Cancelar reserva

### Admin
- `GET    /api/admin/users` — Listar todos os usuários
- `PATCH  /api/admin/users/:id` — Alterar status/role
- `DELETE /api/admin/users/:id` — Remover usuário

## Banco de Dados

SQLite com modo WAL ativado. Seed automático cria:
- 1 usuário admin
- 4 salas de exemplo

O arquivo `spacehub.db` é criado automaticamente na pasta `backend/` na primeira execução.

## Segurança
- Senhas com hash Werkzeug (PBKDF2-SHA256)
- Autenticação JWT com expiração de 8h
- Proteção anti-SQL Injection via SQLAlchemy ORM
- Verificação de conflito de horário no servidor
- Middleware `admin_required` em todas as rotas administrativas
