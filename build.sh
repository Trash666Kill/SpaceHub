apt-get install unzip python3 python3-pip python3-venv
apt update
apt install -y postgresql postgresql-contrib
systemctl enable --now postgresql
systemctl status postgresql
#
sudo -u postgres psql

-- Cria o usuário com senha
CREATE USER spacehub WITH PASSWORD 'troque_esta_senha';

-- Cria o banco com esse usuário como dono
CREATE DATABASE spacehub OWNER spacehub ENCODING 'UTF8';

-- Garante todos os privilégios no banco
GRANT ALL PRIVILEGES ON DATABASE spacehub TO spacehub;

-- (PostgreSQL 15+) também precisa dar permissão no schema public
\c spacehub
GRANT ALL ON SCHEMA public TO spacehub;

-- Sair
\q