from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# ------------------------
# Modelo de Usuário
# ------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # Relação com horários agendados (cria horario.user automaticamente)
    horarios = db.relationship("Horario", backref="user", lazy=True)

    def set_password(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def check_password(self, senha):
        return check_password_hash(self.senha_hash, senha)

    def __repr__(self):
        return f"<User {self.nome} - {self.email}>"

# ------------------------
# Modelo de Horário
# ------------------------
class Horario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Date, nullable=False)
    periodo = db.Column(db.String(20), nullable=False)   # Matutino, Vespertino
    piso = db.Column(db.String(20), nullable=False)      # Superior, Inferior
    aula = db.Column(db.Integer, nullable=False)         # Número da aula
    vaga = db.Column(db.Integer, nullable=False)         # Carrinho Chrome 1 ou 2

    # Quando um usuário comum agenda
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Campos livres para admin ou exibição
    nome = db.Column(db.String(100), nullable=True)      # Nome digitado pelo admin
    turma = db.Column(db.String(50), nullable=True)      # Turma informada

    # Controle de bloqueio
    bloqueado = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Horario {self.data} {self.periodo} {self.piso} Aula {self.aula} Vaga {self.vaga}>"