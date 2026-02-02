# .\venv\Scripts\activate
# cd "C:\Users\leona\Automação\agenda_flask"
# python agenda_chromes.py

from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
import json
import uuid
from models import db, User, Horario

# ------------------------
# CONFIGURAÇÃO INICIAL
# ------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'segredo_super_seguro'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///agenda.db'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------
# ROTAS
# ------------------------

@app.route("/")
def home():
    return redirect(url_for("login"))

# Cadastro
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Captura os dados do formulário
        usuario = request.form.get("usuario", "").strip().lower()
        nome = request.form.get("nome", "").strip()
        senha = request.form.get("senha", "")

        # Monta o email com sufixo fixo
        email = usuario + "@edu.joinville.sc.gov.br"

        # Validações básicas
        if not usuario or not nome or not senha:
            flash("Todos os campos são obrigatórios.", "warning")
            return redirect(url_for("register"))

        if len(senha) < 4:
            flash("A senha deve ter pelo menos 4 dígitos.", "warning")
            return redirect(url_for("register"))

        # Verifica se já existe usuário com esse e-mail
        if User.query.filter_by(email=email).first():
            flash("E-mail já cadastrado!", "danger")
            return redirect(url_for("register"))

        # Cria novo usuário com senha protegida
        senha_hash = generate_password_hash(senha)
        novo_user = User(nome=nome, email=email, senha_hash=senha_hash)
        db.session.add(novo_user)
        db.session.commit()

        flash("Cadastro realizado com sucesso!", "success")
        return redirect(url_for("login"))

    # GET → renderiza o formulário
    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Captura os dados do formulário
        usuario = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")

        # Monta o email com sufixo fixo
        email = usuario + "@edu.joinville.sc.gov.br"

        # Busca usuário pelo e-mail
        user = User.query.filter_by(email=email).first()

        # Valida usuário e senha
        if user and check_password_hash(user.senha_hash, senha):
            login_user(user)
            flash("Login realizado com sucesso!", "success")
            return redirect(url_for("calendar"))  # ou outra rota inicial

        flash("E-mail ou senha inválidos.", "danger")
        return redirect(url_for("login"))

    # GET → renderiza o formulário
    return render_template("login.html")

# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout realizado com sucesso!", "info")
    return redirect(url_for("login"))

# ------------------------
# Rota Agenda (usuário comum)
# ------------------------
@app.route("/agenda")
@login_required
def agenda():
    data_str = request.args.get("data")
    try:
        if data_str:
            data = datetime.strptime(data_str, "%Y-%m-%d").date()
        else:
            data = datetime.today().date()
    except ValueError:
        flash("Data inválida.", "danger")
        return redirect(url_for("calendar"))

    horarios = Horario.query.filter_by(data=data).all()
    return render_template("agenda.html", horarios=horarios, data=data, timedelta=timedelta)


# ------------------------
# Rota Admin
# ------------------------
@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for("agenda"))

    data_str = request.args.get("data")
    try:
        if data_str:
            data = datetime.strptime(data_str, "%Y-%m-%d").date()
        else:
            data = datetime.today().date()
    except ValueError:
        flash("Data inválida.", "danger")
        return redirect(url_for("calendar"))

    horarios = Horario.query.filter_by(data=data).all()
    return render_template("admin.html", horarios=horarios, data=data, timedelta=timedelta)

@app.route("/admin/usuarios", methods=["GET", "POST"])
@login_required
def gerenciar_usuarios():
    if not current_user.is_admin:
        flash("Acesso negado.", "danger")
        return redirect(url_for("calendar"))

    if request.method == "POST":
        user_id = request.form.get("user_id")
        nova_senha = request.form.get("nova_senha")

        usuario = User.query.get(user_id)
        if usuario and nova_senha:
            usuario.senha_hash = generate_password_hash(nova_senha)
            db.session.commit()
            flash(f"Senha do usuário {usuario.nome} atualizada com sucesso!", "success")
        else:
            flash("Erro ao atualizar senha.", "danger")

        return redirect(url_for("calendar"))

    usuarios = User.query.all()
    return render_template("usuarios_admin.html", usuarios=usuarios)

# ------------------------
# Agendar (usuário comum)
# ------------------------
@app.route("/agendar/<int:id>", methods=["POST"])
@login_required
def agendar(id):
    horario = Horario.query.get_or_404(id)

    if horario.user_id or horario.bloqueado:
        flash("Horário indisponível", "danger")
        return redirect(url_for("agenda", data=horario.data.strftime("%Y-%m-%d")))

    turma = request.form.get("turma", "").strip()
    if not turma:
        flash("A turma é obrigatória para agendar.", "danger")
        return redirect(url_for("agenda", data=horario.data.strftime("%Y-%m-%d")))

    horario.user_id = current_user.id
    horario.nome = current_user.nome if hasattr(current_user, "nome") else None
    horario.turma = turma

    db.session.commit()
    flash("Agendamento realizado com sucesso!", "success")
    return redirect(url_for("agenda", data=horario.data.strftime("%Y-%m-%d")))


# ------------------------
# Agendar (admin)
# ------------------------
@app.route("/agendar_admin/<int:id>", methods=["POST"])
@login_required
def agendar_admin(id):
    if not current_user.is_admin:
        return redirect(url_for("agenda"))

    horario = Horario.query.get_or_404(id)

    if horario.user_id or horario.bloqueado:
        flash("Horário indisponível", "danger")
        return redirect(url_for("admin", data=horario.data.strftime("%Y-%m-%d")))

    nome = request.form.get("nome", "").strip()
    turma = request.form.get("turma", "").strip()

    if not nome or not turma:
        flash("Nome e Turma são obrigatórios para agendar.", "danger")
        return redirect(url_for("admin", data=horario.data.strftime("%Y-%m-%d")))

    horario.user_id = None
    horario.nome = nome
    horario.turma = turma

    db.session.commit()

    flash("Agendamento realizado com sucesso!", "success")
    return redirect(url_for("admin", data=horario.data.strftime("%Y-%m-%d")))
# ------------------------
# Cancelar (usuário comum e admin)
# ------------------------
@app.route("/cancelar/<int:id>", methods=["POST"])
@login_required
def cancelar(id):
    horario = Horario.query.get_or_404(id)

    # Admin pode cancelar qualquer reserva
    if current_user.is_admin:
        if horario.user_id or horario.nome or horario.turma:
            horario.user_id = None
            horario.nome = None
            horario.turma = None
            db.session.commit()
            flash("Agendamento cancelado com sucesso!", "warning")
        return redirect(url_for("admin", data=request.args.get("data")))

    # Usuário comum só cancela a própria reserva
    if horario.user_id == current_user.id:
        horario.user_id = None
        horario.nome = None
        horario.turma = None
        db.session.commit()
        flash("Seu agendamento foi cancelado.", "warning")
    else:
        flash("Você não tem permissão para cancelar esta reserva.", "danger")

    return redirect(url_for("agenda", data=request.args.get("data")))

# Calendário
@app.route("/calendar")
@login_required
def calendar():
    bloqueados = db.session.query(Horario.data).filter_by(bloqueado=True).distinct().all()
    bloqueados = [b[0].strftime("%Y-%m-%d") for b in bloqueados]

    agendados = db.session.query(Horario.data).filter(Horario.user_id.isnot(None)).distinct().all()
    agendados = [a[0].strftime("%Y-%m-%d") for a in agendados]

    eventos = []
    for dia in bloqueados:
        eventos.append({
            "start": dia,
            "display": "background",
            "backgroundColor": "#555555"
        })

    for dia in agendados:
        eventos.append({
            "start": dia,
            "display": "background",
            "backgroundColor": "#ff69b4"
        })

    return render_template("calendar.html", eventos=json.dumps(eventos))

@app.route('/alterar_senha', methods=['GET', 'POST'])
@login_required
def alterar_senha():
    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirmar_senha')

        # 1. Verificar senha atual usando método do modelo
        if not current_user.check_password(senha_atual):
            flash('Senha atual incorreta.', 'danger')
            return redirect(url_for('alterar_senha'))

        # 2. Verificar confirmação
        if nova_senha != confirmar_senha:
            flash('A nova senha e a confirmação não coincidem.', 'warning')
            return redirect(url_for('alterar_senha'))

        # 3. Atualizar senha usando método do modelo
        current_user.set_password(nova_senha)
        db.session.commit()

        flash('Senha alterada com sucesso!', 'success')
        return redirect(url_for('calendar'))

    return render_template('alterar_senha.html')

# Bloquear dia
@app.route("/bloquear_data", methods=["POST"])
@login_required
def bloquear_data():
    if current_user.is_admin:
        data_str = request.form.get("data")
        if data_str:
            dia = datetime.strptime(data_str, "%Y-%m-%d").date()
            slots = Horario.query.filter_by(data=dia).all()
            for s in slots:
                s.bloqueado = True
            db.session.commit()
            flash(f"Dia {dia.strftime('%d/%m/%Y')} bloqueado com sucesso!", "success")
    return redirect(url_for("calendar"))

# Desbloquear dia
@app.route("/desbloquear_data", methods=["POST"])
@login_required
def desbloquear_data():
    if current_user.is_admin:
        data_str = request.form.get("data")
        if data_str:
            dia = datetime.strptime(data_str, "%Y-%m-%d").date()
            slots = Horario.query.filter_by(data=dia).all()
            for s in slots:
                s.bloqueado = False
            db.session.commit()
            flash(f"Dia {dia.strftime('%d/%m/%Y')} desbloqueado com sucesso!", "info")
    return redirect(url_for("admin", data=data_str))

# ------------------------
# Função para gerar slots
# ------------------------
def gerar_agenda_2026():
    inicio = date(2026, 1, 1)
    fim = date(2026, 12, 31)
    periodos = ["Matutino", "Vespertino"]
    pisos = ["Superior", "Inferior"]

    dia = inicio
    while dia <= fim:
        if dia.weekday() < 5:
            if Horario.query.filter_by(data=dia).count() == 0:
                for periodo in periodos:
                    for aula in range(1, 6):
                        for piso in pisos:
                            for vaga in range(1, 3):
                                slot = Horario(data=dia, periodo=periodo, aula=aula, piso=piso, vaga=vaga)
                                db.session.add(slot)
        dia += timedelta(days=1)
    db.session.commit()

# ------------------------
# MAIN
# ------------------------
if __name__ == "__main__":
    with app.app_context():
        # Cria as tabelas se não existirem
        db.create_all()

        # Gera todos os horários de 2026 (somente dias úteis)
        gerar_agenda_2026()

        # Criar usuário master se não existir
        if not User.query.filter_by(email="franciele.tartari@edu.joinville.sc.gov.br").first():
            master = User(
                nome="Administrador",
                email="franciele.tartari@edu.joinville.sc.gov.br",
                senha_hash=generate_password_hash("Leonardo84"),
                is_admin=True
            )
            db.session.add(master)
            db.session.commit()

    # Inicia a aplicação
    if __name__ == "__main__":
        with app.app_context():
            db.create_all()
            gerar_agenda_2026()

        app.run(host="0.0.0.0", port=5000)