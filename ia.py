from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Response, stream_with_context
from datetime import datetime
from rag_utils import retrieve_context
from flask import request
from rag_utils import ingest_document
import requests
import ollama
import os
import uuid
import re

app = Flask(__name__)

#  justo después de crear la app:
app.secret_key = 'nanegonza'  # cualquier texto aquí

# Base de datos en carpeta instance (seguro para Flask)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


class Conversacion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=True)

class SesionVisual(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), nullable=False, unique=True)
    identificador = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    usuario = db.relationship('Usuario', backref='sesiones')

class Usuario(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


with app.app_context():
    db.create_all()

def limpiar(texto):
    return re.sub(r'[\x00-\x1f]+', '', texto).strip()

@app.route('/')
@login_required
def index():
    sesiones = SesionVisual.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', sesiones=sesiones)


@app.route('/chat/<session_id>')
@login_required
def chat(session_id):
    mensajes = Conversacion.query.filter_by(session_id=session_id, user_id=current_user.id).order_by(Conversacion.timestamp).all()
    sesion_visual = SesionVisual.query.filter_by(session_id=session_id, user_id=current_user.id).first()
    identificador = sesion_visual.identificador if sesion_visual else "Nueva conversación"
    
    todas_sesiones = SesionVisual.query.filter_by(user_id=current_user.id).all()
    
    return render_template('chat.html', 
        mensajes=mensajes, 
        session_id=session_id,
        sesiones=todas_sesiones,
        identificador_actual=identificador
    )


@app.route('/new')
def nueva():
    nueva_id = str(uuid.uuid4())
    return redirect(url_for('chat', session_id=nueva_id))

@app.route('/eliminar/<session_id>', methods=['POST'])
@login_required
def eliminar_conversacion(session_id):
    session_id_actual = request.form.get("session_id_actual")

    # el usuario sea el dueño
    Conversacion.query.filter_by(session_id=session_id, user_id=current_user.id).delete()
    SesionVisual.query.filter_by(session_id=session_id, user_id=current_user.id).delete()
    db.session.commit()

    if session_id == session_id_actual:
        return redirect(url_for('index'))
    if session_id_actual:
        return redirect(url_for('chat', session_id=session_id_actual))
    return redirect(url_for('index'))


@app.route('/chat/<session_id>', methods=['POST'])
@login_required
def responder(session_id):
    data = request.get_json()
    mensaje_usuario = data.get('message')
    if not mensaje_usuario:
        return jsonify({"error": "Mensaje vacío"}), 400

    primer_mensaje = not Conversacion.query.filter_by(session_id=session_id, user_id=current_user.id).first()

    db.session.add(Conversacion(
        session_id=session_id,
        role='user',
        content=mensaje_usuario,
        user_id=current_user.id  #  Esto es nuevo
    ))

    if primer_mensaje:
        identificador = ' '.join(mensaje_usuario.split()[:3])
        if len(identificador) > 30:
            identificador = identificador[:27] + "..."
        db.session.add(SesionVisual(
            session_id=session_id,
            identificador=identificador,
            user_id=current_user.id  # Esto también es nuevo
        ))

    db.session.commit()

    historial = [{"role": "system", "content": "Responde de forma breve, clara y coherente. Usa pocas palabras y se rapido."}]# cantidad de tokens
    anteriores = Conversacion.query.filter_by(session_id=session_id, user_id=current_user.id).order_by(Conversacion.timestamp).all()
    for m in anteriores:
        historial.append({"role": m.role, "content": m.content})

    try:
        respuesta = ollama.chat(model="phi3:instruct", messages=historial)
        contenido = limpiar(respuesta['message']['content'])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    db.session.add(Conversacion(
        session_id=session_id,
        role='assistant',
        content=contenido,
        user_id=current_user.id  # 👈 Muy importante
    ))
    db.session.commit()

    return jsonify({"response": contenido})


@app.route('/eliminar_todo', methods=['POST'])
def eliminar_todo():
    Conversacion.query.delete()
    SesionVisual.query.delete()
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/api/sesiones')
@login_required
def api_sesiones():
    sesiones = SesionVisual.query.filter_by(user_id=current_user.id).all()
    return jsonify([{"id": s.session_id, "name": s.identificador} for s in sesiones])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if Usuario.query.filter_by(username=username).first():
            return "Usuario ya existe", 400
        user = Usuario(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Usuario.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        return "Usuario o contraseña incorrectos", 400
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def generate_answer(prompt):
    context = retrieve_context(prompt)
    full_prompt = f"Contexto:\n{context}\n\nPregunta: {prompt}"

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "phi3:instruct", "prompt": full_prompt}
    )
    return response.json()['response']

@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.json
    print("Datos recibidos:", data)
    return jsonify({"status": "OK"})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, ssl_context='adhoc')

