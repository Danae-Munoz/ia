from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Response, stream_with_context
from datetime import datetime
from light_rag.light_rag import LightRAG
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
# Inicializa LightRAG una sola vez al inicio
light_rag = LightRAG(docs_folder='light_rag/documents')

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

    # Verifica si es el primer mensaje de la sesión
    primer_mensaje = not Conversacion.query.filter_by(session_id=session_id, user_id=current_user.id).first()

    # Guarda el mensaje del usuario
    db.session.add(Conversacion(
        session_id=session_id,
        role='user',
        content=mensaje_usuario,
        user_id=current_user.id
    ))

    # Si es el primer mensaje, crea la sesión visual
    if primer_mensaje:
        identificador = ' '.join(mensaje_usuario.split()[:3])
        if len(identificador) > 30:
            identificador = identificador[:27] + "..."
        db.session.add(SesionVisual(
            session_id=session_id,
            identificador=identificador,
            user_id=current_user.id
        ))

    db.session.commit()

    # Obtener contexto relevante
    contexto = light_rag.get_relevant_context(mensaje_usuario, top_k=5)

    # Verificar si hay contexto
    tiene_contexto = bool(contexto and contexto.strip())

    if tiene_contexto:
        # Construir prompt con contexto
        prompt = f"""
Eres un asistente amigable y cercano que conversa con un adulto mayor para hacer su vida más alegre y divertida.
Usa un lenguaje claro, respetuoso y cálido.
Responde de manera breve, con oraciones cortas y directas.
Usa un lenguaje simple y evita extenderte demasiado.
Utiliza el siguiente contexto para responder de forma útil y amable:

Contexto relevante:
{contexto}

Pregunta del adulto mayor:
{mensaje_usuario}

Responde como un amigo que se preocupa por su bienestar y felicidad.
"""
    else:
        # Prompt sin contexto
        prompt = f"""
Eres un asistente amigable y cercano que conversa con un adulto mayor para hacer su vida más alegre y divertida.
No encontraste información útil en los documentos.
Responde de la mejor manera posible usando tu conocimiento general.

Pregunta del adulto mayor:
{mensaje_usuario}

Responde como un amigo que se preocupa por su bienestar y felicidad.
"""

    historial = [
        {"role": "system", "content": "Eres un asistente virtual empático y amigable."},
        {"role": "user", "content": prompt}
    ]

    try:
        respuesta = ollama.chat(model="phi3:instruct", messages=historial)
        contenido = limpiar(respuesta['message']['content'])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Guardar la respuesta del asistente
    db.session.add(Conversacion(
        session_id=session_id,
        role='assistant',
        content=contenido,
        user_id=current_user.id
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


if __name__ == '__main__':
    app.run(debug=True)