from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import Response, stream_with_context
from datetime import datetime
import ollama
import os
import uuid
import re

app = Flask(__name__)

# Base de datos en carpeta instance (seguro para Flask)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Conversacion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

def limpiar(texto):
    return re.sub(r'[\x00-\x1f]+', '', texto).strip()

@app.route('/')
def index():
    sesiones = db.session.query(Conversacion.session_id).distinct().all()
    sesiones = [s[0] for s in sesiones]
    return render_template('index.html', sesiones=sesiones)


@app.route('/chat/<session_id>')
def chat(session_id):
    mensajes = Conversacion.query.filter_by(session_id=session_id).order_by(Conversacion.timestamp).all()
    sesiones = db.session.query(Conversacion.session_id).distinct().all()
    sesiones = [s[0] for s in sesiones]
    return render_template('chat.html', mensajes=mensajes, session_id=session_id, sesiones=sesiones)


@app.route('/new')
def nueva():
    nueva_id = str(uuid.uuid4())
    return redirect(url_for('chat', session_id=nueva_id))



@app.route('/eliminar/<session_id>', methods=['POST'])
def eliminar_conversacion(session_id):
    # Eliminar todas las entradas de la conversación con este session_id
    Conversacion.query.filter_by(session_id=session_id).delete()
    db.session.commit()
    
    # Redirigir a la página del chat, no al index
    return redirect(url_for('chat', session_id=session_id))



@app.route('/chat/<session_id>', methods=['POST'])
def responder(session_id):
    data = request.get_json()
    mensaje_usuario = data.get('message')
    if not mensaje_usuario:
        return jsonify({"error": "Mensaje vacío"}), 400

    db.session.add(Conversacion(session_id=session_id, role='user', content=mensaje_usuario))
    db.session.commit()

    historial = [{"role": "system", "content": "Responde de forma breve, clara y coherente. Usa pocas palabras y se rapido."}]
    anteriores = Conversacion.query.filter_by(session_id=session_id).order_by(Conversacion.timestamp).all()
    for m in anteriores:
        historial.append({"role": m.role, "content": m.content})

    try:
        respuesta = ollama.chat(model="phi3:instruct", messages=historial)
        contenido = limpiar(respuesta['message']['content'])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    db.session.add(Conversacion(session_id=session_id, role='assistant', content=contenido))
    db.session.commit()

    return jsonify({"response": contenido})

if __name__ == '__main__':
    app.run(debug=True)
