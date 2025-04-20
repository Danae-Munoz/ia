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

class SesionVisual(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(64), nullable=False, unique=True)
    identificador = db.Column(db.String(50), nullable=False)

with app.app_context():
    db.create_all()

def limpiar(texto):
    return re.sub(r'[\x00-\x1f]+', '', texto).strip()

@app.route('/')
def index():
    sesiones = db.session.query(SesionVisual.session_id, SesionVisual.identificador).all()
    return render_template('index.html', sesiones=sesiones)

@app.route('/chat/<session_id>')
def chat(session_id):
    mensajes = Conversacion.query.filter_by(session_id=session_id).order_by(Conversacion.timestamp).all()
    sesion_visual = SesionVisual.query.filter_by(session_id=session_id).first()
    identificador = sesion_visual.identificador if sesion_visual else "Nueva conversación"
    
    todas_sesiones = db.session.query(
        SesionVisual.session_id, 
        SesionVisual.identificador
    ).all()
    
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
def eliminar_conversacion(session_id):
    session_id_actual = request.form.get("session_id_actual")

    # Verificar si existe la conversación antes de eliminar
    existe_conversacion = Conversacion.query.filter_by(session_id=session_id).first()
    existe_sesion_visual = SesionVisual.query.filter_by(session_id=session_id).first()

    if existe_conversacion or existe_sesion_visual:
        # Eliminar todos los mensajes y el registro visual si existen
        Conversacion.query.filter_by(session_id=session_id).delete()
        SesionVisual.query.filter_by(session_id=session_id).delete()
        db.session.commit()

    # Redirigir al index si estamos eliminando la sesión actual
    if session_id == session_id_actual:
        return redirect(url_for('/chat/'))
    
    # Redirigir a la sesión actual si es diferente
    if session_id_actual:
        return redirect(url_for('chat', session_id=session_id_actual))
    
    # Por defecto redirigir al index
    return redirect(url_for('/chat/'))

@app.route('/chat/<session_id>', methods=['POST'])
def responder(session_id):
    data = request.get_json()
    mensaje_usuario = data.get('message')
    if not mensaje_usuario:
        return jsonify({"error": "Mensaje vacío"}), 400

    # Verificar si es el primer mensaje de esta sesión
    primer_mensaje = not Conversacion.query.filter_by(session_id=session_id).first()
    
    db.session.add(Conversacion(session_id=session_id, role='user', content=mensaje_usuario))
    
    if primer_mensaje:
        # Extraer primera palabra o primeras 3 palabras como identificador
        identificador = ' '.join(mensaje_usuario.split()[:3])
        if len(identificador) > 30:  # Limitar longitud
            identificador = identificador[:27] + "..."
        db.session.add(SesionVisual(session_id=session_id, identificador=identificador))
    
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

@app.route('/eliminar_todo', methods=['POST'])
def eliminar_todo():
    Conversacion.query.delete()
    SesionVisual.query.delete()
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/api/sesiones')
def api_sesiones():
    sesiones = db.session.query(SesionVisual.session_id, SesionVisual.identificador).all()
    return jsonify([{"id": s.session_id, "name": s.identificador} for s in sesiones])

if __name__ == '__main__':
    app.run(debug=True)