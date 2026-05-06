#!/usr/bin/env python3
"""
Sistema de Evaluaciones de Salida — FYRESA
Backend Flask + SQLite
"""

import sqlite3
import os
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'evaluaciones.db')
FRONTEND_DIR = os.path.join(BASE_DIR, '..', 'frontend', 'public')
JWT_SECRET = os.environ.get('JWT_SECRET', 'fyresa_evaluaciones_secret_2026')

app = Flask(__name__, static_folder=FRONTEND_DIR)
CORS(app)

# ─── DB helpers ───────────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    return db

def query(sql, params=(), one=False):
    db = get_db()
    cur = db.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    return rows[0] if (one and rows) else (None if one else rows)

def execute(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    last_id = cur.lastrowid
    db.close()
    return last_id

# ─── JWT simple ───────────────────────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256((pw + JWT_SECRET).encode()).hexdigest()

def create_token(user):
    payload = {
        'id': user['id'],
        'nombre': user['nombre'],
        'email': user['email'],
        'rol': user['rol'],
        'exp': int(time.time()) + 28800  # 8 horas
    }
    import base64
    data = base64.b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(JWT_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
    return f"{data}.{sig}"

def verify_token(token):
    try:
        import base64
        parts = token.split('.')
        if len(parts) != 2:
            return None
        data, sig = parts
        expected = hmac.new(JWT_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.b64decode(data).decode())
        if payload.get('exp', 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'No autorizado'}), 401
        user = verify_token(auth[7:])
        if not user:
            return jsonify({'error': 'Token inválido'}), 401
        request.current_user = user
        return f(*args, **kwargs)
    return decorated

def require_rol(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if request.current_user.get('rol') not in roles:
                return jsonify({'error': 'Sin permisos'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─── Init DB ──────────────────────────────────────────────────────────────────
def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            rol TEXT NOT NULL CHECK(rol IN ('supervisor','superintendente','coord_construccion','coord_rrhh','admin')),
            activo INTEGER DEFAULT 1,
            creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS empleados_baja (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            folio INTEGER UNIQUE NOT NULL,
            nombre TEXT NOT NULL,
            numero_empleado TEXT NOT NULL DEFAULT '',
            cargo TEXT NOT NULL,
            departamento TEXT DEFAULT '',
            fecha_baja DATE NOT NULL,
            motivo TEXT NOT NULL,
            clasificacion TEXT NOT NULL CHECK(clasificacion IN ('A','B','C')),
            comentarios TEXT DEFAULT '',
            fortalezas TEXT DEFAULT '',
            areas_mejora TEXT DEFAULT '',
            recomendaria INTEGER DEFAULT 0,
            supervisor_id INTEGER NOT NULL,
            estatus TEXT DEFAULT 'pendiente' CHECK(estatus IN ('pendiente','en_proceso','autorizado','rechazado')),
            creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(supervisor_id) REFERENCES usuarios(id)
        );

        CREATE TABLE IF NOT EXISTS autorizaciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evaluacion_id INTEGER NOT NULL,
            rol TEXT NOT NULL CHECK(rol IN ('superintendente','coord_construccion','coord_rrhh')),
            usuario_id INTEGER,
            decision TEXT CHECK(decision IN ('autorizado','rechazado')),
            comentario TEXT DEFAULT '',
            firma TEXT DEFAULT '',
            fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(evaluacion_id) REFERENCES empleados_baja(id),
            FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
        );

        CREATE TABLE IF NOT EXISTS criterios_clasificacion (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            clasificacion TEXT NOT NULL CHECK(clasificacion IN ('A','B','C')),
            criterio TEXT NOT NULL,
            descripcion TEXT DEFAULT '',
            activo INTEGER DEFAULT 1
        );
    """)
    db.commit()

    # Migración: agregar columna firma si no existe (para bases de datos existentes)
    try:
        db.execute("ALTER TABLE autorizaciones ADD COLUMN firma TEXT DEFAULT ''")
        db.commit()
    except Exception:
        pass  # Ya existe la columna

    # Datos iniciales si no existen
    existing = db.execute("SELECT id FROM usuarios WHERE email='admin@fyresa.com'").fetchone()
    if not existing:
        pw = hash_password('fyresa2026')
        users = [
            ('Administrador', 'admin@fyresa.com', pw, 'admin'),
            ('Supervisor RRHH', 'supervisor@fyresa.com', pw, 'supervisor'),
            ('Ing. García Superintendente', 'superintendente@fyresa.com', pw, 'superintendente'),
            ('Coord. Construcción López', 'coord.construccion@fyresa.com', pw, 'coord_construccion'),
            ('Coord. RRHH Martínez', 'coord.rrhh@fyresa.com', pw, 'coord_rrhh'),
        ]
        for u in users:
            db.execute("INSERT INTO usuarios (nombre,email,password,rol) VALUES (?,?,?,?)", u)
        db.commit()

        criterios = [
            ('A','Desempeño sobresaliente','Supera constantemente los objetivos y metas establecidas'),
            ('A','Liderazgo natural','Inspira y motiva a sus compañeros, toma la iniciativa'),
            ('A','Actitud excepcional','Actitud positiva, proactiva y orientada a resultados'),
            ('B','Desempeño regular','Cumple con los objetivos básicos establecidos sin destacar'),
            ('B','Trabajo en equipo','Colabora adecuadamente con el equipo de trabajo'),
            ('B','Puntualidad aceptable','Generalmente puntual con pocas ausencias justificadas'),
            ('C','Bajo desempeño','No alcanza los objetivos mínimos establecidos de manera consistente'),
            ('C','Problemas disciplinarios','Incidentes de comportamiento o incumplimiento de normativas'),
            ('C','Ausentismo elevado','Faltas frecuentes sin justificación válida'),
        ]
        for c in criterios:
            db.execute("INSERT INTO criterios_clasificacion (clasificacion,criterio,descripcion) VALUES (?,?,?)", c)
        db.commit()

        sup_id = db.execute("SELECT id FROM usuarios WHERE rol='supervisor'").fetchone()['id']
        evaluaciones = [
            (2908,'Felipe Flores Martínez','3101','Tornero Especialista','Producción','2025-11-04','Renuncia voluntaria','A','Excelente empleado, dedicado y eficiente durante toda su estancia.','Técnica, puntualidad, liderazgo informal','Ninguna destacada',1),
            (2920,'José Alfredo Vázquez Cruz','2245','Ayudante General','Mantenimiento','2025-11-08','Término de contrato','B','Desempeño regular, cumplía con lo básico requerido.','Trabajo en equipo, disponibilidad','Mayor iniciativa y proactividad',0),
            (3043,'Gustavo Nava García','3876','Ayudante General','Construcción','2025-12-16','Despido justificado','C','Ausentismo frecuente y problemas disciplinarios reiterados.','Habilidad técnica en campo','Disciplina, puntualidad, actitud laboral',0),
            (3055,'Jesús Ramos Gutiérrez','4102','Operario Jr Instalación','Construcción','2026-01-06','Renuncia voluntaria','A','Excelente empleado, salió por una mejor oferta económica.','Técnica, iniciativa, proactividad, compromiso','Comunicación escrita',1),
            (3206,'Luis Eder Cadena Íñiguez','4411','Comprador','Administración','2026-03-31','Mutuo acuerdo','B','Cumplía sus objetivos con buena actitud colaborativa.','Negociación, relaciones con proveedores','Análisis de datos y reportes',1),
        ]
        for e in evaluaciones:
            db.execute("""INSERT INTO empleados_baja
                (folio,nombre,numero_empleado,cargo,departamento,fecha_baja,motivo,clasificacion,comentarios,fortalezas,areas_mejora,recomendaria,supervisor_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (*e, sup_id))
        db.commit()

        # Autorizaciones parciales
        sup_user_id = db.execute("SELECT id FROM usuarios WHERE rol='superintendente'").fetchone()['id']
        ev2908 = db.execute("SELECT id FROM empleados_baja WHERE folio=2908").fetchone()['id']
        ev2920 = db.execute("SELECT id FROM empleados_baja WHERE folio=2920").fetchone()['id']
        ev3055 = db.execute("SELECT id FROM empleados_baja WHERE folio=3055").fetchone()['id']
        db.execute("INSERT INTO autorizaciones (evaluacion_id,rol,usuario_id,decision) VALUES (?,?,?,?)", (ev2908,'superintendente',sup_user_id,'autorizado'))
        db.execute("INSERT INTO autorizaciones (evaluacion_id,rol,usuario_id,decision) VALUES (?,?,?,?)", (ev2908,'coord_construccion',sup_user_id,'autorizado'))
        db.execute("INSERT INTO autorizaciones (evaluacion_id,rol,usuario_id,decision) VALUES (?,?,?,?)", (ev2920,'superintendente',sup_user_id,'autorizado'))
        db.execute("INSERT INTO autorizaciones (evaluacion_id,rol,usuario_id,decision) VALUES (?,?,?,?)", (ev3055,'superintendente',sup_user_id,'autorizado'))
        db.execute("INSERT INTO autorizaciones (evaluacion_id,rol,usuario_id,decision) VALUES (?,?,?,?)", (ev3055,'coord_construccion',sup_user_id,'autorizado'))
        db.execute("INSERT INTO autorizaciones (evaluacion_id,rol,usuario_id,decision) VALUES (?,?,?,?)", (ev3055,'coord_rrhh',sup_user_id,'autorizado'))
        db.execute("UPDATE empleados_baja SET estatus='en_proceso' WHERE folio IN (2908,2920)")
        db.execute("UPDATE empleados_baja SET estatus='autorizado' WHERE folio=3055")
        db.commit()
    db.close()

# ─── Rutas ────────────────────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = query("SELECT * FROM usuarios WHERE email=? AND activo=1", (data.get('email',''),), one=True)
    if not user or user['password'] != hash_password(data.get('password','')):
        return jsonify({'error': 'Credenciales incorrectas'}), 401
    token = create_token(user)
    return jsonify({'token': token, 'user': {'id': user['id'], 'nombre': user['nombre'], 'rol': user['rol']}})

@app.route('/api/evaluaciones', methods=['GET'])
@auth_required
def get_evaluaciones():
    filters, params = ["1=1"], []
    for key, col in [('clasificacion','e.clasificacion'), ('estatus','e.estatus'), ('desde', None), ('hasta', None)]:
        val = request.args.get(key)
        if val:
            if key == 'desde': filters.append("e.fecha_baja >= ?"); params.append(val)
            elif key == 'hasta': filters.append("e.fecha_baja <= ?"); params.append(val)
            else: filters.append(f"{col} = ?"); params.append(val)
    if request.current_user['rol'] == 'supervisor':
        filters.append("e.supervisor_id = ?"); params.append(request.current_user['id'])
    sql = f"""
        SELECT e.*, u.nombre as supervisor_nombre,
            (SELECT COUNT(*) FROM autorizaciones a WHERE a.evaluacion_id=e.id AND a.decision='autorizado') as auth_count
        FROM empleados_baja e LEFT JOIN usuarios u ON e.supervisor_id=u.id
        WHERE {' AND '.join(filters)} ORDER BY e.creado_en DESC
    """
    return jsonify(query(sql, params))

@app.route('/api/evaluaciones/<int:eid>', methods=['GET'])
@auth_required
def get_evaluacion(eid):
    ev = query("SELECT e.*, u.nombre as supervisor_nombre FROM empleados_baja e LEFT JOIN usuarios u ON e.supervisor_id=u.id WHERE e.id=?", (eid,), one=True)
    if not ev:
        return jsonify({'error': 'No encontrado'}), 404
    auths = query("SELECT a.*, u.nombre as autorizador_nombre FROM autorizaciones a LEFT JOIN usuarios u ON a.usuario_id=u.id WHERE a.evaluacion_id=? ORDER BY a.fecha", (eid,))
    ev['autorizaciones'] = auths
    return jsonify(ev)

@app.route('/api/evaluaciones', methods=['POST'])
@auth_required
def create_evaluacion():
    if request.current_user['rol'] not in ('supervisor', 'admin'):
        return jsonify({'error': 'Sin permisos'}), 403
    data = request.get_json()
    required = ['nombre','cargo','fecha_baja','motivo','clasificacion']
    if not all(data.get(k) for k in required):
        return jsonify({'error': 'Campos requeridos incompletos'}), 400
    max_folio = query("SELECT MAX(folio) as m FROM empleados_baja", one=True)
    folio = (max_folio['m'] or 3000) + 1
    eid = execute("""
        INSERT INTO empleados_baja (folio,nombre,numero_empleado,cargo,departamento,fecha_baja,motivo,clasificacion,comentarios,fortalezas,areas_mejora,recomendaria,supervisor_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (folio, data['nombre'], data.get('numero_empleado',''), data['cargo'], data.get('departamento',''),
          data['fecha_baja'], data['motivo'], data['clasificacion'], data.get('comentarios',''),
          data.get('fortalezas',''), data.get('areas_mejora',''), 1 if data.get('recomendaria') else 0,
          request.current_user['id']))
    return jsonify({'id': eid, 'folio': folio})

@app.route('/api/evaluaciones/<int:eid>', methods=['PUT'])
@auth_required
def update_evaluacion(eid):
    if request.current_user['rol'] not in ('supervisor', 'admin'):
        return jsonify({'error': 'Sin permisos'}), 403
    data = request.get_json()
    execute("""UPDATE empleados_baja SET nombre=?,cargo=?,departamento=?,fecha_baja=?,motivo=?,clasificacion=?,
        comentarios=?,fortalezas=?,areas_mejora=?,recomendaria=? WHERE id=? AND estatus='pendiente'""",
        (data['nombre'], data['cargo'], data.get('departamento',''), data['fecha_baja'], data['motivo'],
         data['clasificacion'], data.get('comentarios',''), data.get('fortalezas',''),
         data.get('areas_mejora',''), 1 if data.get('recomendaria') else 0, eid))
    return jsonify({'ok': True})

ROL_ORDEN = ['superintendente', 'coord_construccion', 'coord_rrhh']

@app.route('/api/pendientes', methods=['GET'])
@auth_required
def get_pendientes():
    rol = request.current_user['rol']
    if rol not in ROL_ORDEN:
        return jsonify([])
    rol_idx = ROL_ORDEN.index(rol)
    base = """
        SELECT e.*, u.nombre as supervisor_nombre FROM empleados_baja e
        LEFT JOIN usuarios u ON e.supervisor_id=u.id
        WHERE e.estatus NOT IN ('autorizado','rechazado')
        AND NOT EXISTS (SELECT 1 FROM autorizaciones a WHERE a.evaluacion_id=e.id AND a.rol=? AND a.decision IS NOT NULL)
    """
    params = [rol]
    if rol_idx > 0:
        prev_rol = ROL_ORDEN[rol_idx - 1]
        base += " AND EXISTS (SELECT 1 FROM autorizaciones a WHERE a.evaluacion_id=e.id AND a.rol=? AND a.decision='autorizado')"
        params.append(prev_rol)
    return jsonify(query(base, params))

@app.route('/api/autorizaciones', methods=['POST'])
@auth_required
def create_autorizacion():
    rol = request.current_user['rol']
    if rol not in ROL_ORDEN:
        return jsonify({'error': 'Sin permisos'}), 403
    data = request.get_json()
    evaluacion_id = data['evaluacion_id']
    decision = data['decision']
    comentario = data.get('comentario', '')
    firma = data.get('firma', '')
    existing = query("SELECT id FROM autorizaciones WHERE evaluacion_id=? AND rol=?", (evaluacion_id, rol), one=True)
    if existing:
        return jsonify({'error': 'Ya existe una decisión para este rol'}), 400
    execute("INSERT INTO autorizaciones (evaluacion_id,rol,usuario_id,decision,comentario,firma) VALUES (?,?,?,?,?,?)",
            (evaluacion_id, rol, request.current_user['id'], decision, comentario, firma))
    if decision == 'rechazado':
        execute("UPDATE empleados_baja SET estatus='rechazado' WHERE id=?", (evaluacion_id,))
    else:
        auth_count = query("SELECT COUNT(*) as c FROM autorizaciones WHERE evaluacion_id=? AND decision='autorizado'", (evaluacion_id,), one=True)['c']
        if auth_count >= 3:
            execute("UPDATE empleados_baja SET estatus='autorizado' WHERE id=?", (evaluacion_id,))
        else:
            execute("UPDATE empleados_baja SET estatus='en_proceso' WHERE id=? AND estatus='pendiente'", (evaluacion_id,))
    return jsonify({'ok': True})

@app.route('/api/usuarios', methods=['GET'])
@auth_required
def get_usuarios():
    if request.current_user['rol'] != 'admin':
        return jsonify({'error': 'Sin permisos'}), 403
    return jsonify(query("SELECT id,nombre,email,rol,activo,creado_en FROM usuarios"))

@app.route('/api/usuarios', methods=['POST'])
@auth_required
def create_usuario():
    if request.current_user['rol'] != 'admin':
        return jsonify({'error': 'Sin permisos'}), 403
    data = request.get_json()
    try:
        uid = execute("INSERT INTO usuarios (nombre,email,password,rol) VALUES (?,?,?,?)",
                      (data['nombre'], data['email'], hash_password(data['password']), data['rol']))
        return jsonify({'id': uid})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email ya registrado'}), 400

@app.route('/api/reportes/resumen', methods=['GET'])
@auth_required
def get_reportes():
    filters, params = ["1=1"], []
    if request.args.get('desde'):
        filters.append("fecha_baja >= ?"); params.append(request.args['desde'])
    if request.args.get('hasta'):
        filters.append("fecha_baja <= ?"); params.append(request.args['hasta'])
    w = ' AND '.join(filters)
    return jsonify({
        'por_clasif': query(f"SELECT clasificacion, COUNT(*) as total FROM empleados_baja WHERE {w} GROUP BY clasificacion", params),
        'por_motivo': query(f"SELECT motivo, COUNT(*) as total FROM empleados_baja WHERE {w} GROUP BY motivo ORDER BY total DESC", params),
        'por_estatus': query(f"SELECT estatus, COUNT(*) as total FROM empleados_baja WHERE {w} GROUP BY estatus", params),
        'por_dept': query(f"SELECT departamento, COUNT(*) as total FROM empleados_baja WHERE {w} AND departamento!='' GROUP BY departamento ORDER BY total DESC", params),
        'recomendaria': query(f"SELECT recomendaria, COUNT(*) as total FROM empleados_baja WHERE {w} GROUP BY recomendaria", params),
        'mensual': query(f"SELECT strftime('%Y-%m', fecha_baja) as mes, clasificacion, COUNT(*) as total FROM empleados_baja WHERE {w} GROUP BY mes, clasificacion ORDER BY mes", params),
    })

@app.route('/api/criterios', methods=['GET'])
@auth_required
def get_criterios():
    return jsonify(query("SELECT * FROM criterios_clasificacion WHERE activo=1 ORDER BY clasificacion"))

@app.route('/api/criterios', methods=['POST'])
@auth_required
def create_criterio():
    if request.current_user['rol'] != 'admin':
        return jsonify({'error': 'Sin permisos'}), 403
    data = request.get_json()
    cid = execute("INSERT INTO criterios_clasificacion (clasificacion,criterio,descripcion) VALUES (?,?,?)",
                  (data['clasificacion'], data['criterio'], data.get('descripcion','')))
    return jsonify({'id': cid})

@app.route('/api/criterios/<int:cid>', methods=['DELETE'])
@auth_required
def delete_criterio(cid):
    if request.current_user['rol'] != 'admin':
        return jsonify({'error': 'Sin permisos'}), 403
    execute("UPDATE criterios_clasificacion SET activo=0 WHERE id=?", (cid,))
    return jsonify({'ok': True})

# ─── Servir frontend ──────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    if path and os.path.exists(os.path.join(FRONTEND_DIR, path)):
        return send_from_directory(FRONTEND_DIR, path)
    return send_file(os.path.join(FRONTEND_DIR, 'index.html'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 3000))
    print(f"\n✅ Sistema de Evaluaciones de Salida — FYRESA")
    print(f"   http://localhost:{port}\n")
    print(f"   Usuario demo: supervisor@fyresa.com / fyresa2026\n")
    app.run(host='0.0.0.0', port=port, debug=False)
