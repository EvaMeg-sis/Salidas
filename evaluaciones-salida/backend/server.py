#!/usr/bin/env python3
"""
Sistema de Evaluaciones de Cierre — FYRESA v2
Backend Flask + SQLite
"""
import sqlite3, os, hashlib, hmac, json, time
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, 'evaluaciones.db')
FRONTEND   = os.path.join(BASE_DIR, '..', 'frontend', 'public')
JWT_SECRET = os.environ.get('JWT_SECRET', 'fyresa_eval_secret_2026')

app = Flask(__name__, static_folder=FRONTEND)
CORS(app)

# ── DB ────────────────────────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def q(sql, p=(), one=False):
    c = db(); rows = [dict(r) for r in c.execute(sql, p).fetchall()]; c.close()
    return (rows[0] if rows else None) if one else rows

def ex(sql, p=()):
    c = db(); cur = c.execute(sql, p); c.commit(); lid = cur.lastrowid; c.close(); return lid

# ── JWT ───────────────────────────────────────────────────────────────────────
def hp(pw): return hashlib.sha256((pw+JWT_SECRET).encode()).hexdigest()

def mk_token(u):
    import base64
    pay = json.dumps({'id':u['id'],'nombre':u['nombre'],'email':u['email'],'rol':u['rol'],'exp':int(time.time())+28800})
    d = base64.b64encode(pay.encode()).decode()
    s = hmac.new(JWT_SECRET.encode(), d.encode(), hashlib.sha256).hexdigest()
    return f"{d}.{s}"

def chk_token(tok):
    import base64
    try:
        d,s = tok.split('.')
        if hmac.new(JWT_SECRET.encode(),d.encode(),hashlib.sha256).hexdigest() != s: return None
        pay = json.loads(base64.b64decode(d).decode())
        return None if pay.get('exp',0)<time.time() else pay
    except: return None

from functools import wraps
def auth(f):
    @wraps(f)
    def w(*a,**k):
        t = request.headers.get('Authorization','')[7:]
        u = chk_token(t)
        if not u: return jsonify({'error':'No autorizado'}),401
        request.u = u; return f(*a,**k)
    return w

def rol(*roles):
    def dec(f):
        @wraps(f)
        def w(*a,**k):
            if request.u['rol'] not in roles: return jsonify({'error':'Sin permisos'}),403
            return f(*a,**k)
        return w
    return dec

# ── INIT DB ───────────────────────────────────────────────────────────────────
def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS usuarios(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        rol TEXT NOT NULL CHECK(rol IN('admin','supervisor','superintendente','coordinador','coord_rh')),
        activo INTEGER DEFAULT 1, creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS evaluaciones(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folio INTEGER UNIQUE NOT NULL,
        nombre TEXT NOT NULL, funcion TEXT, puesto TEXT, proyecto TEXT,
        fecha_baja DATE, antiguedad TEXT,
        supervisor_id INTEGER, superintendente_id INTEGER,
        coordinador_id INTEGER, coord_rh_id INTEGER,
        -- Paso 2: Supervisor responde
        likert_tecnico INTEGER, likert_disciplina INTEGER,
        likert_actitud INTEGER, likert_seguridad INTEGER,
        promedio REAL, observaciones TEXT, clasificacion TEXT,
        fecha_evaluacion DATETIME,
        -- Paso 3: Validación RH (admin)
        rh_acuerdo INTEGER, rh_no_recont INTEGER, rh_justificacion TEXT,
        rh_usuario_id INTEGER, rh_fecha DATETIME,
        -- Paso 4: Autorizaciones
        super_decision TEXT, super_comentario TEXT, super_usuario_id INTEGER, super_fecha DATETIME,
        coord_decision TEXT, coord_comentario TEXT, coord_usuario_id INTEGER, coord_fecha DATETIME,
        -- Paso 5: Firmas
        firma_supervisor TEXT, firma_super TEXT, firma_coord TEXT, firma_rh TEXT,
        fecha_firma_supervisor DATETIME, fecha_firma_super DATETIME,
        fecha_firma_coord DATETIME, fecha_firma_rh DATETIME,
        -- Estado general
        estatus TEXT DEFAULT 'pendiente_evaluacion'
            CHECK(estatus IN('pendiente_evaluacion','evaluacion_completa',
                             'validacion_rh','autorizacion','rechazado_regresar',
                             'pendiente_firmas','completado')),
        creado_en DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(supervisor_id) REFERENCES usuarios(id),
        FOREIGN KEY(superintendente_id) REFERENCES usuarios(id),
        FOREIGN KEY(coordinador_id) REFERENCES usuarios(id),
        FOREIGN KEY(coord_rh_id) REFERENCES usuarios(id)
    );
    """)
    c.commit()
    # Migración segura
    cols = [r['name'] for r in c.execute("PRAGMA table_info(evaluaciones)").fetchall()]
    for col,typ in [('rh_no_recont','INTEGER'),('super_usuario_id','INTEGER'),
                    ('coord_usuario_id','INTEGER'),('rh_usuario_id','INTEGER')]:
        if col not in cols:
            c.execute(f"ALTER TABLE evaluaciones ADD COLUMN {col} {typ}")
    c.commit()

    if not c.execute("SELECT id FROM usuarios WHERE email='admin@fyresa.com'").fetchone():
        pw = hp('fyresa2026')
        for n,e,r in [
            ('Administrador RRHH','admin@fyresa.com','admin'),
            ('Supervisor López','supervisor1@fyresa.com','supervisor'),
            ('Supervisor Méndez','supervisor2@fyresa.com','supervisor'),
            ('Superintendente García','super1@fyresa.com','superintendente'),
            ('Superintendente Ramos','super2@fyresa.com','superintendente'),
            ('Coordinador Hernández','coord1@fyresa.com','coordinador'),
            ('Coordinador Silva','coord2@fyresa.com','coordinador'),
            ('Coord. RH Martínez','coordrh1@fyresa.com','coord_rh'),
        ]:
            c.execute("INSERT INTO usuarios(nombre,email,password,rol) VALUES(?,?,?,?)",(n,e,pw,r))

        folio = 1001
        sup1 = c.execute("SELECT id FROM usuarios WHERE email='supervisor1@fyresa.com'").fetchone()['id']
        sups1= c.execute("SELECT id FROM usuarios WHERE email='super1@fyresa.com'").fetchone()['id']
        co1  = c.execute("SELECT id FROM usuarios WHERE email='coord1@fyresa.com'").fetchone()['id']
        rh1  = c.execute("SELECT id FROM usuarios WHERE email='coordrh1@fyresa.com'").fetchone()['id']
        c.execute("""INSERT INTO evaluaciones(folio,nombre,funcion,puesto,proyecto,fecha_baja,antiguedad,
            supervisor_id,superintendente_id,coordinador_id,coord_rh_id,estatus)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (folio,'Felipe Flores Martínez','Operador','Tornero Especialista','Proyecto Norte',
             '2025-11-04','2 años 3 meses',sup1,sups1,co1,rh1,'pendiente_evaluacion'))
        c.commit()
    c.close()

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.post('/api/login')
def login():
    d = request.json
    u = q("SELECT * FROM usuarios WHERE email=? AND activo=1",(d.get('email',''),),one=True)
    if not u or u['password']!=hp(d.get('password','')): return jsonify({'error':'Credenciales incorrectas'}),401
    return jsonify({'token':mk_token(u),'user':{'id':u['id'],'nombre':u['nombre'],'rol':u['rol']}})

# ── USUARIOS ──────────────────────────────────────────────────────────────────
@app.get('/api/usuarios')
@auth
def get_usuarios():
    rol_filter = request.args.get('rol')
    if rol_filter:
        return jsonify(q("SELECT id,nombre,email,rol,activo FROM usuarios WHERE rol=? AND activo=1 ORDER BY nombre",(rol_filter,)))
    if request.u['rol']!='admin': return jsonify({'error':'Sin permisos'}),403
    return jsonify(q("SELECT id,nombre,email,rol,activo,creado_en FROM usuarios ORDER BY rol,nombre"))

@app.post('/api/usuarios')
@auth
@rol('admin')
def crear_usuario():
    d = request.json
    if not all(d.get(k) for k in ['nombre','email','password','rol']):
        return jsonify({'error':'Campos requeridos'}),400
    try:
        uid = ex("INSERT INTO usuarios(nombre,email,password,rol) VALUES(?,?,?,?)",
                 (d['nombre'],d['email'],hp(d['password']),d['rol']))
        return jsonify({'id':uid})
    except: return jsonify({'error':'Email ya registrado'}),400

@app.put('/api/usuarios/<int:uid>')
@auth
@rol('admin')
def editar_usuario(uid):
    d = request.json
    if d.get('password'):
        ex("UPDATE usuarios SET nombre=?,email=?,rol=?,password=? WHERE id=?",(d['nombre'],d['email'],d['rol'],hp(d['password']),uid))
    else:
        ex("UPDATE usuarios SET nombre=?,email=?,rol=? WHERE id=?",(d['nombre'],d['email'],d['rol'],uid))
    return jsonify({'ok':True})

@app.delete('/api/usuarios/<int:uid>')
@auth
@rol('admin')
def desactivar_usuario(uid):
    ex("UPDATE usuarios SET activo=0 WHERE id=?",(uid,))
    return jsonify({'ok':True})

# ── EVALUACIONES ──────────────────────────────────────────────────────────────
def eval_query(extra_where="", params=[], user=None):
    base = """
    SELECT e.*,
        us.nombre as supervisor_nombre, us.email as supervisor_email,
        ust.nombre as superintendente_nombre,
        uco.nombre as coordinador_nombre,
        urh.nombre as coord_rh_nombre
    FROM evaluaciones e
    LEFT JOIN usuarios us  ON e.supervisor_id=us.id
    LEFT JOIN usuarios ust ON e.superintendente_id=ust.id
    LEFT JOIN usuarios uco ON e.coordinador_id=uco.id
    LEFT JOIN usuarios urh ON e.coord_rh_id=urh.id
    WHERE 1=1
    """
    if extra_where: base += " AND " + extra_where
    base += " ORDER BY e.creado_en DESC"
    return q(base, params)

@app.get('/api/evaluaciones')
@auth
def get_evaluaciones():
    u = request.u
    if u['rol'] == 'admin':
        data = eval_query()
    elif u['rol'] == 'supervisor':
        data = eval_query("e.supervisor_id=?", [u['id']])
    elif u['rol'] == 'superintendente':
        data = eval_query("e.superintendente_id=? AND e.estatus IN('autorizacion','pendiente_firmas','completado','rechazado_regresar')", [u['id']])
    elif u['rol'] == 'coordinador':
        data = eval_query("e.coordinador_id=? AND e.estatus IN('autorizacion','pendiente_firmas','completado','rechazado_regresar')", [u['id']])
    elif u['rol'] == 'coord_rh':
        data = eval_query("e.coord_rh_id=? AND e.estatus IN('pendiente_firmas','completado')", [u['id']])
    else:
        data = []
    return jsonify(data)

@app.get('/api/evaluaciones/<int:eid>')
@auth
def get_evaluacion(eid):
    ev = eval_query("e.id=?", [eid], user=request.u)
    if not ev: return jsonify({'error':'No encontrado'}),404
    return jsonify(ev[0])

@app.post('/api/evaluaciones')
@auth
@rol('admin')
def crear_evaluacion():
    d = request.json
    req = ['nombre','supervisor_id','superintendente_id','coordinador_id','coord_rh_id']
    if not all(d.get(k) for k in req): return jsonify({'error':'Campos requeridos'}),400
    max_f = q("SELECT MAX(folio) as m FROM evaluaciones",one=True)
    folio = (max_f['m'] or 1000)+1
    eid = ex("""INSERT INTO evaluaciones(folio,nombre,funcion,puesto,proyecto,fecha_baja,antiguedad,
        supervisor_id,superintendente_id,coordinador_id,coord_rh_id,estatus)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (folio,d['nombre'],d.get('funcion',''),d.get('puesto',''),d.get('proyecto',''),
         d.get('fecha_baja',''),d.get('antiguedad',''),
         d['supervisor_id'],d['superintendente_id'],d['coordinador_id'],d['coord_rh_id'],
         'pendiente_evaluacion'))
    return jsonify({'id':eid,'folio':folio})

@app.put('/api/evaluaciones/<int:eid>')
@auth
@rol('admin')
def editar_evaluacion(eid):
    d = request.json
    ev = q("SELECT estatus FROM evaluaciones WHERE id=?", (eid,), one=True)
    if not ev: return jsonify({'error':'No encontrado'}),404
    ex("""UPDATE evaluaciones SET nombre=?,funcion=?,puesto=?,proyecto=?,fecha_baja=?,antiguedad=?,
        supervisor_id=?,superintendente_id=?,coordinador_id=?,coord_rh_id=? WHERE id=?""",
       (d['nombre'],d.get('funcion',''),d.get('puesto',''),d.get('proyecto',''),
        d.get('fecha_baja',''),d.get('antiguedad',''),
        d['supervisor_id'],d['superintendente_id'],d['coordinador_id'],d['coord_rh_id'],eid))
    return jsonify({'ok':True})

# ── PASO 2: SUPERVISOR EVALUA ─────────────────────────────────────────────────
@app.post('/api/evaluaciones/<int:eid>/evaluar')
@auth
@rol('supervisor')
def evaluar(eid):
    ev = q("SELECT * FROM evaluaciones WHERE id=? AND supervisor_id=?",(eid,request.u['id']),one=True)
    if not ev: return jsonify({'error':'Sin acceso o no encontrado'}),403
    if ev['estatus'] not in ('pendiente_evaluacion','rechazado_regresar'):
        return jsonify({'error':'Esta evaluación no puede modificarse en este estado'}),400
    d = request.json
    t = [d.get('likert_tecnico',0),d.get('likert_disciplina',0),d.get('likert_actitud',0),d.get('likert_seguridad',0)]
    prom = round(sum(t)/4,2)
    ex("""UPDATE evaluaciones SET likert_tecnico=?,likert_disciplina=?,likert_actitud=?,likert_seguridad=?,
        promedio=?,observaciones=?,clasificacion=?,fecha_evaluacion=datetime('now'),
        estatus='evaluacion_completa',
        super_decision=NULL,super_comentario=NULL,super_usuario_id=NULL,super_fecha=NULL,
        coord_decision=NULL,coord_comentario=NULL,coord_usuario_id=NULL,coord_fecha=NULL,
        rh_acuerdo=NULL,rh_no_recont=NULL,rh_justificacion=NULL,rh_usuario_id=NULL,rh_fecha=NULL,
        firma_supervisor=NULL,firma_super=NULL,firma_coord=NULL,firma_rh=NULL
        WHERE id=?""",
        (d['likert_tecnico'],d['likert_disciplina'],d['likert_actitud'],d['likert_seguridad'],
         prom,d.get('observaciones',''),d.get('clasificacion',''),eid))
    return jsonify({'ok':True,'promedio':prom})

# ── PASO 3: VALIDACIÓN RH (admin) ─────────────────────────────────────────────
@app.post('/api/evaluaciones/<int:eid>/validar_rh')
@auth
@rol('admin')
def validar_rh(eid):
    ev = q("SELECT estatus FROM evaluaciones WHERE id=?",(eid,),one=True)
    if not ev or ev['estatus'] != 'evaluacion_completa':
        return jsonify({'error':'La evaluación debe estar completa para validar'}),400
    d = request.json
    ex("""UPDATE evaluaciones SET rh_acuerdo=?,rh_no_recont=?,rh_justificacion=?,
        rh_usuario_id=?,rh_fecha=datetime('now'),estatus='autorizacion' WHERE id=?""",
       (1 if d.get('acuerdo') else 0, 1 if d.get('no_recont') else 0,
        d.get('justificacion',''), request.u['id'], eid))
    return jsonify({'ok':True})

# ── PASO 4: AUTORIZACIÓN (super y coordinador) ────────────────────────────────
@app.post('/api/evaluaciones/<int:eid>/autorizar')
@auth
@rol('superintendente','coordinador')
def autorizar(eid):
    ur = request.u['rol']
    ev = q("SELECT * FROM evaluaciones WHERE id=?",(eid,),one=True)
    if not ev or ev['estatus'] != 'autorizacion':
        return jsonify({'error':'No disponible para autorizar'}),400
    # Verificar que le pertenece
    campo_id = 'superintendente_id' if ur=='superintendente' else 'coordinador_id'
    if ev[campo_id] != request.u['id']:
        return jsonify({'error':'Esta evaluación no te está asignada'}),403
    d = request.json
    decision = d.get('decision') # 'autorizado' o 'rechazado'
    if ur == 'superintendente':
        ex("""UPDATE evaluaciones SET super_decision=?,super_comentario=?,
            super_usuario_id=?,super_fecha=datetime('now') WHERE id=?""",
           (decision, d.get('comentario',''), request.u['id'], eid))
    else:
        ex("""UPDATE evaluaciones SET coord_decision=?,coord_comentario=?,
            coord_usuario_id=?,coord_fecha=datetime('now') WHERE id=?""",
           (decision, d.get('comentario',''), request.u['id'], eid))
    # Re-evaluar estatus
    ev2 = q("SELECT super_decision,coord_decision FROM evaluaciones WHERE id=?",(eid,),one=True)
    sd, cd = ev2['super_decision'], ev2['coord_decision']
    if sd=='rechazado' or cd=='rechazado':
        ex("UPDATE evaluaciones SET estatus='rechazado_regresar' WHERE id=?",(eid,))
    elif sd=='autorizado' and cd=='autorizado':
        ex("UPDATE evaluaciones SET estatus='pendiente_firmas' WHERE id=?",(eid,))
    return jsonify({'ok':True})

# ── PASO 5: FIRMAS ────────────────────────────────────────────────────────────
@app.post('/api/evaluaciones/<int:eid>/firmar')
@auth
def firmar(eid):
    ur = request.u['rol']
    uid = request.u['id']
    ev = q("SELECT * FROM evaluaciones WHERE id=?",(eid,),one=True)
    if not ev or ev['estatus'] != 'pendiente_firmas':
        return jsonify({'error':'No disponible para firmar'}),400
    campo_id = {'supervisor':'supervisor_id','superintendente':'superintendente_id',
                'coordinador':'coordinador_id','coord_rh':'coord_rh_id'}.get(ur)
    if not campo_id or ev[campo_id] != uid:
        return jsonify({'error':'Esta evaluación no te corresponde firmar'}),403
    campo_firma = {'supervisor':'firma_supervisor','superintendente':'firma_super',
                   'coordinador':'firma_coord','coord_rh':'firma_rh'}[ur]
    campo_fecha = {'supervisor':'fecha_firma_supervisor','superintendente':'fecha_firma_super',
                   'coordinador':'fecha_firma_coord','coord_rh':'fecha_firma_rh'}[ur]
    firma = request.json.get('firma','')
    ex(f"UPDATE evaluaciones SET {campo_firma}=?,{campo_fecha}=datetime('now') WHERE id=?",(firma,eid))
    # Verificar si todas firmaron
    ev2 = q("SELECT firma_supervisor,firma_super,firma_coord,firma_rh FROM evaluaciones WHERE id=?",(eid,),one=True)
    if all(ev2[f] for f in ['firma_supervisor','firma_super','firma_coord','firma_rh']):
        ex("UPDATE evaluaciones SET estatus='completado' WHERE id=?",(eid,))
    return jsonify({'ok':True})

# ── REPORTES ──────────────────────────────────────────────────────────────────
@app.get('/api/reportes')
@auth
@rol('admin')
def reportes():
    return jsonify({
        'por_clasif': q("SELECT clasificacion,COUNT(*) as total FROM evaluaciones WHERE clasificacion IS NOT NULL GROUP BY clasificacion"),
        'por_estatus': q("SELECT estatus,COUNT(*) as total FROM evaluaciones GROUP BY estatus"),
        'por_supervisor': q("""SELECT u.nombre, COUNT(*) as total,
            SUM(CASE WHEN e.clasificacion='A' THEN 1 ELSE 0 END) as a,
            SUM(CASE WHEN e.clasificacion='B' THEN 1 ELSE 0 END) as b,
            SUM(CASE WHEN e.clasificacion='C' THEN 1 ELSE 0 END) as c
            FROM evaluaciones e JOIN usuarios u ON e.supervisor_id=u.id
            GROUP BY u.id ORDER BY total DESC"""),
        'total': q("SELECT COUNT(*) as c FROM evaluaciones",one=True)['c'],
        'completadas': q("SELECT COUNT(*) as c FROM evaluaciones WHERE estatus='completado'",one=True)['c'],
    })

# ── FRONTEND ──────────────────────────────────────────────────────────────────
@app.route('/', defaults={'path':''})
@app.route('/<path:path>')
def spa(path):
    f = os.path.join(FRONTEND, path)
    if path and os.path.exists(f): return send_from_directory(FRONTEND, path)
    return send_file(os.path.join(FRONTEND,'index.html'))

if __name__=='__main__':
    init_db()
    port = int(os.environ.get('PORT',3000))
    print(f"\n✅ FYRESA Evaluaciones de Cierre v2")
    print(f"   http://localhost:{port}")
    print(f"   admin@fyresa.com / fyresa2026\n")
    app.run(host='0.0.0.0', port=port, debug=False)
