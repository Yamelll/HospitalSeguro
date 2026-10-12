"""Hospital Seguro: panel demostrativo de controles HIPAA (Flask + SQL Server).

Flask solo orquesta: sesiones, rutas seguras e interfaz. Lo siguiente lo hace
SQL Server de forma nativa y Flask no lo reimplementa:
  * Enmascaramiento dinámico (DDM) sobre dbo.Pacientes.
  * Hash de contraseñas (HASHBYTES) y su comparación.
  * Auditoría de lectura de pacientes (dbo.usp_ConsultarPacientes).
  * Triggers de auditoría de UPDATE/DELETE en dbo.Expedientes.
  * Sanitización Safe Harbor (dbo.sp_AnonimizarPacientesQA).

Reglas que cumple este archivo:
  1. Nunca hay SELECT a dbo.Pacientes: se usa siempre usp_ConsultarPacientes.
  2. La conexión sale de variables de entorno (.env) y siempre lleva Encrypt=yes.
  3. Todas las consultas usan parámetros "?"; ningún valor del usuario se concatena.
  4. Flask no enmascara ni hashea datos.
"""
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from datetime import date, datetime
from datetime import time as dt_time
from decimal import Decimal
from functools import wraps

import pyodbc
from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for

load_dotenv()


# --------------------------------------------------------------------------
# Configuración (todo viene del .env)
# --------------------------------------------------------------------------
def _requerida(nombre):
    valor = os.getenv(nombre, "").strip()
    if not valor:
        raise RuntimeError(f"Falta {nombre} en el archivo .env (revisa .env.example).")
    return valor


def _bandera(nombre, defecto="false"):
    return os.getenv(nombre, defecto).strip().lower() in ("1", "true", "yes", "si", "sí")


SECRET_KEY = _requerida("SECRET_KEY")
if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY debe tener al menos 32 caracteres.")

DB_DRIVER = os.getenv("DB_DRIVER", "ODBC Driver 17 for SQL Server").strip()
DB_SERVER = _requerida("DB_SERVER")
DB_NAME = os.getenv("DB_NAME", "HospitalSeguro").strip()
DB_USER = _requerida("DB_USER")
DB_PASSWORD = _requerida("DB_PASSWORD")
DB_TRUST_SERVER_CERT = "yes" if _bandera("DB_TRUST_SERVER_CERT", "yes") else "no"

# La sanitización solo se permite si ENTORNO=QA (protege contra ejecutarla en producción).
ENTORNO = os.getenv("ENTORNO", "PROD").strip().upper()

COOKIE_SEGURA = _bandera("SESSION_COOKIE_SECURE")
SESION_INACTIVIDAD_SEG = 30 * 60
SESION_MAXIMA_SEG = 8 * 60 * 60

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SEGURA,
    MAX_CONTENT_LENGTH=64 * 1024,
)


def _valor_odbc(valor):
    """Escapa un valor para la cadena de conexión ODBC (maneja ; y })."""
    return "{" + str(valor).replace("}", "}}") + "}"


def _cadena_conexion():
    # Encrypt=yes va siempre fijo: cifrado en tránsito obligatorio (regla 2).
    return ";".join([
        f"DRIVER={_valor_odbc(DB_DRIVER)}",
        f"SERVER={_valor_odbc(DB_SERVER)}",
        f"DATABASE={_valor_odbc(DB_NAME)}",
        f"UID={_valor_odbc(DB_USER)}",
        f"PWD={_valor_odbc(DB_PASSWORD)}",
        "Encrypt=yes",
        f"TrustServerCertificate={DB_TRUST_SERVER_CERT}",
        "APP=HospitalSeguroFlask",
    ])


@contextmanager
def db_connection():
    """Abre una conexión, confirma al terminar bien, revierte si falla y siempre cierra.

    El commit es necesario: usp_ConsultarPacientes inserta en dbo.Auditoria antes de
    hacer el SELECT y, sin commit, ese registro se perdería al cerrar la conexión.
    """
    conexion = pyodbc.connect(_cadena_conexion(), timeout=8)
    try:
        conexion.timeout = 20
        yield conexion
        conexion.commit()
    except Exception:
        conexion.rollback()
        raise
    finally:
        conexion.close()


# --------------------------------------------------------------------------
# Roles y permisos (RolID tal como se insertó en dbo.AppUsuarios)
# --------------------------------------------------------------------------
ROLES = {
    1: {
        "nombre": "Administrador",
        "permisos": "Gestiona usuarios, revisa la bitácora, pacientes, expedientes (solo lectura) "
                    "y consentimientos. Ejecuta la sanitización Safe Harbor en QA.",
        "intro": "Administración del sistema: usuarios, bitácora y sanitización de datos.",
    },
    2: {
        "nombre": "Médico",
        "permisos": "Consulta pacientes y personal; crea y edita expedientes clínicos.",
        "intro": "Atención clínica: pacientes y expedientes. Cada lectura de pacientes queda auditada.",
    },
    3: {
        "nombre": "Auditor HIPAA",
        "permisos": "Solo lectura de la bitácora y de los consentimientos. No accede a datos clínicos.",
        "intro": "Supervisión de cumplimiento: revisa quién hizo qué y cuándo.",
    },
}

PERMISOS = {
    "pacientes": {1, 2},
    "expedientes_leer": {1, 2},
    "expedientes_escribir": {2},
    "personal": {1, 2},
    "consentimientos": {1, 3},
    "usuarios": {1},
    "auditoria": {1, 3},
    "sanitizar": {1},
}

# (id de pestaña, etiqueta, permiso requerido). El orden es el de la interfaz.
PESTANAS = [
    ("pacientes", "Pacientes · DDM", "pacientes"),
    ("expedientes", "Expedientes", "expedientes_leer"),
    ("personal", "Personal médico", "personal"),
    ("consentimientos", "Consentimientos", "consentimientos"),
    ("usuarios", "Usuarios · RBAC", "usuarios"),
    ("auditoria", "Auditoría", "auditoria"),
    ("sanitizacion", "Sanitización · Safe Harbor", "sanitizar"),
]

LIMITES_FILAS = (50, 100, 200, 500)


# --------------------------------------------------------------------------
# Sesiones en memoria (un solo proceso) y control de intentos de login
# --------------------------------------------------------------------------
_sesiones = {}
_sesiones_lock = threading.Lock()

FALLOS_VENTANA_SEG = 15 * 60
BLOQUEO_SEG = 5 * 60
LIMITE_FALLOS_USUARIO = 5
LIMITE_FALLOS_IP = 10
_fallos = {}
_fallos_lock = threading.Lock()


def _purgar_sesiones(ahora):
    vencidas = [
        sid for sid, s in _sesiones.items()
        if ahora - s["last_access"] > SESION_INACTIVIDAD_SEG or ahora - s["created"] > SESION_MAXIMA_SEG
    ]
    for sid in vencidas:
        del _sesiones[sid]


def _current_auth():
    sid = session.get("sid")
    if not sid:
        return None
    ahora = time.monotonic()
    with _sesiones_lock:
        _purgar_sesiones(ahora)
        auth = _sesiones.get(sid)
        if auth:
            auth["last_access"] = ahora
            return auth
    session.clear()
    return None


def _cerrar_sesiones_de(user_id):
    with _sesiones_lock:
        for sid in [sid for sid, s in _sesiones.items() if s["user_id"] == user_id]:
            del _sesiones[sid]


def _segundos_bloqueado(claves):
    ahora = time.monotonic()
    restante = 0.0
    with _fallos_lock:
        for clave in claves:
            entrada = _fallos.get(clave)
            if entrada and entrada["bloqueado_hasta"] > ahora:
                restante = max(restante, entrada["bloqueado_hasta"] - ahora)
    return int(restante) + 1 if restante else 0


def _registrar_fallo(clave, limite):
    ahora = time.monotonic()
    with _fallos_lock:
        if len(_fallos) > 5000:
            for k in [k for k, e in _fallos.items()
                      if ahora - e["inicio"] > FALLOS_VENTANA_SEG and e["bloqueado_hasta"] < ahora]:
                del _fallos[k]
        entrada = _fallos.get(clave)
        if entrada is None or ahora - entrada["inicio"] > FALLOS_VENTANA_SEG:
            entrada = {"cuenta": 0, "inicio": ahora, "bloqueado_hasta": 0.0}
            _fallos[clave] = entrada
        entrada["cuenta"] += 1
        if entrada["cuenta"] >= limite:
            entrada["bloqueado_hasta"] = ahora + BLOQUEO_SEG
            entrada["cuenta"] = 0
            entrada["inicio"] = ahora


def _limpiar_fallos(clave):
    with _fallos_lock:
        _fallos.pop(clave, None)


def _iguales(a, b):
    return secrets.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


# --------------------------------------------------------------------------
# Utilidades de base de datos
# --------------------------------------------------------------------------
def _json_valor(valor):
    if isinstance(valor, (datetime, date, dt_time)):
        return valor.isoformat()
    if isinstance(valor, Decimal):
        return float(valor)
    if isinstance(valor, (bytes, bytearray, memoryview)):
        return "[binario]"
    return valor


def _records(cursor):
    # Salta resultados que no son filas (por ejemplo, conteos de filas afectadas).
    while cursor.description is None:
        if not cursor.nextset():
            return []
    columnas = [c[0] for c in cursor.description]
    return [
        {nombre: _json_valor(valor) for nombre, valor in zip(columnas, fila)}
        for fila in cursor.fetchall()
    ]


def _auditar(usuario, accion, tabla, filas=0, detalle=""):
    """Registra un evento en dbo.Auditoria (mejor esfuerzo, nunca rompe la petición).

    Misma forma de INSERT que usa usp_ConsultarPacientes. Si la cuenta de servicio no
    tiene INSERT o la tabla restringe los valores de Accion, solo se anota en el log.
    """
    try:
        with db_connection() as conexion:
            conexion.cursor().execute(
                """
                INSERT INTO dbo.Auditoria
                    (UsuarioAplicacion, LoginSQL, Accion, TablaAfectada, FilasAfectadas, Detalle)
                VALUES (?, ORIGINAL_LOGIN(), ?, ?, ?, ?)
                """,
                (str(usuario)[:128], accion, tabla, int(filas), str(detalle)[:200]),
            )
    except (pyodbc.Error, RuntimeError):
        app.logger.warning("No se pudo registrar el evento de auditoría %s", accion, exc_info=True)


def _falla_bd(exc, mensaje):
    app.logger.error(mensaje, exc_info=exc)
    sqlstate = exc.args[0] if isinstance(exc, pyodbc.Error) and exc.args else ""
    if sqlstate == "23000":
        return jsonify(error="No se pudo guardar: el registro está duplicado o hace referencia "
                             "a datos que no existen."), 409
    if sqlstate == "22001":
        return jsonify(error="Alguno de los textos supera la longitud que permite la base de datos."), 400
    return jsonify(error=mensaje), 500


def requiere(permiso):
    def decorador(handler):
        @wraps(handler)
        def envuelto(*args, **kwargs):
            auth = _current_auth()
            if not auth:
                return jsonify(error="La sesión expiró. Inicia sesión nuevamente."), 401
            if auth["role_id"] not in PERMISOS[permiso]:
                _auditar(auth["username"], "ACCESO_DENEGADO", "App", 0, f"{request.method} {request.path}")
                return jsonify(error="Tu perfil no tiene permiso para esta operación."), 403
            g.auth = auth
            return handler(*args, **kwargs)
        return envuelto
    return decorador


# --------------------------------------------------------------------------
# Validaciones de entrada
# --------------------------------------------------------------------------
def _entero_positivo(valor):
    if isinstance(valor, bool) or not isinstance(valor, (int, str)):
        return None
    try:
        numero = int(valor)
    except ValueError:
        return None
    return numero if numero > 0 else None


CAMPOS_EXPEDIENTE = (
    ("motivo", "Motivo", 500),
    ("diagnostico", "Diagnóstico", 2000),
    ("tratamiento", "Tratamiento", 2000),
)


def _validar_expediente(datos, creando):
    if not isinstance(datos, dict):
        return None, "Solicitud inválida."
    limpio = {}
    if creando:
        limpio["paciente_id"] = _entero_positivo(datos.get("paciente_id"))
        limpio["personal_id"] = _entero_positivo(datos.get("personal_id"))
        if not limpio["paciente_id"]:
            return None, "Selecciona un paciente."
        if not limpio["personal_id"]:
            return None, "Selecciona el personal médico responsable."
    for clave, etiqueta, maximo in CAMPOS_EXPEDIENTE:
        valor = datos.get(clave, "")
        if not isinstance(valor, str):
            return None, f"El campo {etiqueta} no es válido."
        valor = valor.strip()
        if not valor:
            return None, f"El campo {etiqueta} es obligatorio."
        if len(valor) > maximo:
            return None, f"El campo {etiqueta} admite hasta {maximo} caracteres."
        limpio[clave] = valor
    return limpio, None


USUARIO_RE = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")


def _validar_password(password):
    if not isinstance(password, str) or not (10 <= len(password) <= 100):
        return "La contraseña debe tener entre 10 y 100 caracteres."
    if not password.isascii():
        return "La contraseña solo puede usar caracteres ASCII."
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password) and re.search(r"\d", password)):
        return "La contraseña debe incluir mayúsculas, minúsculas y números."
    return None


def _escapar_like(texto):
    for caracter in ("\\", "%", "_", "["):
        texto = texto.replace(caracter, "\\" + caracter)
    return f"%{texto}%"


# --------------------------------------------------------------------------
# Seguridad HTTP: CSRF, cabeceras y errores
# --------------------------------------------------------------------------
def _login_page(error=None, estado=200):
    token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return render_template("login.html", csrf_token=token, error=error), estado


@app.before_request
def _proteger_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    esperado = session.get("csrf_token", "")
    recibido = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if esperado and recibido and _iguales(esperado, recibido):
        return None
    if request.path == url_for("login"):
        return _login_page("La solicitud expiró. Recarga la página e inténtalo de nuevo.", 400)
    if request.path.startswith("/api/"):
        return jsonify(error="Token de seguridad inválido. Recarga la página."), 400
    return redirect(url_for("index"))


@app.after_request
def _cabeceras(respuesta):
    respuesta.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["Referrer-Policy"] = "no-referrer"
    respuesta.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if COOKIE_SEGURA:
        respuesta.headers["Strict-Transport-Security"] = "max-age=31536000"
    if not request.path.startswith("/static/"):
        respuesta.headers["Cache-Control"] = "no-store"
    return respuesta


@app.errorhandler(404)
def _no_encontrado(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="Recurso no encontrado."), 404
    return "No encontrado", 404


@app.errorhandler(405)
def _metodo_no_permitido(_error):
    if request.path.startswith("/api/"):
        return jsonify(error="Método no permitido."), 405
    return "Método no permitido", 405


@app.errorhandler(413)
def _demasiado_grande(_error):
    return jsonify(error="La solicitud es demasiado grande."), 413


# --------------------------------------------------------------------------
# Autenticación (la comparación del hash la hace SQL Server con HASHBYTES)
# --------------------------------------------------------------------------
def autenticar_usuario(nombre_usuario, password):
    """Devuelve los datos del usuario si usuario, contraseña y estado son válidos.

    dbo.AppUsuarios guarda CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', clave), 2), por eso la
    contraseña se convierte a VARCHAR antes de hashear: así coincide con el hash almacenado.
    """
    with db_connection() as conexion:
        cursor = conexion.cursor()
        cursor.execute(
            """
            SELECT UsuarioID, NombreUsuario, RolID
            FROM dbo.AppUsuarios
            WHERE NombreUsuario = ?
              AND Activo = 1
              AND PasswordHash = CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', CAST(? AS VARCHAR(128))), 2)
            """,
            (nombre_usuario, password),
        )
        fila = cursor.fetchone()
    if fila is None or fila.RolID not in ROLES:
        return None
    return {"id": fila.UsuarioID, "username": fila.NombreUsuario, "role_id": fila.RolID}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if _current_auth():
            return redirect(url_for("index"))
        return _login_page()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        return _login_page("Ingresa tu usuario y contraseña.", 400)
    if len(username) > 100 or len(password) > 128:
        return _login_page("Usuario, contraseña o estado de cuenta no válidos.", 401)

    clave_ip = ("ip", request.remote_addr)
    clave_usuario = ("user", username.lower())
    espera = _segundos_bloqueado([clave_ip, clave_usuario])
    if espera:
        minutos = max(1, round(espera / 60))
        return _login_page(f"Demasiados intentos fallidos. Intenta de nuevo en {minutos} min.", 429)

    try:
        usuario = autenticar_usuario(username, password)
    except (pyodbc.Error, RuntimeError):
        app.logger.exception("No se pudo consultar la base de datos para autenticar")
        return _login_page("No se pudo validar el acceso. Revisa la conexión con la base de datos.", 503)

    if usuario is None:
        _registrar_fallo(clave_ip, LIMITE_FALLOS_IP)
        _registrar_fallo(clave_usuario, LIMITE_FALLOS_USUARIO)
        _auditar(username, "LOGIN_FALLIDO", "AppUsuarios", 0, "Credenciales o estado de cuenta no válidos")
        return _login_page("Usuario, contraseña o estado de cuenta no válidos.", 401)

    _limpiar_fallos(clave_usuario)
    session.clear()
    sid = secrets.token_urlsafe(32)
    ahora = time.monotonic()
    with _sesiones_lock:
        _purgar_sesiones(ahora)
        _sesiones[sid] = {
            "user_id": usuario["id"],
            "username": usuario["username"],
            "role_id": usuario["role_id"],
            "created": ahora,
            "last_access": ahora,
        }
    session["sid"] = sid
    session["csrf_token"] = secrets.token_urlsafe(32)
    _auditar(usuario["username"], "LOGIN", "AppUsuarios", 0,
             f"Inicio de sesión con rol {ROLES[usuario['role_id']]['nombre']}")
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    auth = _current_auth()
    sid = session.get("sid")
    if sid:
        with _sesiones_lock:
            _sesiones.pop(sid, None)
    session.clear()
    if auth:
        _auditar(auth["username"], "LOGOUT", "AppUsuarios", 0, "Cierre de sesión")
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Interfaz
# --------------------------------------------------------------------------
@app.get("/")
def index():
    auth = _current_auth()
    if not auth:
        return redirect(url_for("login"))
    rol = ROLES[auth["role_id"]]
    pestanas = [{"id": i, "label": e} for i, e, permiso in PESTANAS if auth["role_id"] in PERMISOS[permiso]]
    perfiles = [
        {"nombre": r["nombre"], "permisos": r["permisos"], "activo": rid == auth["role_id"]}
        for rid, r in ROLES.items()
    ]
    return render_template(
        "index.html",
        username=auth["username"],
        rol=rol,
        pestanas=pestanas,
        primero=pestanas[0]["id"],
        tab_ids=[p["id"] for p in pestanas],
        perfiles=perfiles,
        csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)),
        puede_escribir_exp=auth["role_id"] in PERMISOS["expedientes_escribir"],
        roles_opciones=[{"id": rid, "nombre": r["nombre"]} for rid, r in ROLES.items()],
        entorno=ENTORNO,
        sanitizacion_permitida=ENTORNO == "QA",
        limites=LIMITES_FILAS,
    )


# --------------------------------------------------------------------------
# API: pacientes, expedientes, personal y consentimientos
# --------------------------------------------------------------------------
@app.get("/api/pacientes")
@requiere("pacientes")
def api_pacientes():
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            # Regla 1: la lectura de pacientes SIEMPRE pasa por el SP que la audita.
            cursor.execute("EXEC usp_ConsultarPacientes @UsuarioAplicacion = ?", (g.auth["username"],))
            registros = _records(cursor)
        return jsonify(registros)
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudieron consultar los pacientes. Verifica la conexión y los permisos.")


@app.get("/api/expedientes")
@requiere("expedientes_leer")
def api_expedientes():
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute(
                """
                SELECT TOP (?) ExpedienteID, PacienteID, PersonalID, Motivo, Diagnostico, Tratamiento
                FROM dbo.Expedientes
                ORDER BY ExpedienteID DESC
                """,
                (200,),
            )
            registros = _records(cursor)
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudieron consultar los expedientes.")
    _auditar(g.auth["username"], "SELECT", "Expedientes", len(registros), "Consulta de expedientes desde la aplicación")
    return jsonify(registros)


@app.post("/api/expedientes")
@requiere("expedientes_escribir")
def api_expediente_crear():
    datos, error = _validar_expediente(request.get_json(silent=True), creando=True)
    if error:
        return jsonify(error=error), 400
    try:
        with db_connection() as conexion:
            conexion.cursor().execute(
                """
                INSERT INTO dbo.Expedientes (PacienteID, PersonalID, Motivo, Diagnostico, Tratamiento)
                VALUES (?, ?, ?, ?, ?)
                """,
                (datos["paciente_id"], datos["personal_id"], datos["motivo"],
                 datos["diagnostico"], datos["tratamiento"]),
            )
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo crear el expediente.")
    _auditar(g.auth["username"], "INSERT", "Expedientes", 1,
             f"Expediente creado para el paciente {datos['paciente_id']}")
    return jsonify(mensaje="Expediente creado correctamente."), 201


@app.put("/api/expedientes/<int:expediente_id>")
@requiere("expedientes_escribir")
def api_expediente_editar(expediente_id):
    datos, error = _validar_expediente(request.get_json(silent=True), creando=False)
    if error:
        return jsonify(error=error), 400
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute("SELECT 1 FROM dbo.Expedientes WHERE ExpedienteID = ?", (expediente_id,))
            if cursor.fetchone() is None:
                return jsonify(error="El expediente no existe."), 404
            # El trigger de auditoría de dbo.Expedientes registra este UPDATE en la base de datos.
            cursor.execute(
                """
                UPDATE dbo.Expedientes
                SET Motivo = ?, Diagnostico = ?, Tratamiento = ?
                WHERE ExpedienteID = ?
                """,
                (datos["motivo"], datos["diagnostico"], datos["tratamiento"], expediente_id),
            )
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo actualizar el expediente.")
    # El trigger ve a la cuenta de servicio; este evento deja constancia del usuario real.
    _auditar(g.auth["username"], "UPDATE", "Expedientes", 1, f"Expediente {expediente_id} modificado desde la aplicación")
    return jsonify(mensaje="Expediente actualizado correctamente.")


@app.get("/api/personal")
@requiere("personal")
def api_personal():
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute("SELECT TOP (?) * FROM dbo.Personal", (500,))
            return jsonify(_records(cursor))
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo consultar el personal.")


@app.get("/api/consentimientos")
@requiere("consentimientos")
def api_consentimientos():
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute("SELECT TOP (?) * FROM dbo.Consentimientos", (500,))
            return jsonify(_records(cursor))
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudieron consultar los consentimientos.")


# --------------------------------------------------------------------------
# API: usuarios (solo administrador). El hash lo calcula SQL Server.
# --------------------------------------------------------------------------
@app.get("/api/usuarios")
@requiere("usuarios")
def api_usuarios():
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            # Nunca se selecciona PasswordHash.
            cursor.execute(
                """
                SELECT UsuarioID, NombreUsuario, RolID, Activo, FechaCreacion
                FROM dbo.AppUsuarios
                ORDER BY UsuarioID
                """
            )
            registros = _records(cursor)
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudieron consultar los usuarios.")
    for registro in registros:
        registro["Rol"] = ROLES.get(registro["RolID"], {}).get("nombre", "Sin rol válido")
        registro["Activo"] = bool(registro["Activo"])
    return jsonify(registros)


@app.post("/api/usuarios")
@requiere("usuarios")
def api_usuario_crear():
    datos = request.get_json(silent=True)
    if not isinstance(datos, dict):
        return jsonify(error="Solicitud inválida."), 400
    nombre = datos.get("username")
    password = datos.get("password")
    rol_id = _entero_positivo(datos.get("rol_id"))
    if not isinstance(nombre, str) or not USUARIO_RE.match(nombre.strip()):
        return jsonify(error="El usuario debe tener de 3 a 50 caracteres: letras, números, punto, guion o guion bajo."), 400
    nombre = nombre.strip()
    if rol_id not in ROLES:
        return jsonify(error="Selecciona un rol válido."), 400
    error_password = _validar_password(password)
    if error_password:
        return jsonify(error=error_password), 400
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute("SELECT 1 FROM dbo.AppUsuarios WHERE NombreUsuario = ?", (nombre,))
            if cursor.fetchone() is not None:
                return jsonify(error="Ya existe un usuario con ese nombre."), 409
            cursor.execute(
                """
                INSERT INTO dbo.AppUsuarios (NombreUsuario, PasswordHash, RolID, Activo, FechaCreacion)
                VALUES (?, CONVERT(VARCHAR(64), HASHBYTES('SHA2_256', CAST(? AS VARCHAR(128))), 2), ?, 1, GETDATE())
                """,
                (nombre, password, rol_id),
            )
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo crear el usuario.")
    _auditar(g.auth["username"], "INSERT", "AppUsuarios", 1, f"Usuario creado: {nombre} ({ROLES[rol_id]['nombre']})")
    return jsonify(mensaje=f"Usuario {nombre} creado correctamente."), 201


@app.patch("/api/usuarios/<int:usuario_id>/estado")
@requiere("usuarios")
def api_usuario_estado(usuario_id):
    datos = request.get_json(silent=True)
    if not isinstance(datos, dict) or not isinstance(datos.get("activo"), bool):
        return jsonify(error="Solicitud inválida."), 400
    activo = datos["activo"]
    if usuario_id == g.auth["user_id"]:
        return jsonify(error="No puedes cambiar el estado de tu propia cuenta."), 400
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute("SELECT NombreUsuario FROM dbo.AppUsuarios WHERE UsuarioID = ?", (usuario_id,))
            fila = cursor.fetchone()
            if fila is None:
                return jsonify(error="El usuario no existe."), 404
            nombre = fila.NombreUsuario
            cursor.execute("UPDATE dbo.AppUsuarios SET Activo = ? WHERE UsuarioID = ?", (1 if activo else 0, usuario_id))
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo actualizar el usuario.")
    if not activo:
        _cerrar_sesiones_de(usuario_id)
    _auditar(g.auth["username"], "UPDATE", "AppUsuarios", 1,
             f"Usuario {nombre} {'activado' if activo else 'desactivado'}")
    return jsonify(mensaje=f"Usuario {nombre} {'activado' if activo else 'desactivado'}.")


# --------------------------------------------------------------------------
# API: auditoría (administrador y auditor)
# --------------------------------------------------------------------------
@app.get("/api/auditoria")
@requiere("auditoria")
def api_auditoria():
    accion = request.args.get("accion", "").strip()[:40]
    usuario = request.args.get("usuario", "").strip()[:128]
    limite = _entero_positivo(request.args.get("limite", "100"))
    if limite not in LIMITES_FILAS:
        limite = 100
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute(
                """
                SELECT TOP (?)
                    AuditoriaID, FechaEvento, UsuarioAplicacion, LoginSQL,
                    Accion, TablaAfectada, FilasAfectadas, Detalle
                FROM dbo.Auditoria
                WHERE (? = N'' OR Accion = ?)
                  AND (? = N'' OR UsuarioAplicacion LIKE ? ESCAPE '\\')
                ORDER BY FechaEvento DESC, AuditoriaID DESC
                """,
                (limite, accion, accion, usuario, _escapar_like(usuario)),
            )
            return jsonify(_records(cursor))
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo consultar la bitácora. Verifica que la tabla y sus permisos existan.")


@app.get("/api/auditoria/resumen")
@requiere("auditoria")
def api_auditoria_resumen():
    try:
        with db_connection() as conexion:
            cursor = conexion.cursor()
            cursor.execute("SELECT Accion, COUNT(*) AS Total FROM dbo.Auditoria GROUP BY Accion ORDER BY Total DESC")
            acciones = _records(cursor)
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo calcular el resumen de la bitácora.")
    return jsonify(total=sum(a["Total"] for a in acciones), acciones=acciones)


# --------------------------------------------------------------------------
# API: sanitización Safe Harbor (solo administrador y solo en QA)
# --------------------------------------------------------------------------
@app.post("/api/anonimizar")
@requiere("sanitizar")
def api_anonimizar():
    if ENTORNO != "QA":
        return jsonify(error=f"Bloqueado: la sanitización solo se permite con ENTORNO=QA (actual: {ENTORNO})."), 403
    datos = request.get_json(silent=True)
    if not isinstance(datos, dict) or datos.get("confirmacion") != "SANITIZAR":
        return jsonify(error="Escribe SANITIZAR para confirmar la operación."), 400
    try:
        with db_connection() as conexion:
            conexion.cursor().execute("EXEC dbo.sp_AnonimizarPacientesQA")
    except (pyodbc.Error, RuntimeError) as exc:
        return _falla_bd(exc, "No se pudo ejecutar la sanitización. Verifica el procedimiento y sus permisos.")
    _auditar(g.auth["username"], "EXEC", "Pacientes", 0, "Sanitización Safe Harbor ejecutada (sp_AnonimizarPacientesQA)")
    return jsonify(mensaje="El procedimiento de sanitización Safe Harbor se ejecutó correctamente.")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=_bandera("FLASK_DEBUG"))