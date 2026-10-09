import os
import secrets
import threading
import time
from datetime import date, datetime
from functools import wraps

import pyodbc
from dotenv import load_dotenv
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

load_dotenv()

app = Flask(__name__, template_folder=".")
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "").lower() == "true",
)

# Esta conexión corresponde a la cuenta de servicio de la aplicación.
# Configura DB_CONNECTION_STRING en el archivo .env.
CONNECTION_STRING = os.environ.get("DB_CONNECTION_STRING")

SESSION_TTL_SECONDS = 30 * 60
_db_sessions = {}
_db_sessions_lock = threading.Lock()

ROLE_DETAILS = {
    "Hospital_Admin": {
        "name": "Administrador",
        "permissions": "Lectura y modificación de pacientes, personal y expedientes.",
    },
    "Hospital_Medico": {
        "name": "Médico",
        "permissions": "Lectura de pacientes, personal y expedientes.",
    },
    "Hospital_Recepcion": {
        "name": "Recepción",
        "permissions": "Lectura de pacientes únicamente desde la vista autorizada.",
    },
}


def _connect_db():
    if not CONNECTION_STRING:
        raise RuntimeError("Falta configurar DB_CONNECTION_STRING en el archivo .env.")
    return pyodbc.connect(CONNECTION_STRING, timeout=8)


def autenticar_usuario(nombre_usuario, password):
    """Autentica contra AppUsuarios y devuelve los datos básicos del usuario."""
    with _connect_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT
                u.UsuarioID,
                u.NombreUsuario,
                u.PasswordHash,
                r.NombreRol
            FROM dbo.AppUsuarios AS u
            INNER JOIN dbo.AppRoles AS r
                ON r.RolID = u.RolID
            WHERE u.NombreUsuario = ?
              AND u.Activo = 1
            """,
            nombre_usuario,
        )
        usuario = cursor.fetchone()

    if usuario is None:
        return None

    if not check_password_hash(usuario.PasswordHash, password):
        return None

    # Solo se aceptan los tres roles contemplados por el panel.
    if usuario.NombreRol not in ROLE_DETAILS:
        return None

    return {
        "id": usuario.UsuarioID,
        "username": usuario.NombreUsuario,
        "role": usuario.NombreRol,
    }


def _purge_expired_sessions(now=None):
    now = now or time.monotonic()
    expired = [
        key for key, value in _db_sessions.items()
        if now - value["last_access"] > SESSION_TTL_SECONDS
    ]
    for key in expired:
        del _db_sessions[key]


def _current_auth():
    session_id = session.get("app_session_id")
    if not session_id:
        return None

    now = time.monotonic()
    with _db_sessions_lock:
        _purge_expired_sessions(now)
        auth = _db_sessions.get(session_id)
        if auth:
            auth["last_access"] = now
            return auth

    session.clear()
    return None


def _require_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        auth = _current_auth()
        if not auth:
            return jsonify({"error": "La sesión expiró. Inicia sesión nuevamente."}), 401
        g.db_auth = auth
        return handler(*args, **kwargs)
    return wrapped


def _require_role(role):
    def decorator(handler):
        @wraps(handler)
        def wrapped(*args, **kwargs):
            auth = _current_auth()
            if not auth:
                return jsonify({"error": "La sesión expiró. Inicia sesión nuevamente."}), 401
            if role not in auth["roles"]:
                return jsonify({"error": "Tu perfil no tiene permiso para esta operación."}), 403
            g.db_auth = auth
            return handler(*args, **kwargs)
        return wrapped
    return decorator


def _records(cursor):
    columns = [column[0] for column in cursor.description]
    records = []
    for row in cursor.fetchall():
        record = dict(zip(columns, row))
        for key, value in record.items():
            if isinstance(value, (date, datetime)):
                record[key] = value.isoformat()
        records.append(record)
    return records


def _csrf_valid():
    expected = session.get("csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token", "")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))


@app.route("/", methods=["GET"])
def index():
    auth = _current_auth()
    if not auth:
        return redirect(url_for("login"))

    profiles = [
        {"role": role, **details, "active": role in auth["roles"]}
        for role, details in ROLE_DETAILS.items()
    ]
    return render_template(
        "index.html",
        username=auth["username"],
        roles=auth["roles"],
        profiles=profiles,
        csrf_token=session["csrf_token"],
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if _current_auth():
            return redirect(url_for("index"))
        csrf_token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
        return render_template("login.html", csrf_token=csrf_token, error=None)

    if not secrets.compare_digest(
        session.get("csrf_token", ""), request.form.get("csrf_token", "")
    ):
        return render_template(
            "login.html",
            csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)),
            error="La solicitud expiró. Recarga la página e inténtalo de nuevo.",
        ), 400

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not username or not password:
        return render_template(
            "login.html",
            csrf_token=session["csrf_token"],
            error="Ingresa tu usuario y contraseña.",
        ), 400

    try:
        usuario = autenticar_usuario(username, password)
    except (pyodbc.Error, RuntimeError):
        app.logger.exception("No se pudo consultar la base de datos para autenticar")
        return render_template(
            "login.html",
            csrf_token=session["csrf_token"],
            error="No se pudo validar el acceso. Revisa la conexión con la base de datos.",
        ), 503

    if usuario is None:
        return render_template(
            "login.html",
            csrf_token=session["csrf_token"],
            error="Usuario, contraseña o estado de cuenta no válidos.",
        ), 401

    session.clear()
    session_id = secrets.token_urlsafe(32)
    auth = {
        "user_id": usuario["id"],
        "username": usuario["username"],
        "roles": [usuario["role"]],
        "last_access": time.monotonic(),
    }
    with _db_sessions_lock:
        _purge_expired_sessions()
        _db_sessions[session_id] = auth

    session["app_session_id"] = session_id
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout():
    if not _csrf_valid():
        return jsonify({"error": "Token de seguridad inválido. Recarga la página."}), 400

    session_id = session.get("app_session_id")
    if session_id:
        with _db_sessions_lock:
            _db_sessions.pop(session_id, None)
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/pacientes", methods=["GET"])
@_require_auth
def get_pacientes():
    try:
        with _connect_db() as connection:
            cursor = connection.cursor()
            roles = g.db_auth["roles"]
            if "Hospital_Recepcion" in roles and not (
                "Hospital_Admin" in roles or "Hospital_Medico" in roles
            ):
                cursor.execute(
                    """
                    SELECT PacienteID, Identificacion, Nombre, Apellidos, Correo, Telefono
                    FROM dbo.vw_PacientesRecepcion
                    """
                )
            else:
                cursor.execute(
                    """
                    SELECT PacienteID, Identificacion, Nombre, Apellidos, Correo, Telefono
                    FROM dbo.Pacientes
                    """
                )
            return jsonify(_records(cursor))
    except (pyodbc.Error, RuntimeError):
        app.logger.exception("No se pudo consultar la lista de pacientes")
        return jsonify({
            "error": "No se pudieron consultar los pacientes. Verifica la conexión y los permisos de la cuenta de servicio."
        }), 500


@app.route("/api/auditoria", methods=["GET"])
@_require_role("Hospital_Admin")
def get_auditoria():
    try:
        with _connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT TOP 20 AuditoriaID, FechaEvento, Accion, TablaAfectada, Detalle
                FROM dbo.Auditoria
                ORDER BY FechaEvento DESC
                """
            )
            return jsonify(_records(cursor))
    except (pyodbc.Error, RuntimeError):
        app.logger.exception("No se pudo consultar la bitácora de auditoría")
        return jsonify({
            "error": "No se pudo consultar la bitácora. Verifica que la tabla y sus permisos existan."
        }), 500


@app.route("/api/anonimizar", methods=["POST"])
@_require_role("Hospital_Admin")
def anonimizar_datos():
    if not _csrf_valid():
        return jsonify({"error": "Token de seguridad inválido. Recarga la página."}), 400

    try:
        with _connect_db() as connection:
            cursor = connection.cursor()
            cursor.execute("EXEC dbo.sp_AnonimizarPacientesQA")
            connection.commit()
        return jsonify({
            "mensaje": "El procedimiento de sanitización Safe Harbor se ejecutó correctamente."
        })
    except (pyodbc.Error, RuntimeError):
        app.logger.exception("No se pudo ejecutar el procedimiento Safe Harbor")
        return jsonify({
            "error": "No se pudo ejecutar la sanitización. Verifica el procedimiento y sus permisos."
        }), 500


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "").lower() == "true", port=5000)
