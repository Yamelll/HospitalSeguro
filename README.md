# Hospital Seguro: panel demostrativo HIPAA

Aplicación Flask que orquesta sesiones, rutas seguras e interfaz sobre la base de datos `HospitalSeguro` (SQL Server) **sin modificar su arquitectura**. El enmascaramiento (DDM), los hashes, la auditoría de lectura, los triggers y la sanitización los ejecuta SQL Server; Flask solo los invoca.

## Instalación

```bash
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env          # Linux/macOS: cp .env.example .env
# edita .env con tus datos (SECRET_KEY nueva, cuenta de servicio, ENTORNO=QA)
python app.py                   # http://127.0.0.1:5000
```

Requiere el driver **ODBC Driver 17 (o 18) for SQL Server** instalado en el equipo.

Para una exposición más estable (Windows): `pip install waitress` y `waitress-serve --listen=127.0.0.1:5000 app:app`. Usa **un solo proceso**: las sesiones viven en memoria.

## Reglas de diseño y dónde se cumplen

| Regla | Implementación |
|---|---|
| 1. Lectura de pacientes auditada | `/api/pacientes` ejecuta únicamente `EXEC usp_ConsultarPacientes @UsuarioAplicacion = ?`. No existe ningún `SELECT` a `dbo.Pacientes` en el código (lo verifica `tests/test_smoke.py`). |
| 2. Conexión segura | La cadena se arma desde variables de `.env` y **siempre** incluye `Encrypt=yes`. |
| 3. Sin inyección SQL | Todas las consultas usan `?`. Los filtros de la bitácora usan parámetros, no texto concatenado. |
| 4. Flask no enmascara ni hashea | El hash lo calcula y compara SQL Server (`HASHBYTES`); el enmascaramiento es el DDM de la BD. |

## Permisos por rol (RolID según tus `INSERT`)

| Pestaña | Administrador (1) | Médico (2) | Auditor HIPAA (3) |
|---|:-:|:-:|:-:|
| Pacientes · DDM | ✔ | ✔ | — |
| Expedientes | solo lectura | leer, crear y editar | — |
| Personal médico | ✔ | ✔ | — |
| Consentimientos | ✔ | — | ✔ |
| Usuarios · RBAC | ✔ | — | — |
| Auditoría | ✔ | — | ✔ |
| Sanitización Safe Harbor | ✔ (solo `ENTORNO=QA`) | — | — |

Los permisos se validan **en el servidor** en cada ruta (la interfaz solo oculta pestañas). Un acceso denegado devuelve 403 y queda en la bitácora como `ACCESO_DENEGADO`.

## Guion de demostración (≈ 8 min)

Cuentas de tus inserts: `admin_sistema` / `AdminSeguro2026!`, `dr_carlos_r` y `dra_laura_m` / `MedPassword2026!`, `auditor_hipaa` / `AuditSeguro2026!`.

1. **Login fallido y RBAC.** Intenta entrar con una contraseña incorrecta (queda `LOGIN_FALLIDO`). Tras 5 fallos seguidos con el mismo usuario se bloquea 5 minutos.
2. **Médico (`dr_carlos_r`).** Abre *Pacientes*: la lectura se audita y los datos enmascarados por DDM se resaltan. En *Expedientes* crea uno nuevo y edítalo (el trigger de BD audita el UPDATE).
3. **Acceso denegado.** Con la misma sesión abre `http://127.0.0.1:5000/api/auditoria` en el navegador: 403.
4. **Auditor (`auditor_hipaa`).** Solo ve *Consentimientos* y *Auditoría*. Filtra por `SELECT` o por usuario `dr_carlos_r`, localiza el `ACCESO_DENEGADO` del paso anterior y exporta el CSV.
5. **Administrador (`admin_sistema`).** En *Usuarios* crea una cuenta y desactívala (pierde la sesión al instante). En *Sanitización* escribe `SANITIZAR`, ejecuta y vuelve a *Pacientes* para ver el cambio.

## Prueba automática

```bash
python -m unittest discover -s tests -v
```

Usa un `pyodbc` simulado (no necesita SQL Server) y comprueba login por rol, matriz de permisos, CSRF, la llamada exacta al SP, validaciones y que nunca se consulte `dbo.Pacientes` directamente.

## Supuestos y limitaciones (conviene mencionarlas en la exposición)

- **DDM y la cuenta de servicio.** Flask se conecta con una sola cuenta SQL, y el DDM se evalúa por usuario de SQL Server, así que todos los roles de la aplicación ven el mismo enmascaramiento. La diferencia entre roles la aplica Flask (quién puede llamar a cada ruta). Enmascaramiento distinto por rol exigiría una cuenta SQL por rol, lo que cambia la arquitectura.
- **Bitácora.** `LoginSQL` registra la cuenta de servicio; el usuario real va en `UsuarioAplicacion`. Flask agrega eventos `LOGIN`, `LOGIN_FALLIDO`, `LOGOUT`, `ACCESO_DENEGADO`, `INSERT`/`UPDATE` de expedientes y usuarios y `EXEC` de sanitización con un `INSERT` en `dbo.Auditoria`. Si la cuenta no tiene `INSERT` o la tabla restringe los valores de `Accion` con un `CHECK`, el evento solo se escribe en el log de la aplicación y la app sigue funcionando (valores en `app.py`, función `_auditar`).
- **Hashes.** Tus contraseñas usan `SHA2_256` sin sal. Es válido para la demo, pero una versión de producción debería usar sal y un algoritmo lento (por ejemplo PBKDF2/Argon2). Menciónalo como limitación conocida en tu investigación.
- **Personal y Consentimientos.** Se muestran con `SELECT *` y las columnas se detectan solas, porque su definición exacta no estaba en el material compartido. Si quieres columnas fijas y etiquetas propias, edita `defineView` en `static/app.js` y la consulta en `app.py`.
- **Expedientes.** No hay borrado desde la interfaz (la retención es de 6 años). Si agregas uno, el trigger de DELETE ya audita.
- **Sesiones en memoria.** Se pierden al reiniciar y no funcionan con varios procesos.
- **Seguridad HTTP.** Incluye CSRF en toda operación de escritura, cookies `HttpOnly`/`SameSite`, CSP estricta (sin scripts ni estilos inline), `no-store`, bloqueo por intentos fallidos y cierre de sesión por inactividad (30 min) y duración máxima (8 h).


## Estructura

```
app.py                         backend Flask
templates/login.html           inicio de sesión
templates/index.html           panel con pestañas según el rol
static/styles.css, app.js      interfaz (sin código inline)
tests/test_smoke.py            prueba con BD simulada
permisos_cuenta_servicio.sql   opcional: permisos mínimos de la cuenta de servicio
.env.example, requirements.txt
```
