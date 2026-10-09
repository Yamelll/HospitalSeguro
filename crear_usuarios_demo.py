import os

import pyodbc
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

# Cuentas de demostración. Cambia estas contraseñas antes de cualquier uso real.
usuarios_demo = [
    ("admin.demo", "Hospital_Admin", "Admin123"),
    ("medico.demo", "Hospital_Medico", "Medico123"),
    ("recepcion.demo", "Hospital_Recepcion", "Recepcion123"),
]


def main():
    connection_string = os.getenv("DB_CONNECTION_STRING")
    if not connection_string:
        raise SystemExit(
            "Falta DB_CONNECTION_STRING. Copia .env.example a .env y configura "
            "la conexión a SQL Server."
        )

    with pyodbc.connect(connection_string) as conn:
        cursor = conn.cursor()

        for nombre, rol, password in usuarios_demo:
            password_hash = generate_password_hash(password)
            cursor.execute(
                """
                IF NOT EXISTS (
                    SELECT 1
                    FROM dbo.AppUsuarios
                    WHERE NombreUsuario = ?
                )
                BEGIN
                    INSERT INTO dbo.AppUsuarios
                        (NombreUsuario, PasswordHash, RolID, Activo)
                    SELECT ?, ?, RolID, 1
                    FROM dbo.AppRoles
                    WHERE NombreRol = ?;

                    IF @@ROWCOUNT = 0
                        THROW 50001, 'No existe el rol configurado en dbo.AppRoles.', 1;
                END
                """,
                nombre, nombre, password_hash, rol
            )

        conn.commit()

    print("Usuarios de demostración creados o ya existentes.")


if __name__ == "__main__":
    main()
