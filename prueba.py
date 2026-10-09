import os
import pyodbc
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

load_dotenv()

conn = pyodbc.connect(os.getenv("DB_CONNECTION_STRING"))
cursor = conn.cursor()

cursor.execute(
    "SELECT PasswordHash FROM dbo.AppUsuarios WHERE NombreUsuario = ?",
    "admin.demo"
)

row = cursor.fetchone()

print(check_password_hash(row[0], "Admin123"))