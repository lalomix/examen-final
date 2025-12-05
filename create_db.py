import sqlite3
from werkzeug.security import generate_password_hash

# Conexión a la base de datos
conn = sqlite3.connect('example.db')
c = conn.cursor()

# Limpiar tablas si existen para regenerar con datos seguros
c.execute('DROP TABLE IF EXISTS comments')
c.execute('DROP TABLE IF EXISTS users')

# Crear la tabla de usuarios
c.execute('''
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
''')

# Insertar usuarios con HASH SEGURO (Werkzeug)
# Esto soluciona la vulnerabilidad de Hashing Débil
admin_pass = generate_password_hash('password')
user_pass = generate_password_hash('password')

c.execute('''
    INSERT INTO users (username, password, role) VALUES
    ('admin', ?, 'admin'),
    ('user', ?, 'user')
''', (admin_pass, user_pass))

# Crear la tabla de comentarios
c.execute('''
    CREATE TABLE comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

conn.commit()
conn.close()

print("Base de datos creada exitosamente con contraseñas seguras.")