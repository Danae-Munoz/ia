import sqlite3

conn = sqlite3.connect("instance/test.sqlite3")
conn.execute("CREATE TABLE test (id INTEGER)")
conn.close()

print("¡Funciona! Se pudo crear la base de datos.")
