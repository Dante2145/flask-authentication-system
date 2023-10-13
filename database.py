import sqlite3

conn = sqlite3.connect('./instance/database.db')
cursor = conn.cursor()

table_to_delete = 'scan'

drop_table_query = f"DROP TABLE IF EXISTS {table_to_delete}"

cursor.execute(drop_table_query)

conn.commit()

cursor.close()
conn.close()