import psycopg2
import os
conn = psycopg2.connect(
    dbname=os.environ['PGDATABASE'],
    user=os.environ['PGUSER'],
    password= os.environ['PGPASSWORD'],
    host=os.environ['PGHOST']
)
cursor = conn.cursor()
cursor.execute("""
ALTER TABLE chats (
    username VARCHAR(255) NOT NULL,
    time VARCHAR,
    message VARCHAR NOT NULL
    ADD COLUMN IF NOT EXISTS query VARCHAR
);
""")
conn.commit()
print('done')