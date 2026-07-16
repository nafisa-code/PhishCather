import sqlite3
def create_database():
    conn = sqlite3.connect("database/phishcatcher.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        subject TEXT,
        date TEXT,
        threat_level TEXT,
        threat_score INTEGER
    )
    """)
    conn.commit()
    conn.close()
create_database()
