import os
import psycopg2

def migrate():
    user = os.getenv("DB_USER", "postgres")
    password = os.getenv("DB_PASSWORD", "Doane40640666")
    host = os.getenv("DB_HOST", "localhost")
    port = os.getenv("DB_PORT", "5432")
    dbname = os.getenv("DB_NAME", "threat_platform")

    conn = psycopg2.connect(
        dbname=dbname,
        user=user,
        password=password,
        host=host,
        port=port
    )
    cur = conn.cursor()

    print(f"Applying organizational scaling updates to {dbname}...")
    
    # Create Asset table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS asset (
            id SERIAL PRIMARY KEY,
            hostname VARCHAR UNIQUE NOT NULL,
            ip_address VARCHAR NOT NULL,
            mac_address VARCHAR,
            os_info VARCHAR,
            last_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            is_managed BOOLEAN DEFAULT FALSE
        );
    """)
    
    # Add hostname to normalizedlog and alert
    tables = ['normalizedlog', 'alert']
    for table in tables:
        cur.execute(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                             WHERE table_name='{table}' AND column_name='hostname') THEN
                    ALTER TABLE {table} ADD COLUMN hostname VARCHAR DEFAULT 'localhost';
                    CREATE INDEX idx_{table}_hostname ON {table} (hostname);
                END IF;
            END $$;
        """)

    conn.commit()
    cur.close()
    conn.close()
    print("Migration successful!")

if __name__ == "__main__":
    migrate()
