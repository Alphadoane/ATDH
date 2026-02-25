import os
import psycopg2
from psycopg2 import sql

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

    print(f"Applying schema updates to {dbname}...")
    
    # Create AttackSession table if it doesn't exist
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attacksession (
            id SERIAL PRIMARY KEY,
            source_ip VARCHAR NOT NULL,
            risk_score INTEGER DEFAULT 0,
            start_time TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            last_seen TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
            techniques VARCHAR DEFAULT '',
            is_active BOOLEAN DEFAULT TRUE
        );
    """)
    
    # Add columns to Alert table if they don't exist
    columns_to_add = [
        ("mitre_technique", "VARCHAR"),
        ("mitre_id", "VARCHAR"),
        ("session_id", "INTEGER REFERENCES attacksession(id)")
    ]
    
    for col_name, col_type in columns_to_add:
        cur.execute(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                             WHERE table_name='alert' AND column_name='{col_name}') THEN
                    ALTER TABLE alert ADD COLUMN {col_name} {col_type};
                END IF;
            END $$;
        """)

    conn.commit()
    cur.close()
    conn.close()
    print("Migration successful!")

if __name__ == "__main__":
    migrate()
