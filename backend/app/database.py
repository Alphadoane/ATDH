from sqlmodel import SQLModel, create_engine, Session
import os

# Using environment variables for PostgreSQL connection
POSTGRES_USER = os.getenv("DB_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("DB_PASSWORD", "Doane40640666")
POSTGRES_HOST = os.getenv("DB_HOST", "localhost")
POSTGRES_PORT = os.getenv("DB_PORT", "5432")
POSTGRES_DB = os.getenv("DB_NAME", "threat_platform")

postgres_url = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
engine = create_engine(postgres_url, echo=True)

def create_db_and_tables():
    # Note: Ensure the database exists before running this
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
