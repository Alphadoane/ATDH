from datetime import datetime
from typing import Optional
from sqlmodel import Field, SQLModel, create_engine, Session, select

class NormalizedLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    hostname: Optional[str] = Field(default="localhost", index=True)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: str
    username: Optional[str] = None
    process_name: Optional[str] = None
    status: Optional[str] = None
    raw_log: str
    risk_score: int = 0

class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    hostname: Optional[str] = Field(default="localhost", index=True)
    rule_name: str
    severity: str  # Low, Medium, High, Critical
    description: str
    source_ip: Optional[str] = None
    status: str = "New" # New, In Progress, Resolved
    risk_score: int
    mitre_technique: Optional[str] = None
    mitre_id: Optional[str] = None
    session_id: Optional[int] = Field(default=None, foreign_key="attacksession.id")

class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hostname: str = Field(unique=True, index=True)
    ip_address: str = Field(index=True)
    mac_address: Optional[str] = None
    os_info: Optional[str] = None
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    is_managed: bool = Field(default=False) # True if agent is installed

class AttackSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source_ip: str = Field(index=True)
    risk_score: int = 0
    start_time: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    techniques: str = "" # Comma-separated T-IDs
    is_active: bool = True

class DetectionRuleConfig(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True)
    is_active: bool = True
    threshold: int
    window_seconds: int
    severity: str
