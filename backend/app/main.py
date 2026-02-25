from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Session, select
from typing import List
from .database import engine, create_db_and_tables, get_session
from .models import NormalizedLog, Alert, AttackSession
from .engine.correlation_engine import CorrelationEngine

from .engine.normalizer import Normalizer
from .engine.detection_engine import DetectionEngine
from .engine.risk_scorer import RiskScorer

app = FastAPI(title="Adaptive Threat Detection Platform")
normalizer = Normalizer()
detection_engine = DetectionEngine()
risk_scorer = RiskScorer()

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

@app.get("/")
def read_root():
    return {"status": "Platform Active", "version": "0.1.0"}

@app.get("/logs", response_model=List[NormalizedLog])
def get_logs(session: Session = Depends(get_session)):
    return session.exec(select(NormalizedLog).order_by(NormalizedLog.timestamp.desc())).all()

@app.get("/alerts", response_model=List[Alert])
def get_alerts(session: Session = Depends(get_session)):
    return session.exec(select(Alert).order_by(Alert.timestamp.desc())).all()

@app.get("/sessions", response_model=List[AttackSession])
def get_sessions(session: Session = Depends(get_session)):
    return session.exec(select(AttackSession).order_by(AttackSession.last_seen.desc())).all()

@app.post("/ingest/raw")
async def ingest_raw_log(raw_log: str, log_type: str = "auto", session: Session = Depends(get_session)):
    # 1. Normalize
    normalized = normalizer.normalize(raw_log, log_type)
    if not normalized:
        raise HTTPException(status_code=400, detail="Failed to normalize log")

    # 2. Risk Scoring (Initial)
    normalized.risk_score = risk_scorer.calculate_risk(normalized)
    
    # 3. Save Log
    session.add(normalized)
    session.commit()
    session.refresh(normalized)

    # 4. Detection Engine
    recent_logs = session.exec(select(NormalizedLog)).all()
    new_alerts = detection_engine.process_events(recent_logs)
    
    # 5. Correlation & MITRE
    correlation_engine = CorrelationEngine(session)
    for alert in new_alerts:
        existing = session.exec(select(Alert).where(Alert.description == alert.description)).first()
        if not existing:
            correlation_engine.process_alert(alert)
    
    session.commit()
    
    return {"status": "success", "log_id": normalized.id, "alerts_generated": len(new_alerts)}
