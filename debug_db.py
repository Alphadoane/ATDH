from sqlmodel import Session, select, create_engine
from backend.app.models import Alert, AttackSession, NormalizedLog

engine = create_engine("postgresql://postgres:Doane40640666@localhost:5432/threat_platform")

with Session(engine) as session:
    alerts = session.exec(select(Alert)).all()
    sessions = session.exec(select(AttackSession)).all()
    logs = session.exec(select(NormalizedLog).order_by(NormalizedLog.id.desc()).limit(5)).all()
    
    print(f"Total Alerts: {len(alerts)}")
    for a in alerts:
        print(f" - {a.rule_name}: {a.description} (Session: {a.session_id})")
        
    print(f"Total Sessions: {len(sessions)}")
    for s in sessions:
        print(f" - {s.source_ip}: Risk {s.risk_score}, Techs: {s.techniques}")

    print("Recent Logs:")
    for l in logs:
        print(f" - ID {l.id}: {l.raw_log[:50]}")
