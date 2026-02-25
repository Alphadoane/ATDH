from datetime import datetime, timedelta
from typing import List, Optional
from sqlmodel import Session, select
from ..models import Alert, AttackSession

class CorrelationEngine:
    def __init__(self, session: Session):
        self.session = session

    def process_alert(self, alert: Alert):
        """
        Correlate an incoming alert with an existing AttackSession 
        or create a new one.
        """
        source_id = alert.source_ip if alert.source_ip else "Local_System"

        # Look for an active session from this source in the last 1 hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        statement = select(AttackSession).where(
            AttackSession.source_ip == source_id,
            AttackSession.is_active == True,
            AttackSession.last_seen > one_hour_ago
        )
        attack_session = self.session.exec(statement).first()

        if not attack_session:
            # Create new session
            attack_session = AttackSession(
                source_ip=source_id,
                risk_score=alert.risk_score,
                techniques=alert.mitre_id if alert.mitre_id else ""
            )
            self.session.add(attack_session)
            self.session.commit()
            self.session.refresh(attack_session)
        else:
            # Update existing session
            attack_session.last_seen = datetime.utcnow()
            attack_session.risk_score += alert.risk_score
            
            # Add unique MITRE IDs to the session
            if alert.mitre_id:
                current_techs = set(attack_session.techniques.split(",") if attack_session.techniques else [])
                current_techs.add(alert.mitre_id)
                attack_session.techniques = ",".join(filter(None, current_techs))
            
            # Escalate if multiple stages detected
            if len(attack_session.techniques.split(",")) >= 3:
                attack_session.risk_score += 50 # Bonus for chain detection
                
            self.session.add(attack_session)
            self.session.commit()

        # Link alert to session
        alert.session_id = attack_session.id
        self.session.add(alert)
        self.session.commit()
