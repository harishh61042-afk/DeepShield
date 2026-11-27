from app.models.entities import AuditLog


def audit(db, actor_id, action, target_type="", target_id=None, outcome="success", metadata=None):
    db.add(AuditLog(actor_id=actor_id, action=action, target_type=target_type, target_id=str(target_id) if target_id else None, outcome=outcome, metadata_json=metadata or {}))
