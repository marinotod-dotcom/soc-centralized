from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from sqlalchemy import select

from src.auth.roles import require_role
from src.auth.auth_routes import router as auth_router
from src.db.session import get_session
from src.models.db.vulnerability_tracking import VulnerabilityTracking
from src.services.vulnerability_tracking_service import VulnerabilityTrackingService
from src.utils.wazuh_utils import build_clients

from src.services.sla_analytics_service import SlaAnalyticsService
from src.models.schemas.sla_analytics import VulnDashboardResponse

load_dotenv()

app = FastAPI(title="Vulnerability Tracking API")
app.include_router(auth_router)

indexer_client, _manager_client = build_clients()
tracking_service = VulnerabilityTrackingService(wazuh_client=indexer_client)
dashboard_service = SlaAnalyticsService()

@app.get("/api/me")
def get_me(identity: dict = Depends(require_role("technicien", "admin_cyber"))):
    return identity

@app.get("/api/vulnerabilities")
def list_vulnerabilities(_=Depends(require_role("technicien", "admin_cyber"))):
    with get_session() as db:
        rows = db.scalars(select(VulnerabilityTracking)).all()
        return [
            {
                "cve_id": r.cve_id,
                "agent_name": r.agent_name,
                "severity": r.severity,
                "package": r.package,
                "cvss": r.cvss,
                "fix_version": r.fix_version,
                "status": r.status.value,
                "treated_by": r.treated_by,
                "treated_at": r.treated_at.isoformat() if r.treated_at else None,
                "validated_by": r.validated_by,
                "validated_at": r.validated_at.isoformat() if r.validated_at else None,
            }
            for r in rows
        ]

@app.post("/api/vulnerabilities/{cve_id}/{agent_name}/treat")
def treat_vulnerability(
    cve_id: str,
    agent_name: str,
    comment: str = Body(..., embed=True),
    identity: dict = Depends(require_role("technicien")),
):
    try:
        tracking_service.mark_treated(
            cve_id=cve_id, agent_name=agent_name, technician=identity["username"], comment=comment
        )
    except ValueError as e:
        raise HTTPException(404, str(e))
    return {"ok": True}

@app.post("/api/vulnerabilities/{cve_id}/{agent_name}/validate")
def validate_vulnerability(
    cve_id: str,
    agent_name: str,
    comment: str | None = Body(None, embed=True),
    identity: dict = Depends(require_role("admin_cyber")),
):
    try:
        new_status = tracking_service.validate(
            cve_id=cve_id, agent_name=agent_name, admin=identity["username"], comment=comment
        )
    except ValueError as e:
        raise HTTPException(404, str(e))
    return {"status": new_status.value}

@app.get("/api/sla/dashboard", response_model=VulnDashboardResponse)
def get_vuln_dashboard(_=Depends(require_role("technicien", "admin_cyber"))):
    return dashboard_service.get_dashboard()
