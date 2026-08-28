import logging
from fastapi import HTTPException, Request
from src.auth.session import COOKIE_NAME, decode_session_token

logger = logging.getLogger(__name__)

def require_role(*allowed_roles: str):
    def dependency(request: Request):
        token = request.cookies.get(COOKIE_NAME)
        if not token:
            raise HTTPException(401, "Utilisateur non authentifie")

        payload = decode_session_token(token)
        if payload is None:
            raise HTTPException(401, "Session invalide ou expiree")

        username, role = payload["sub"], payload["role"]

        if role not in allowed_roles:
            logger.info("Acces refuse pour %s (role=%s, requis=%s)", username, role, allowed_roles)
            raise HTTPException(403, f"Role '{role}' insuffisant pour cette action")

        return {"username": username, "role": role}

    return dependency