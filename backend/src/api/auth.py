import logging

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

USER_ROLE_MAP = {
    "tech": "technicien",
    "admin": "admin_cyber",
}


def get_role(username: str | None) -> str | None:
    if not username:
        return None
    return USER_ROLE_MAP.get(username)


def require_role(*allowed_roles: str):
    def dependency(request: Request):
        username = request.headers.get("X-Auth-User")
        if not username:
            raise HTTPException(401, "Utilisateur non authentifie")

        role = get_role(username)
        if role is None:
            logger.warning("Utilisateur %s authentifie mais sans role connu", username)
            raise HTTPException(403, "Aucun role associe a cet utilisateur")

        if role not in allowed_roles:
            logger.info("Acces refuse pour %s (role=%s, requis=%s)", username, role, allowed_roles)
            raise HTTPException(403, f"Role '{role}' insuffisant pour cette action")

        return {"username": username, "role": role}

    return dependency