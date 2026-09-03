import logging
from src.auth.ldap_auth import authenticate
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from src.auth.session import COOKIE_NAME, create_session_token, decode_session_token

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/login")
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    user = authenticate(username, password)
    if user is None:
        logger.info("Tentative de login echouee pour %s", username)
        raise HTTPException(401, "Identifiants invalides")

    token = create_session_token(user.username, user.role)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        #secure=True,
        samesite="strict",
        max_age=3600,
    )
    logger.info("Login reussi pour %s (role=%s)", user.username, user.role)
    return {"username": user.username, "role": user.role}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME)
    return {"detail": "Deconnecte"}

@router.get("/verify")
def verify(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token or decode_session_token(token) is None:
        raise HTTPException(401, "Session invalide")
    return {"ok": True}
