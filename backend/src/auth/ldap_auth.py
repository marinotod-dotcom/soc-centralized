import os
import logging
from dataclasses import dataclass
from ldap3 import ALL, SUBTREE, Connection, Server

logger = logging.getLogger(__name__)

LDAP_HOST = os.environ["LDAP_HOST"].strip()
LDAP_PORT = int(os.environ.get("LDAP_PORT", "636"))
LDAP_BASE_DN = os.environ["LDAP_BASE_DN"].strip()
LDAP_BIND_DN = os.environ["LDAP_BIND_DN"].strip()
LDAP_BIND_PASSWORD = os.environ["LDAP_BIND_PASSWORD"].strip()
LDAP_USER_SEARCH_FILTER = "(sAMAccountName={username})"
AD_MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"
GROUP_ROLE_MAP = [
    (f"CN=APPROBATEUR,CN=VULNERABILITY,CN=ADMINISTRATIONS,{LDAP_BASE_DN}", "admin_cyber"),
    (f"CN=RESPONSABLE,CN=VULNERABILITY,CN=ADMINISTRATIONS,{LDAP_BASE_DN}", "technicien"),
]

@dataclass
class AuthenticatedUser:
    username: str
    role: str

def _get_server() -> Server:
    return Server(LDAP_HOST, port=LDAP_PORT, use_ssl=True, get_info=ALL)

def _resolve_role(service_conn: Connection, username: str) -> str | None:
    for group_dn, role in GROUP_ROLE_MAP:
        search_filter = (
            f"(&(sAMAccountName={username})"
            f"(memberOf:{AD_MATCHING_RULE_IN_CHAIN}:={group_dn}))"
        )
        service_conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
        )
        if service_conn.entries:
            return role
    return None

def authenticate(username: str, password: str) -> AuthenticatedUser | None:
    server = _get_server()

    try:
        service_conn = Connection(
            server, LDAP_BIND_DN, LDAP_BIND_PASSWORD, authentication="SIMPLE", auto_bind=True
        )
    except Exception:
        logger.exception("Echec de connexion au compte de service LDAP")
        return None

    service_conn.search(
        search_base=LDAP_BASE_DN,
        search_filter=LDAP_USER_SEARCH_FILTER.format(username=username),
        search_scope=SUBTREE,
        attributes=["distinguishedName"],
    )
    if not service_conn.entries:
        logger.warning("Utilisateur AD inconnu: %s", username)
        service_conn.unbind()
        return None

    user_dn = str(service_conn.entries[0].distinguishedName)

    try:
        user_conn = Connection(server, user_dn, password, authentication="SIMPLE", auto_bind=True)
        user_conn.unbind()
    except Exception:
        logger.info("Echec d'authentification pour %s", username)
        service_conn.unbind()
        return None

    role = _resolve_role(service_conn, username)
    service_conn.unbind()

    if role is None:
        logger.warning("Utilisateur %s authentifie mais aucun groupe SOC connu", username)
        return None

    return AuthenticatedUser(username=username, role=role)