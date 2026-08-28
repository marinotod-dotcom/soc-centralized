"""
tests/test-api.py
Test de connexion aux APIs Wazuh Manager et Wazuh Indexer
"""

import os
import sys
import requests
import urllib3
from dotenv import load_dotenv

# Désactiver les avertissements SSL (certificats auto-signés Wazuh)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Charger les variables d'environnement depuis .env (racine du projet)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def ok(msg: str):
    print(f"  [OK]  {msg}")

def fail(msg: str):
    print(f"  [KO]  {msg}")

def section(title: str):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# ─────────────────────────────────────────────
# 1. Wazuh Manager API
# ─────────────────────────────────────────────

def test_wazuh_manager():
    section("Wazuh Manager API")

    host     = os.getenv("WAZUH_MANAGER_HOST", "").rstrip("/")
    password = os.getenv("WAZUH_MANAGER_PASSWORD", "")
    username = os.getenv("WAZUH_MANAGER_USERNAME", "")
    timeout  = int(os.getenv("WAZUH_MANAGER_TIMEOUT", "60"))

    if not all([host, username, password]):
        fail("Variables WAZUH_MANAGER_* manquantes dans .env")
        return False

    print(f"  Host     : {host}")
    print(f"  Username : {username}")

    # Authentification → JWT token
    auth_url = f"{host}/security/user/authenticate"
    try:
        resp = requests.post(
            auth_url,
            auth=(username, password),
            verify=False,
            timeout=timeout,
        )
        resp.raise_for_status()
        token = resp.json().get("data", {}).get("token")
        if not token:
            fail(f"Authentification réussie mais token absent. Réponse : {resp.text[:200]}")
            return False
        ok(f"Authentification réussie (HTTP {resp.status_code})")
    except requests.exceptions.ConnectionError as e:
        fail(f"Impossible de joindre {host} → {e}")
        return False
    except requests.exceptions.Timeout:
        fail(f"Timeout après {timeout}s sur {auth_url}")
        return False
    except requests.exceptions.HTTPError as e:
        fail(f"Erreur HTTP {resp.status_code} → {e}")
        return False

    # Vérification rapide : liste des agents
    try:
        headers = {"Authorization": f"Bearer {token}"}
        resp2 = requests.get(
            f"{host}/agents?limit=1",
            headers=headers,
            verify=False,
            timeout=timeout,
        )
        resp2.raise_for_status()
        total = resp2.json().get("data", {}).get("total_affected_items", "?")
        ok(f"Endpoint /agents accessible — {total} agent(s) enregistré(s)")
    except Exception as e:
        fail(f"Endpoint /agents inaccessible → {e}")
        return False

    return True


# ─────────────────────────────────────────────
# 2. Wazuh Indexer (OpenSearch)
# ─────────────────────────────────────────────

def test_wazuh_indexer():
    section("Wazuh Indexer (OpenSearch)")

    host     = os.getenv("WAZUH_INDEXER_HOST", "").rstrip("/")
    username = os.getenv("WAZUH_INDEXER_USERNAME", "")
    password = os.getenv("WAZUH_INDEXER_PASSWORD", "")
    index    = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")
    timeout  = int(os.getenv("WAZUH_MANAGER_TIMEOUT", "60"))

    if not all([host, username, password]):
        fail("Variables WAZUH_INDEXER_* manquantes dans .env")
        return False

    print(f"  Host    : {host}")
    print(f"  Username: {username}")
    print(f"  Index   : {index}")

    # Health check cluster
    try:
        resp = requests.get(
            f"{host}/_cluster/health",
            auth=(username, password),
            verify=False,
            timeout=timeout,
        )
        resp.raise_for_status()
        data   = resp.json()
        status = data.get("status", "unknown")
        name   = data.get("cluster_name", "unknown")
        color  = {"green": "OK", "yellow": "AVERTISSEMENT", "red": "CRITIQUE"}.get(status, status)
        ok(f"Cluster '{name}' accessible — statut : {status.upper()} ({color})")
    except requests.exceptions.ConnectionError as e:
        fail(f"Impossible de joindre {host} → {e}")
        return False
    except requests.exceptions.Timeout:
        fail(f"Timeout après {timeout}s sur {host}/_cluster/health")
        return False
    except requests.exceptions.HTTPError as e:
        fail(f"Erreur HTTP {resp.status_code} → {e}")
        return False

    # Vérification de l'index pattern
    try:
        resp2 = requests.get(
            f"{host}/{index}/_count",
            auth=(username, password),
            verify=False,
            timeout=timeout,
        )
        resp2.raise_for_status()
        count = resp2.json().get("count", "?")
        ok(f"Index '{index}' accessible — {count} document(s)")
    except Exception as e:
        fail(f"Index '{index}' inaccessible → {e}")
        return False

    return True


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    print("\n" + "="*55)
    print("  WAZUH WEEKLY REPORT — Test de connexion APIs")
    print("="*55)

    results = {
        "Wazuh Manager API"       : test_wazuh_manager(),
        "Wazuh Indexer (OpenSearch)": test_wazuh_indexer(),
    }

    section("Résumé")
    all_ok = True
    for name, status in results.items():
        symbol = "OK" if status else "KO"
        print(f"  [{symbol}]  {name}")
        if not status:
            all_ok = False

    print()
    if all_ok:
        print("  Toutes les connexions sont opérationnelles.")
        sys.exit(0)
    else:
        print("  Une ou plusieurs connexions ont échoué. Vérifiez votre .env et la disponibilité des services.")
        sys.exit(1)


if __name__ == "__main__":
    main()