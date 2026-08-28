import os
import sys
import time
import pytest
from datetime import datetime
from dotenv import load_dotenv
from src.clients.wazuh_indexer import WazuhIndexerClient
from src.collectors.compliance import ComplianceCollector

load_dotenv()

DATE_FROM = datetime(2025, 6, 9,  0,  0,  0)
DATE_TO   = datetime(2025, 6, 15, 23, 59, 59)

WARN_THRESHOLD_MS  = 2_000
ERROR_THRESHOLD_MS = 10_000

@pytest.fixture(scope="module")
def indexer_client():
    client = WazuhIndexerClient(
        host=os.getenv("WAZUH_INDEXER_HOST", "https://10.200.42.98:9200"),
        username=os.getenv("WAZUH_INDEXER_USERNAME", "admin"),
        password=os.getenv("WAZUH_INDEXER_PASSWORD", "SecretPassword"),
    )
    try:
        client.test_connection()
    except Exception as e:
        pytest.skip(f"Wazuh Indexer inaccessible : {e}")
    return client

@pytest.fixture(scope="module")
def collector(indexer_client):
    return ComplianceCollector(indexer_client=indexer_client)

def run_timed(label: str, fn, *args, **kwargs):
    """
    Execute fn(*args, **kwargs), mesure le temps ecoule,
    affiche un rapport et retourne (resultat, elapsed_ms).
    """
    start      = time.perf_counter()
    result     = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000

    if elapsed_ms < WARN_THRESHOLD_MS:
        status = "[OK]  "
    elif elapsed_ms < ERROR_THRESHOLD_MS:
        status = "[WARN]"
    else:
        status = "[SLOW]"

    print(f"\n  {status}  {label:<45}  {elapsed_ms:>8.1f} ms")

    return result, elapsed_ms

class TestComplianceCollectorPerformance:

    def test_perf_hipaa(self, collector):
        kpi, ms = run_timed(
            "get_hipaa",
            collector.hipaa, DATE_FROM, DATE_TO,
        )
        assert kpi is not None
        assert ms < ERROR_THRESHOLD_MS, f"Requete trop lente : {ms:.0f} ms"

    def test_perf_rgpd(self, collector):
        kpi, ms = run_timed(
            "get_rgpd",
            collector.rgpd, DATE_FROM, DATE_TO,
        )
        assert kpi is not None
        assert ms < ERROR_THRESHOLD_MS, f"Requete trop lente : {ms:.0f} ms"


    def test_perf_all_sequential(self, collector):
        """
        Execute toutes les requetes en sequence et affiche un resume global.
        Utile pour estimer le temps total de generation du rapport.
        """
        queries = {
            "hipaa":            collector.hipaa,
            "rgpd": collector.rgpd,
        }

        results     = {}
        total_start = time.perf_counter()

        print("\n" + "-" * 65)
        print(f"  {'REQUETE':<45}  {'DUREE':>8}")
        print("-" * 65)

        for name, fn in queries.items():
            _, ms = run_timed(name, fn, DATE_FROM, DATE_TO)
            results[name] = ms

        total_ms = (time.perf_counter() - total_start) * 1000
        print("-" * 65)
        print(f"  {'TOTAL':<45}  {total_ms:>8.1f} ms")
        print("-" * 65)

        slowest = max(results, key=results.get)
        print(f"\n  Requete la plus lente : {slowest} ({results[slowest]:.1f} ms)")

        assert total_ms < ERROR_THRESHOLD_MS * len(queries), (
            f"Temps total trop eleve : {total_ms:.0f} ms"
        )
