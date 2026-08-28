import os
import sys
import time
import pytest
from datetime import datetime
from dotenv import load_dotenv
from src.collectors.log import LogCollector
from src.clients.wazuh_indexer import WazuhIndexerClient
from src.clients.wazuh_manager import WazuhManagerClient

load_dotenv()

DATE_FROM = datetime(2025, 6, 9,  0,  0,  0)
DATE_TO   = datetime(2025, 6, 15, 23, 59, 59)

WARN_THRESHOLD_MS  = 2_000
ERROR_THRESHOLD_MS = 10_000

@pytest.fixture(scope="module")
def indexer_client():
    client = WazuhIndexerClient(
        host=os.getenv("WAZUH_INDEXER_HOST", "https://localhost:9200"),
        username=os.getenv("WAZUH_INDEXER_USERNAME", "admin"),
        password=os.getenv("WAZUH_INDEXER_PASSWORD", "admin"),
    )
    try:
        client.test_connection()
    except Exception as e:
        pytest.skip(f"Wazuh Indexer inaccessible : {e}")
    return client


@pytest.fixture(scope="module")
def manager_client():
    from src.clients.wazuh_manager import WazuhManagerClient
    client = WazuhManagerClient(
        host=os.getenv("WAZUH_MANAGER_HOST", "https://localhost:55000"),
        username=os.getenv("WAZUH_MANAGER_USERNAME", "wazuh"),
        password=os.getenv("WAZUH_MANAGER_PASSWORD", "wazuh"),
    )
    try:
        client.test_connection()
    except Exception as e:
        pytest.skip(f"Wazuh Manager inaccessible : {e}")
    return client


@pytest.fixture(scope="module")
def collector(indexer_client, manager_client):
    return LogCollector(
        indexer_client=indexer_client,
        manager_client=manager_client,
    )


# ── helper chronometre ─────────────────────────────────────────────────────────

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


# ── tests de performance ───────────────────────────────────────────────────────

class TestLogCollectorPerformance:

    def test_perf_agent_summary(self, collector):
        kpi, ms = run_timed(
            "get_agent_summary",
            collector.get_agent_summary,
        )
        assert kpi is not None
        assert ms < ERROR_THRESHOLD_MS, f"Requete trop lente : {ms:.0f} ms"

    def test_perf_never_connected_agents(self, collector):
        # get_agent_summary doit etre appele avant (dependance _total_declared)
        # le fixture scope=module garantit que le collector est le meme instance
        kpi, ms = run_timed(
            "get_never_connected_agents",
            collector.get_never_connected_agents,
        )
        assert kpi is not None
        assert ms < ERROR_THRESHOLD_MS, f"Requete trop lente : {ms:.0f} ms"

    def test_perf_confirmed_incidents(self, collector):
        kpi, ms = run_timed(
            "get_confirmed_incidents",
            collector.get_confirmed_incidents, DATE_FROM, DATE_TO,
        )
        assert kpi is not None
        assert ms < ERROR_THRESHOLD_MS, f"Requete trop lente : {ms:.0f} ms"

    def test_perf_all_sequential(self, collector):
        """
        Execute toutes les requetes en sequence et affiche un resume global.
        Utile pour estimer le temps total de generation du rapport.

        Note : get_never_connected_agents depend de get_agent_summary
        (attribut _total_declared). L'ordre d'execution est garanti ici.
        """
        print("\n" + "-" * 65)
        print(f"  {'REQUETE':<45}  {'DUREE':>8}")
        print("-" * 65)

        results     = {}
        total_start = time.perf_counter()

        # 1. agent_summary en premier (initialise _total_declared)
        _, ms = run_timed("get_agent_summary", collector.get_agent_summary)
        results["agent_summary"] = ms

        # 2. never_connected_agents (necessite _total_declared)
        _, ms = run_timed("get_never_connected_agents", collector.get_never_connected_agents)
        results["never_connected_agents"] = ms

        # 3. confirmed_incidents (requete Indexer independante)
        _, ms = run_timed("get_confirmed_incidents",
                          collector.get_confirmed_incidents, DATE_FROM, DATE_TO)
        results["confirmed_incidents"] = ms

        total_ms = (time.perf_counter() - total_start) * 1000
        print("-" * 65)
        print(f"  {'TOTAL':<45}  {total_ms:>8.1f} ms")
        print("-" * 65)

        slowest = max(results, key=results.get)
        print(f"\n  Requete la plus lente : {slowest} ({results[slowest]:.1f} ms)")

        assert total_ms < ERROR_THRESHOLD_MS * len(results), (
            f"Temps total trop eleve : {total_ms:.0f} ms"
        )