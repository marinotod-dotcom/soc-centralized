import os
import time
import pytest
from datetime import datetime
from dotenv import load_dotenv
from src.clients.wazuh_indexer import WazuhIndexerClient
from src.collectors.action_plan import ActionPlanCollector

load_dotenv()

DATE_FROM = datetime(2025, 6, 9,  0,  0,  0)
DATE_TO   = datetime(2025, 6, 15, 23, 59, 59)

WARN_THRESHOLD_MS  = 5_000
ERROR_THRESHOLD_MS = 30_000


@pytest.fixture(scope="module")
def indexer_client():
    client = WazuhIndexerClient(
        host=os.getenv("WAZUH_INDEXER_HOST"),
        username=os.getenv("WAZUH_INDEXER_USERNAME"),
        password=os.getenv("WAZUH_INDEXER_PASSWORD"),
    )
    try:
        client.test_connection()
    except Exception as e:
        pytest.skip(f"Wazuh Indexer inaccessible : {e}")
    return client


@pytest.fixture(scope="module")
def collector(indexer_client):
    return ActionPlanCollector(indexer_client=indexer_client)


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


class TestActionPlanCollectorPerformance:

    def test_perf_get_vulnerabilities_by_agent(self, collector):
        buckets, ms = run_timed(
            "get_vulnerabilities_by_agent (page_size=1000)",
            collector.get_vulnerabilities_by_agent, DATE_FROM, DATE_TO,
        )
        assert isinstance(buckets, list)
        assert ms < ERROR_THRESHOLD_MS, f"Extraction trop lente : {ms:.0f} ms"
        print(f"\n  {len(buckets)} combinaisons (CVE, agent) récupérées")

    def test_bucket_structure(self, collector):
        """Vérifie que chaque bucket a la forme attendue par le parser JS
        de la page plan d'action (key.cve, key.agent, doc_count, details)."""
        buckets, _ = run_timed(
            "get_vulnerabilities_by_agent (structure)",
            collector.get_vulnerabilities_by_agent, DATE_FROM, DATE_TO,
        )
        if not buckets:
            pytest.skip("Aucune vulnérabilité active sur la fenêtre de test.")

        sample = buckets[0]
        assert "key" in sample
        assert "cve" in sample["key"]
        assert "agent" in sample["key"]
        assert "doc_count" in sample
        assert "details" in sample
        assert "hits" in sample["details"]

    def test_max_pages_safeguard(self, collector, caplog):
        """Vérifie que le garde-fou max_pages tronque proprement l'extraction
        et journalise un avertissement, plutôt que de boucler indéfiniment."""
        buckets, ms = run_timed(
            "get_vulnerabilities_by_agent (max_pages=1, page_size=10)",
            collector.get_vulnerabilities_by_agent,
            DATE_FROM, DATE_TO, page_size=10, max_pages=1,
        )
        assert isinstance(buckets, list)
        assert len(buckets) <= 10, "max_pages=1 avec page_size=10 doit tronquer à 10 buckets max"

        if len(buckets) == 10:
            assert "max_pages" in caplog.text, (
                "Le garde-fou devrait journaliser un avertissement en cas de troncature"
            )

    def test_pagination_consistency(self, collector):
        """Vérifie que le nombre de combinaisons (CVE, agent) récupérées est
        indépendant de la taille de page — sinon la pagination composite
        (after_key) perd ou duplique des résultats entre deux pages.

        Note : suppose que les données Wazuh sont stables entre les deux
        appels (fenêtre passée, pas la semaine courante) ; sur un environnement
        où l'indexation continue en temps réel, un léger écart est possible.
        """
        small_page, ms_small = run_timed(
            "get_vulnerabilities_by_agent (page_size=50)",
            collector.get_vulnerabilities_by_agent, DATE_FROM, DATE_TO, page_size=50,
        )
        large_page, ms_large = run_timed(
            "get_vulnerabilities_by_agent (page_size=500)",
            collector.get_vulnerabilities_by_agent, DATE_FROM, DATE_TO, page_size=500,
        )

        keys_small = {(b["key"]["cve"], b["key"]["agent"]) for b in small_page}
        keys_large = {(b["key"]["cve"], b["key"]["agent"]) for b in large_page}

        assert keys_small == keys_large, (
            f"Écart de pagination : {len(keys_small)} combinaisons avec page_size=50 "
            f"vs {len(keys_large)} avec page_size=500"
        )

    def test_perf_all_sequential(self, collector):
        """
        Execute les scénarios de charge en sequence et affiche un resume
        global. Utile pour estimer le temps total avant intégration au
        pipeline hebdomadaire (action_plan_pipeline).
        """
        scenarios = {
            "default (page_size=1000)": lambda: collector.get_vulnerabilities_by_agent(DATE_FROM, DATE_TO),
            "small_page (page_size=50)": lambda: collector.get_vulnerabilities_by_agent(DATE_FROM, DATE_TO, page_size=50),
        }

        results     = {}
        total_start = time.perf_counter()

        print("\n" + "-" * 65)
        print(f"  {'SCENARIO':<45}  {'DUREE':>8}")
        print("-" * 65)

        for name, fn in scenarios.items():
            _, ms = run_timed(name, fn)
            results[name] = ms

        total_ms = (time.perf_counter() - total_start) * 1000
        print("-" * 65)
        print(f"  {'TOTAL':<45}  {total_ms:>8.1f} ms")
        print("-" * 65)

        slowest = max(results, key=results.get)
        print(f"\n  Scenario le plus lent : {slowest} ({results[slowest]:.1f} ms)")

        assert total_ms < ERROR_THRESHOLD_MS * len(scenarios), (
            f"Temps total trop eleve : {total_ms:.0f} ms"
        )